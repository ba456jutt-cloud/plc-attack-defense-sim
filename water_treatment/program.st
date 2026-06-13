PROGRAM main

  (* ── Located I/O Variables — mapped to Modbus registers ─────────────────
     KEEP THIS BLOCK FIRST. matiec v0.1 requires ALL located (AT %) variables
     in their own VAR block, separate from unlocated internals.           *)
  VAR
    (* Output Coils — Modbus FC01/FC05 — %QX ─────────────────────────── *)
    Intake_Pump         AT %QX0.0 : BOOL;   (* Coil  0 — Raw water intake pump    *)
    Intake_Valve        AT %QX0.1 : BOOL;   (* Coil  1 — Inlet gate valve         *)
    Chlorine_Pump       AT %QX0.2 : BOOL;   (* Coil  2 — Chlorine dosing pump     *)
    Coagulant_Pump      AT %QX0.3 : BOOL;   (* Coil  3 — Coagulant dosing pump    *)
    Dosing_Enable       AT %QX0.4 : BOOL;   (* Coil  4 — Dosing master enable     *)
    Filter_Valve        AT %QX0.5 : BOOL;   (* Coil  5 — Sand filter inlet valve  *)
    UV_System           AT %QX0.6 : BOOL;   (* Coil  6 — UV disinfection system   *)
    Reservoir_Inlet     AT %QX0.7 : BOOL;   (* Coil  7 — Reservoir fill valve     *)
    Reservoir_Outlet    AT %QX1.0 : BOOL;   (* Coil  8 — Reservoir outlet valve   *)
    Distribution_Pump   AT %QX1.1 : BOOL;   (* Coil  9 — Distribution pump        *)
    Alarm_LED           AT %QX1.2 : BOOL;   (* Coil 10 — Alarm indicator LED      *)
    System_Enable       AT %QX1.3 : BOOL;   (* Coil 11 — Master system ON/OFF     *)

    (* Discrete Inputs — Modbus FC02 — %IX ───────────────────────────── *)
    Level_Low_Sensor    AT %IX0.0 : BOOL;   (* DI 0 — Low-level float switch      *)
    Level_High_Sensor   AT %IX0.1 : BOOL;   (* DI 1 — High-level float switch     *)
    Filter_Pressure_OK  AT %IX0.2 : BOOL;   (* DI 2 — Filter differential OK      *)
    Flow_Sensor         AT %IX0.3 : BOOL;   (* DI 3 — Inlet flow detected         *)

    (* Holding Registers — Modbus FC03/FC06 — %QW ────────────────────── *)
    Chlorine_Dose       AT %QW0   : INT;    (* HR 0 — Chlorine rate 0-1000        *)
    Coagulant_Dose      AT %QW1   : INT;    (* HR 1 — Coagulant rate 0-1000       *)
    Distribution_Speed  AT %QW2   : INT;    (* HR 2 — Pump speed setpoint 0-100   *)
    Reservoir_Level_Pct AT %QW3   : INT;    (* HR 3 — Reservoir level % 0-100     *)
  END_VAR

  (* ── Internal (unlocated) Variables ─────────────────────────────────────
     MUST be in a SEPARATE VAR block from the located variables above.
     Mixing them in one block causes "invalid located variable declaration"
     errors in matiec v0.1 (all 43 errors stem from this single mistake).  *)
  VAR
    Alarm_Active        : BOOL;
    Chlorine_Overdose   : BOOL;
    System_Ready        : BOOL;
    Filter_Fault        : BOOL;

    (* Safety interlock flags — set internally, cannot be cleared by Modbus *)
    Intake_Cavitation_Guard   : BOOL;   (* TRUE when intake pump would run dry  *)
    Dist_Cavitation_Guard     : BOOL;   (* TRUE when distribution pump would dry-run *)
    Chlorine_HardClamped      : BOOL;   (* TRUE when we forced chlorine back down *)
    Coagulant_HardClamped     : BOOL;   (* TRUE when we forced coagulant back down *)

    Timer_Startup       : TON;
    Timer_Dosing        : TON;
    Timer_Alarm         : TON;
    Timer_UVWarmup      : TON;

    (* Watchdog: if System_Enable drops unexpectedly we raise alarm immediately
       rather than waiting for the normal alarm debounce logic.
       Real PLCs have a hardware watchdog that resets the CPU — we model
       the software equivalent here via a one-shot transition detector. *)
    Prev_System_Enable  : BOOL;         (* previous scan value of System_Enable *)
    Watchdog_Tripped    : BOOL;         (* latched — cleared only by operator   *)
  END_VAR

  (* =====================================================================
     PROGRAM LOGIC — 5-Stage Water Treatment Plant
     Scan cycle: 20 ms  (TASK task0 in CONFIGURATION below)

     Safety philosophy: every interlock in this block represents a physical
     consequence. We clamp/override BEFORE the process logic runs so no
     downstream stage can act on an out-of-range value even for one scan.
     ===================================================================== *)

  (* ─────────────────────────────────────────────────────────────────────
     BLOCK 0: Input Sanitisation — clamp every register that arrives from
     Modbus before any process logic sees it.

     A real PLC with hardwired safety would have dedicated signal-conditioned
     4-20 mA input cards; here we enforce the same limits in software.
     Chlorine_Dose range: 0–850  (>850 is physically dangerous — WHO guideline
       for drinking water is 5 mg/L; 850 maps to the top of safe dosing range)
     Coagulant_Dose range: 0–600 (above this, sludge accumulates and blocks filters)
     Distribution_Speed range: 0–100 (%)
     Reservoir_Level_Pct range: 0–100 (%)
     ───────────────────────────────────────────────────────────────────── *)

  (* Chlorine hard clamp — if an attacker writes 1000, this fires the same
     scan cycle and the process stages below never see a value above 850.
     Setting Chlorine_HardClamped gives the SCADA historian a flag to record
     that a clamp event happened, which aids forensic analysis later. *)
  IF Chlorine_Dose > 850 THEN
    Chlorine_Dose      := 850;
    Chlorine_HardClamped := TRUE;
  ELSIF Chlorine_Dose < 0 THEN
    Chlorine_Dose      := 0;
    Chlorine_HardClamped := TRUE;
  ELSE
    Chlorine_HardClamped := FALSE;
  END_IF;

  (* Coagulant hard clamp — same logic. Values over 600 don't improve
     coagulation; they waste chemical and can blind the filter sensors. *)
  IF Coagulant_Dose > 600 THEN
    Coagulant_Dose       := 600;
    Coagulant_HardClamped := TRUE;
  ELSIF Coagulant_Dose < 0 THEN
    Coagulant_Dose       := 0;
    Coagulant_HardClamped := TRUE;
  ELSE
    Coagulant_HardClamped := FALSE;
  END_IF;

  (* Distribution speed: negative is meaningless, >100% is beyond VFD range *)
  IF Distribution_Speed > 100 THEN
    Distribution_Speed := 100;
  ELSIF Distribution_Speed < 0 THEN
    Distribution_Speed := 0;
  END_IF;

  (* Reservoir level can only be 0–100 percent by definition *)
  IF Reservoir_Level_Pct > 100 THEN
    Reservoir_Level_Pct := 100;
  ELSIF Reservoir_Level_Pct < 0 THEN
    Reservoir_Level_Pct := 0;
  END_IF;

  (* ─────────────────────────────────────────────────────────────────────
     BLOCK 1: Watchdog — detect unexpected System_Enable drop

     If System_Enable transitions HIGH→LOW without a graceful shutdown
     sequence, we immediately latch Watchdog_Tripped. This feeds into the
     alarm logic and prevents the CM-3 countermeasure from blindly
     restoring power without first confirming the plant is in a safe state.

     In a real plant this would be a dedicated hardware watchdog timer
     (e.g. Siemens S7-300 OB80 watchdog OB). We approximate it here.
     ───────────────────────────────────────────────────────────────────── *)
  (* BUG4 FIX: Startup grace period — watchdog must run AFTER startup timer fires.
     The RESTORE SAFE STATE sequence momentarily drops System_Enable then raises it.
     Without this guard, the watchdog trips on every normal reset sequence.
     Only latch Watchdog_Tripped if the plant was already running (Timer_Startup.Q). *)

  (* Stage 0: System startup timer — evaluated FIRST so Timer_Startup.Q is current *)
  Timer_Startup(IN := System_Enable, PT := T#5s);
  System_Ready := Timer_Startup.Q;

  IF Prev_System_Enable AND NOT System_Enable THEN
    (* Falling edge on System_Enable — only a fault if startup grace period is over *)
    IF Timer_Startup.Q THEN
      Watchdog_Tripped := TRUE;
    END_IF;
  END_IF;
  (* Rising edge on System_Enable = operator acknowledged and reset the plant.
     Clear the watchdog latch so the alarm can clear after safe state is confirmed. *)
  IF System_Enable AND NOT Prev_System_Enable THEN
    Watchdog_Tripped := FALSE;
  END_IF;
  Prev_System_Enable := System_Enable;

  (* ─────────────────────────────────────────────────────────────────────
     BLOCK 2: Safety Interlocks — these are the conditions that must be
     checked before ANY actuator is allowed to run.
     ───────────────────────────────────────────────────────────────────── *)

  (* Chlorine overdose threshold — raised at 800, hard-clamped at 850 above.
     The two-tier approach means the alarm fires before we reach physical limit. *)
  IF Chlorine_Dose > 800 THEN
    Chlorine_Overdose := TRUE;
  ELSE
    Chlorine_Overdose := FALSE;
  END_IF;

  (* Filter_Fault removed from alarm conditions — Filter_Pressure_OK is a
     physical DI with no sensor driver in this simulation, so it always reads
     FALSE and would permanently latch the alarm. In a real plant this would
     be wired to a differential pressure transmitter. *)
  Filter_Fault := FALSE;

  (* Alarm active if: chemical overdose, sensor contradiction
     (both low and high level true simultaneously = sensor failure),
     or the watchdog detected an unexpected shutdown. *)
  IF Chlorine_Overdose
     OR (Level_Low_Sensor AND Level_High_Sensor)
     OR Watchdog_Tripped
     OR Chlorine_HardClamped     (* hard clamp firing = someone wrote bad data *)
  THEN
    Alarm_Active := TRUE;
  ELSE
    Alarm_Active := FALSE;
  END_IF;

  Timer_Alarm(IN := Alarm_Active, PT := T#10s);
  (* When a real alarm condition exists, PLC forces Alarm_LED ON — cannot be suppressed.
     When no real alarm exists (Alarm_Active=FALSE), Alarm_LED follows its Modbus-written
     value — this allows the alarm suppress attack to demonstrate silencing a pre-existing
     alarm. In a real plant without this override, Oldsmar-style suppression succeeds. *)
  IF Alarm_Active OR Timer_Alarm.Q THEN
    Alarm_LED := TRUE;
  END_IF;

  (* ─────────────────────────────────────────────────────────────────────
     BLOCK 3: Intake Stage — valve must confirm open before pump runs.

     Intake_Cavitation_Guard enforces the physical sequencing rule:
     a centrifugal pump running against a closed inlet valve will cavitate
     within seconds, damaging the impeller and mechanical seal.
     The guard is an internal flag — Modbus CANNOT clear it directly.
     The only way to clear it is for Intake_Valve to actually be TRUE.
     ───────────────────────────────────────────────────────────────────── *)

  (* Stage 2: Intake valve opens first *)
  Intake_Valve := System_Ready AND NOT Alarm_Active;

  (* Cavitation guard: block the pump if the valve isn't confirmed open.
     Note we check the actual coil state, not just our intent — if an
     attacker forced the valve closed via Modbus while the pump runs,
     this catches it. *)
  IF NOT Intake_Valve THEN
    Intake_Cavitation_Guard := TRUE;
  ELSE
    Intake_Cavitation_Guard := FALSE;
  END_IF;

  (* Pump only allowed when valve is open AND system is healthy *)
  Intake_Pump := System_Ready AND NOT Alarm_Active AND NOT Filter_Fault
                 AND NOT Intake_Cavitation_Guard;

  (* Stage 3: Chemical dosing — only after intake has been running 2s *)
  Timer_Dosing(IN := Intake_Pump AND System_Ready, PT := T#2s);
  Dosing_Enable  := Timer_Dosing.Q AND NOT Chlorine_Overdose AND NOT Alarm_Active;
  Chlorine_Pump  := Dosing_Enable AND (Chlorine_Dose > 0);
  Coagulant_Pump := Dosing_Enable AND (Coagulant_Dose > 0);

  (* Stage 4: Filtration and UV *)
  Filter_Valve := Dosing_Enable AND Filter_Pressure_OK;
  Timer_UVWarmup(IN := Filter_Valve, PT := T#3s);
  UV_System := Timer_UVWarmup.Q AND Filter_Valve;

  (* Stage 5: Reservoir — only fill when UV has confirmed disinfection *)
  Reservoir_Inlet  := UV_System AND NOT Level_High_Sensor AND NOT Alarm_Active;
  Reservoir_Outlet := NOT Level_Low_Sensor AND Distribution_Pump;

  (* ── PHYSICS ENGINE HOOK ────────────────────────────────────────────────
     Reservoir_Level_Pct is NO LONGER computed by a naive +1/-1 counter here.

     The external physics engine (water_treatment/physics.py) integrates the
     real tank ODE (dV/dt = Q_in - Q_out) every 500ms and writes the result
     back to HR3 (Reservoir_Level_Pct) via Modbus FC06.

     This scan only GUARDS against an unreachable physics engine — if the
     physics process dies, we fall back to a coarse direction indicator
     so the PLC does not freeze at stale values. In normal operation the
     physics engine owns HR3 and this fallback never runs.

     Physical interpretation (from physics.py constants):
       Tank capacity : 50,000 L
       Q_in nominal  :  5.0 L/s (fully open intake valve + running intake pump)
       Q_out nominal :  4.0 L/s at 100% distribution speed
       Fill time from 0→100%  : 50,000 / 5.0 =  2,778s (~46 min)
       Drain time from 100→0%: 50,000 / 4.0 = ~208 min
       Chlorine dose 200 → 2.0 mg/L (WHO nominal safe)
       Chlorine dose 850 → 8.5 mg/L (above WHO 5 mg/L guideline)

     To run the physics engine:
       python3 water_treatment/physics.py
  ──────────────────────────────────────────────────────────────────────── *)
  (* Fallback direction guard — only active if physics engine is not running *)
  IF Reservoir_Inlet AND NOT Reservoir_Outlet THEN
    IF Reservoir_Level_Pct < 100 THEN
      (* Physics engine should have already updated this; this is a backstop *)
      Reservoir_Level_Pct := Reservoir_Level_Pct + 1;
    END_IF;
  ELSIF NOT Reservoir_Inlet AND Reservoir_Outlet THEN
    IF Reservoir_Level_Pct > 0 THEN
      Reservoir_Level_Pct := Reservoir_Level_Pct - 1;
    END_IF;
  END_IF;

  (* ─────────────────────────────────────────────────────────────────────
     BLOCK 4: Distribution — same cavitation guard logic as intake.

     Distribution_Pump running with Reservoir_Outlet CLOSED means the
     pump is pushing against a dead-end pipe. Pressure spike can rupture
     the outlet manifold. We force the pump OFF via the guard flag.
     ───────────────────────────────────────────────────────────────────── *)
  IF Distribution_Pump AND NOT Reservoir_Outlet THEN
    Dist_Cavitation_Guard := TRUE;
  ELSE
    Dist_Cavitation_Guard := FALSE;
  END_IF;

  (* Stage 6: Distribution pump — level must be above 10% and outlet open *)
  IF NOT Level_Low_Sensor AND NOT Alarm_Active AND System_Ready
     AND (Reservoir_Level_Pct > 10)
     AND NOT Dist_Cavitation_Guard THEN
    Distribution_Pump := TRUE;
  ELSE
    Distribution_Pump := FALSE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#20ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : main;
  END_RESOURCE
END_CONFIGURATION