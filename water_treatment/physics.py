#!/usr/bin/env python3
"""
physics.py — ODE-Based Water Treatment Plant Physics Simulation
===============================================================
CPSS Project — Phase 6 Fix

Replaces the trivial `Reservoir_Level_Pct := Reservoir_Level_Pct + 1`
counter in program.st with real differential equations.

The simulation runs as a background process, reads PLC coil/register state
via Modbus every TICK seconds, integrates the ODEs forward, and writes the
resulting physical values BACK to the PLC registers. The PLC's own logic
continues to run and can override these values via its own scan logic,
but the physics simulation dominates the register values between scans.

PHYSICS MODELS:

1. Tank Level ODE  (Section 3.1)
   dV/dt = Q_in(t) - Q_out(t)
   where:
     V         = water volume in reservoir (litres)
     Q_in      = flow rate in (L/s), depends on Reservoir_Inlet coil and pump state
     Q_out     = flow rate out (L/s), depends on Distribution_Pump and Distribution_Speed
   Reservoir_Level_Pct = 100 * V / V_max

2. Chlorine Decay ODE  (Section 3.2 — WHO/EPA first-order decay model)
   dC/dt = Q_in * C_dose / V - k_d * C - Q_out * C / V
   where:
     C         = chlorine concentration in reservoir (mg/L)
     C_dose    = chlorine dose from pump (mg/L equivalent of register value)
     k_d       = first-order decay constant (1/s), temperature-dependent
     Q_in, Q_out as above

   The register value Chlorine_Dose (0-850 integer) maps to mg/L:
     C_dose_mgL = Chlorine_Dose * DOSE_SCALE_FACTOR
   WHO guideline: 0.2–5 mg/L in distribution; above 10 mg/L = toxic concern

3. Sensor Noise  (Section 3.3)
   Each measured value has additive Gaussian noise plus a slow drift term:
     measured = true_value + N(0, sigma) + drift
   This makes anomaly detection realistic — the CM-6 baseline has natural
   variance that the Z-score and CUSUM must account for.

4. Actuator Response Time  (Section 3.4)
   Valves and pumps don't change state instantly. We model a first-order lag:
     dx/dt = (setpoint - x) / tau
   where tau is the actuator time constant (e.g., 2s for a motorised valve).

REFERENCES:
  - Rossman, L.A. (2000). EPANET 2 Users Manual. EPA/600/R-00/057.
    https://www.epa.gov/water-research/epanet (chlorine decay model, Section 3.4)
  - WHO (2011). Guidelines for Drinking-water Quality, 4th ed. Chapter 8 (Chlorination).
  - Kroll, D. (2006). Cyber security for water utilities. AWWA.
  - MiniCPS project (Rocchetto & Tippenhauer, 2017) — ICS physics simulation framework.
  - Taormina et al. (2017). "Characterizing Cyber-Physical Attacks on Water Distribution
    Systems." J. Water Resources Planning and Management, 143(5).

USAGE:
  # Run standalone (writes physics to PLC registers in real time)
  python3 water_treatment/physics.py

  # Dry-run: compute physics but don't write to PLC
  python3 water_treatment/physics.py --dry-run

  # Print current physical state
  python3 water_treatment/physics.py --status

  # Integration: import and call step() from another module
  from water_treatment.physics import PhysicsEngine
  eng = PhysicsEngine()
  state = eng.step(dt=0.5, coils=[...], regs=[...])
"""

import sys
import os
import time
import json
import math
import random
import argparse
from datetime import datetime
from pathlib import Path

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not installed. Run: pip install pymodbus==3.6.6")
    sys.exit(1)

# Try to import scipy for ODE solver; fall back to simple Euler if unavailable
try:
    from scipy.integrate import odeint
    _SCIPY = True
except ImportError:
    _SCIPY = False

# ── Physical constants ─────────────────────────────────────────────────────────
TANK_VOLUME_MAX_L   = 50_000.0    # litres — reservoir capacity
TANK_AREA_M2        = 50.0        # m² — cross-sectional area of reservoir

Q_IN_NOMINAL_LS     = 5.0         # L/s — nominal intake flow rate (valve fully open)
Q_OUT_NOMINAL_LS    = 4.0         # L/s — nominal distribution flow rate at 100% speed

# Chlorine dose scale: register value 200 → 2.0 mg/L (WHO nominal)
# register value 850 → 8.5 mg/L (above WHO 5 mg/L guideline — toxic concern)
# register value 1000 (unclamped) → 10 mg/L (WHO acute toxicity threshold)
DOSE_SCALE_FACTOR   = 0.01        # mg/L per register unit

# First-order chlorine decay constant at 20°C (EPA EPANET model, Table 3-1)
# Units: 1/s. Typical range: 0.001–0.01 /s for bulk decay.
K_DECAY_1_S         = 0.002       # /s at 20°C

WHO_SAFE_MAX_MGL    = 5.0         # mg/L — WHO drinking water guideline
WHO_TOXIC_MGL       = 10.0        # mg/L — acute concern threshold

# Actuator time constants (first-order lag, seconds)
TAU_VALVE           = 2.0         # motorised valve: 2s to fully open/close
TAU_PUMP            = 1.0         # pump ramp-up: 1s

# Sensor noise parameters
SIGMA_LEVEL         = 0.3         # % — level sensor noise (0.3% of full scale)
SIGMA_CHLORINE      = 0.05        # mg/L — chlorine sensor noise
DRIFT_RATE          = 0.001       # per second — slow sensor drift

# ── Physics state ──────────────────────────────────────────────────────────────
class PhysicsEngine:
    """
    Integrates the tank level and chlorine concentration ODEs.
    Call step(dt, coils, regs) each tick to advance the simulation.
    """

    def __init__(self):
        # Initial conditions — plant starts at 50% level, 2 mg/L chlorine
        self.volume_L     = TANK_VOLUME_MAX_L * 0.50
        self.chlorine_mgL = 2.0

        # Actuator states (first-order lag outputs, 0.0–1.0)
        self.intake_valve_actual    = 0.0
        self.reservoir_inlet_actual = 0.0
        self.reservoir_outlet_actual= 0.0
        self.dist_pump_fraction     = 0.0   # 0–1, follows Distribution_Speed / 100

        # Drift state
        self._drift_level = 0.0
        self._drift_cl    = 0.0

        self.t = 0.0  # simulation time (s)

    # ── Actuator lag (first-order: dx/dt = (setpoint - x) / tau) ─────────────
    def _lag(self, current, setpoint, tau, dt):
        """Euler step of first-order actuator lag."""
        return current + dt * (setpoint - current) / tau

    # ── ODE right-hand side ───────────────────────────────────────────────────
    def _derivatives(self, state, t, Q_in, Q_out, C_dose_mgL):
        """
        state = [V, C]
        V : volume in litres
        C : chlorine concentration in mg/L

        dV/dt = Q_in - Q_out  (L/s)

        dC/dt = (Q_in * C_dose + C_in * Q_in - k_d * C * V - C * Q_out) / V
              simplified (C_in = C_dose from dosing pump, no background chlorine):
              = Q_in * C_dose / V - k_d * C - Q_out * C / V

        When V approaches 0, division is unstable — guard with max(V, 1.0).
        """
        V, C = state
        V    = max(V, 1.0)  # prevent division by zero

        dV_dt = Q_in - Q_out
        dC_dt = (Q_in * C_dose_mgL) / V - K_DECAY_1_S * C - (Q_out * C) / V

        return [dV_dt, dC_dt]

    # ── Add sensor noise + drift ───────────────────────────────────────────────
    def _noisy(self, true_val, sigma, drift_state, drift_key):
        """Gaussian noise + slow random walk drift."""
        # Update drift with a small random step (Brownian motion)
        self._drift_level += random.gauss(0, DRIFT_RATE) if drift_key == "level" else 0
        self._drift_cl    += random.gauss(0, DRIFT_RATE) if drift_key == "cl"    else 0
        drift = self._drift_level if drift_key == "level" else self._drift_cl

        noisy = true_val + random.gauss(0, sigma) + drift
        return noisy

    # ── Main step function ─────────────────────────────────────────────────────
    def step(self, dt, coils, regs):
        """
        Advance the physics by dt seconds given current PLC coil and register state.

        coils : list of 12 booleans (Modbus coil map from program.st)
        regs  : list of 4 ints     (Holding registers: Cl_Dose, Coag, Speed, Level)

        Returns dict with:
          level_pct     : reservoir level % (with noise) — write to HR3
          chlorine_mgL  : chlorine concentration (with noise)
          chlorine_dose_register : what Cl register should be set to (OPTIONAL)
          volume_L      : true tank volume (no noise — internal use)
          q_in_ls       : actual inflow (L/s)
          q_out_ls      : actual outflow (L/s)
          who_safe      : bool — chlorine within WHO safe range
          toxic         : bool — chlorine above WHO toxic threshold
        """
        # Unpack coil state
        intake_pump      = coils[0]
        intake_valve     = coils[1]
        reservoir_inlet  = coils[7]
        reservoir_outlet = coils[8]
        dist_pump        = coils[9]
        system_enable    = coils[11]

        dist_speed_pct = regs[2] / 100.0     # 0–1
        chlorine_reg   = regs[0]             # 0–850 integer

        # Map chlorine register → mg/L dose
        c_dose_mgL = chlorine_reg * DOSE_SCALE_FACTOR

        # Advance actuator lags
        # Intake valve: setpoint = 1 if intake_valve coil is TRUE
        self.intake_valve_actual = self._lag(
            self.intake_valve_actual,
            1.0 if (intake_valve and system_enable) else 0.0,
            TAU_VALVE, dt
        )
        self.reservoir_inlet_actual = self._lag(
            self.reservoir_inlet_actual,
            1.0 if (reservoir_inlet and system_enable) else 0.0,
            TAU_VALVE, dt
        )
        self.reservoir_outlet_actual = self._lag(
            self.reservoir_outlet_actual,
            1.0 if (reservoir_outlet and system_enable) else 0.0,
            TAU_VALVE, dt
        )
        self.dist_pump_fraction = self._lag(
            self.dist_pump_fraction,
            dist_speed_pct if (dist_pump and system_enable) else 0.0,
            TAU_PUMP, dt
        )

        # Compute actual flow rates using actuator fractions
        # Q_in: intake pump must be running AND intake valve must be open
        q_in_intake = (Q_IN_NOMINAL_LS * self.intake_valve_actual
                       if intake_pump and system_enable else 0.0)

        # Q_in_reservoir: the flow actually reaching the reservoir
        # (goes through dosing, filtration, UV — all simplified to a fraction here)
        q_in_reservoir = q_in_intake * self.reservoir_inlet_actual

        # Q_out: distribution pump flow, gated by outlet valve
        q_out = (Q_OUT_NOMINAL_LS * self.dist_pump_fraction
                 * self.reservoir_outlet_actual)

        # Clamp: volume cannot exceed max or go below 0
        if self.volume_L >= TANK_VOLUME_MAX_L and q_in_reservoir > q_out:
            q_in_reservoir = q_out  # tank full — inflow equals outflow (overflow spillway)
        if self.volume_L <= 0 and q_out > q_in_reservoir:
            q_out = q_in_reservoir  # tank empty — no outflow

        # Integrate ODEs
        state0 = [self.volume_L, self.chlorine_mgL]

        if _SCIPY:
            # scipy odeint gives better numerical stability for stiff ODEs
            sol = odeint(
                self._derivatives,
                state0,
                [0, dt],
                args=(q_in_reservoir, q_out, c_dose_mgL),
                rtol=1e-4, atol=1e-6
            )
            new_V, new_C = sol[-1]
        else:
            # Euler fallback (adequate for dt ≤ 0.5s and these time constants)
            dVdt = q_in_reservoir - q_out
            V    = max(state0[0], 1.0)
            dCdt = (q_in_reservoir * c_dose_mgL / V
                    - K_DECAY_1_S * state0[1]
                    - q_out * state0[1] / V)
            new_V = state0[0] + dVdt * dt
            new_C = state0[1] + dCdt * dt

        # Physical bounds
        new_V = max(0.0, min(new_V, TANK_VOLUME_MAX_L))
        new_C = max(0.0, new_C)

        self.volume_L     = new_V
        self.chlorine_mgL = new_C
        self.t           += dt

        # Compute level percentage (true value)
        level_true = 100.0 * new_V / TANK_VOLUME_MAX_L

        # Apply sensor noise
        level_noisy    = self._noisy(level_true, SIGMA_LEVEL, self._drift_level, "level")
        chlorine_noisy = self._noisy(new_C,       SIGMA_CHLORINE, self._drift_cl, "cl")

        # Clamp noisy outputs to valid register range
        level_pct_int  = int(max(0, min(100, round(level_noisy))))
        # Chlorine mg/L → register value (reverse of dose scale)
        # The register is the DOSE setpoint (input), not the measured concentration.
        # We report concentration separately for monitoring; don't overwrite the dose register.

        return {
            "level_pct":         level_pct_int,
            "level_pct_true":    round(level_true, 2),
            "chlorine_mgL":      round(chlorine_noisy, 3),
            "chlorine_mgL_true": round(new_C, 3),
            "volume_L":          round(new_V, 1),
            "q_in_ls":           round(q_in_reservoir, 3),
            "q_out_ls":          round(q_out, 3),
            "dose_mgL":          round(c_dose_mgL, 2),
            "who_safe":          0.2 <= chlorine_noisy <= WHO_SAFE_MAX_MGL,
            "toxic":             chlorine_noisy > WHO_TOXIC_MGL,
            "actuators": {
                "intake_valve_pct":     round(self.intake_valve_actual * 100, 1),
                "reservoir_inlet_pct":  round(self.reservoir_inlet_actual * 100, 1),
                "reservoir_outlet_pct": round(self.reservoir_outlet_actual * 100, 1),
                "dist_pump_pct":        round(self.dist_pump_fraction * 100, 1),
            },
            "scipy_used": _SCIPY,
        }


# ── Standalone runner — writes physics to PLC in real time ───────────────────
def run_physics_loop(dry_run=False, tick=0.5):
    """
    Poll PLC state, compute physics step, write results back.

    This loop runs at `tick` seconds. The PLC scan cycle is 20ms —
    we write at 0.5s which is 25 scans. The PLC may write its own
    +1 counter between our writes, so we also patch program.st (see
    INSTALLATION NOTE below) to remove the counter and rely on this
    process for level updates.

    INSTALLATION NOTE:
      program.st BLOCK 5 reservoir level update has been replaced to
      remove the naive +1 counter. See the comments in program.st
      around "PHYSICS ENGINE HOOK" — the level register is now written
      externally by this process rather than computed inside the PLC scan.
    """
    print(f"""
  Physics engine starting:
    tick       = {tick}s
    scipy      = {_SCIPY} ({'ODE solver' if _SCIPY else 'Euler fallback'})
    dry_run    = {dry_run}
    tank_max   = {TANK_VOLUME_MAX_L:,.0f} L
    k_decay    = {K_DECAY_1_S} /s  (WHO first-order chlorine decay at 20°C)
    dose_scale = {DOSE_SCALE_FACTOR} mg/L per register unit
    WHO safe   = 0.2–{WHO_SAFE_MAX_MGL} mg/L
    WHO toxic  = >{WHO_TOXIC_MGL} mg/L

  Chlorine dose interpretation:
    register 200 → {200*DOSE_SCALE_FACTOR:.1f} mg/L  (WHO nominal, safe)
    register 500 → {500*DOSE_SCALE_FACTOR:.1f} mg/L  (upper safe range)
    register 850 → {850*DOSE_SCALE_FACTOR:.1f} mg/L  (above WHO guideline)
    register 1000→ {1000*DOSE_SCALE_FACTOR:.1f} mg/L  (acute toxicity concern)
    """)

    engine = PhysicsEngine()
    client = ModbusTcpClient("127.0.0.1", port=502)

    if not client.connect():
        print("[!] Cannot connect to PLC. Is OpenPLC running?")
        sys.exit(1)

    print(f"  Connected to PLC. Starting physics loop (Ctrl-C to stop).\n")
    print(f"  {'Time':>8}  {'Level%':>8}  {'Volume_L':>10}  "
          f"{'Cl_mgL':>8}  {'Q_in':>8}  {'Q_out':>8}  {'WHO':>6}  {'Toxic':>6}")
    print("  " + "─" * 75)

    try:
        while True:
            t0 = time.monotonic()

            # Read current PLC state
            rc = client.read_coils(0, 12)
            rr = client.read_holding_registers(0, 4)

            if rc.isError() or rr.isError():
                print(f"  [PHYS] Read error — retrying...")
                time.sleep(tick)
                continue

            coils = list(rc.bits[:12])
            regs  = list(rr.registers[:4])

            # Advance physics
            state = engine.step(dt=tick, coils=coils, regs=regs)

            # Write level back to PLC (HR3 = Reservoir_Level_Pct)
            if not dry_run:
                client.write_register(3, state["level_pct"])

            # Print status line
            who_str   = "OK " if state["who_safe"] else "WARN"
            toxic_str = "YES" if state["toxic"]    else "no "
            print(f"  {engine.t:>8.1f}  "
                  f"{state['level_pct']:>8}  "
                  f"{state['volume_L']:>10,.0f}  "
                  f"{state['chlorine_mgL']:>8.3f}  "
                  f"{state['q_in_ls']:>8.3f}  "
                  f"{state['q_out_ls']:>8.3f}  "
                  f"{who_str:>6}  "
                  f"{toxic_str:>6}")

            if state["toxic"]:
                print(f"  ⚠  CHLORINE {state['chlorine_mgL']:.3f} mg/L EXCEEDS "
                      f"WHO TOXIC THRESHOLD ({WHO_TOXIC_MGL} mg/L)")

            # Sleep for remainder of tick
            elapsed = time.monotonic() - t0
            sleep_t = max(0, tick - elapsed)
            time.sleep(sleep_t)

    except KeyboardInterrupt:
        print("\n  Physics engine stopped.")
        client.close()


# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="ODE Physics Engine for Water Treatment Simulation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute physics but do not write to PLC registers")
    parser.add_argument("--tick", type=float, default=0.5,
                        help="Physics update interval in seconds (default 0.5)")
    parser.add_argument("--status", action="store_true",
                        help="Show physics interpretation of current register values and exit")
    args = parser.parse_args()

    if args.status:
        client = ModbusTcpClient("127.0.0.1", port=502)
        if not client.connect():
            print("Cannot connect to PLC")
            sys.exit(1)
        rr = client.read_holding_registers(0, 4)
        client.close()
        if not rr.isError():
            regs = rr.registers
            cl_mgL = regs[0] * DOSE_SCALE_FACTOR
            print(f"\n  Current register interpretation:")
            print(f"  Chlorine_Dose   = {regs[0]} → {cl_mgL:.2f} mg/L", end="")
            if cl_mgL > WHO_TOXIC_MGL:
                print(f"  ⚠ ABOVE TOXIC THRESHOLD ({WHO_TOXIC_MGL} mg/L)")
            elif cl_mgL > WHO_SAFE_MAX_MGL:
                print(f"  ⚠ ABOVE WHO SAFE LIMIT ({WHO_SAFE_MAX_MGL} mg/L)")
            else:
                print(f"  ✓ within WHO safe range (0.2–{WHO_SAFE_MAX_MGL} mg/L)")
            print(f"  Reservoir_Level = {regs[3]}%")
            vol = TANK_VOLUME_MAX_L * regs[3] / 100
            print(f"  Estimated volume= {vol:,.0f} L of {TANK_VOLUME_MAX_L:,.0f} L max")
        return

    run_physics_loop(dry_run=args.dry_run, tick=args.tick)

if __name__ == "__main__":
    main()