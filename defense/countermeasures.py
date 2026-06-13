#!/usr/bin/env python3
"""
countermeasures.py — Automated ICS Defense Response Engine
============================================================
CPSS End-Semester Project — Defense & Mitigation Layer

Watches the PLC state (via Modbus polling) and takes AUTOMATIC
countermeasure actions when attacks or anomalies are detected.

This implements the "Respond" phase of NIST SP 800-61 Incident Response
and maps to IEC 62443-3-3 SR 6.2 (Audit Record Review) and
SR 7.3 (Control System Backup).

Countermeasures:
  CM-1   Chemical Overdose    → Write Chlorine_Dose back to safe value (200)
  CM-2   Alarm Suppression    → Re-enable Alarm_LED if OFF during high chlorine
  CM-3   System Blackout      → SEQUENCED restore: valves first, then pumps
  CM-4   Dist Cavitation      → Force Distribution_Pump OFF if Outlet CLOSED
  CM-4b  Intake Cavitation    → Force Intake_Pump OFF if Intake_Valve CLOSED
  CM-5   Tank Overflow        → Force Reservoir_Inlet OFF if level > 85%
  CM-6   Slow Drift           → CUSUM + Z-score dual detection on Chlorine_Dose

Sequencing note (CM-3):
  Restoring a plant from a blackout is not just "write safe defaults."
  Water hammer — a destructive pressure surge — can physically rupture pipes
  if pumps restart before valves are confirmed open. Our sequenced recovery:
    Step 1: System_Enable ON, all pumps OFF, all valves open (2s dwell)
    Step 2: Intake pump allowed once intake valve confirmed open
    Step 3: Distribution pump allowed once reservoir outlet confirmed open
  This matches IEC 62443-3-3 SR 7.3 recovery procedure requirements.

Usage:
    python3 defense/countermeasures.py                  # run as daemon
    python3 defense/countermeasures.py --dry-run        # detect but don't act
    python3 defense/countermeasures.py --poll 0.5       # 500ms poll interval
"""

import sys, os, time, json, threading, math, collections, argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not found — activate venv first"); sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
PLC_HOST      = "127.0.0.1"
PLC_PORT      = 502
POLL_INTERVAL = 1.0
LOG_MAX       = 300
BASELINE_N    = 60   # samples before statistical detection is active

# ── Safe state values — these are the NOMINAL operating setpoints,
#    not arbitrary defaults. They were determined from normal plant operation.
SAFE_REGS  = [200, 300, 50, 50]    # Chlorine, Coagulant, Speed, Level
SAFE_COILS = [True, True, True, True, True, True, True, False, True, False, False, True]

REG_NAMES  = ["Chlorine_Dose", "Coagulant_Dose", "Distribution_Speed", "Reservoir_Level_Pct"]
COIL_NAMES = [
    "Intake_Pump","Intake_Valve","Chlorine_Pump","Coagulant_Pump",
    "Dosing_Enable","Filter_Valve","UV_System","Reservoir_Inlet",
    "Reservoir_Outlet","Distribution_Pump","Alarm_LED","System_Enable"
]

# ── Countermeasure definitions ─────────────────────────────────────────────────
CMS = {
    "CM-1": {
        "name": "Chemical Overdose Mitigation",
        "trigger": "Chlorine_Dose > 800",
        "action": "Write Chlorine_Dose → 200 (safe nominal)",
        "iec62443": "SR 3.5 — Input Validation",
        "nist": "NIST SP 800-61 §3.3.1 Containment",
        "mitre": "T0831 — Manipulation of Control",
        "cooldown": 5,
    },
    "CM-2": {
        "name": "Alarm Suppression Recovery",
        "trigger": "Alarm_LED OFF while Chlorine_Dose > 600",
        "action": "Re-enable Alarm_LED (coil 10 → ON)",
        "iec62443": "SR 6.1 — Audit Log Accessibility",
        "nist": "NIST SP 800-61 §3.3.2 Eradication",
        "mitre": "T0838 — Modify Alarm Settings",
        "cooldown": 3,
    },
    "CM-3": {
        "name": "System Blackout — Sequenced Recovery",
        "trigger": "System_Enable OFF + all pumps OFF for 2s",
        "action": "Step 1: open valves → Step 2: enable system → Step 3: allow pumps",
        "iec62443": "SR 7.3 — Control System Backup / Recovery Procedure",
        "nist": "NIST SP 800-61 §3.4 Recovery",
        "mitre": "T0816 — Device Restart/Shutdown",
        "cooldown": 10,
    },
    "CM-4": {
        "name": "Distribution Pump Cavitation Prevention",
        "trigger": "Distribution_Pump ON + Reservoir_Outlet CLOSED",
        "action": "Force Distribution_Pump OFF — dry-run against closed outlet kills impeller",
        "iec62443": "SR 3.6 — Deterministic Output",
        "nist": "NIST SP 800-82 §6.2 Protective Technology",
        "mitre": "T0855 — Unauthorized Command Message",
        "cooldown": 4,
    },
    "CM-4b": {
        "name": "Intake Pump Cavitation Prevention",
        "trigger": "Intake_Pump ON + Intake_Valve CLOSED",
        "action": "Force Intake_Pump OFF — same cavitation risk as distribution side",
        "iec62443": "SR 3.6 — Deterministic Output",
        "nist": "NIST SP 800-82 §6.2 Protective Technology",
        "mitre": "T0855 — Unauthorized Command Message",
        "cooldown": 4,
    },
    "CM-5": {
        "name": "Tank Overflow Prevention",
        "trigger": "Reservoir_Inlet ON + Reservoir_Level_Pct > 88",
        "action": "Force Reservoir_Inlet OFF",
        "iec62443": "SR 3.5 — Input Validation",
        "nist": "NIST SP 800-82 §6.2 Protective Technology",
        "mitre": "T0855 — Unauthorized Command Message",
        "cooldown": 4,
    },
    "CM-6": {
        "name": "Statistical Drift Detection (Z-score + CUSUM)",
        "trigger": "Chlorine_Dose Z-score > 3.5σ OR CUSUM > threshold",
        "action": "Clamp Chlorine_Dose to baseline mean + 2σ",
        "iec62443": "SR 6.2 — Audit Record Review",
        "nist": "NIST SP 800-61 §3.2 Detection & Analysis",
        "mitre": "T0836 — Modify Parameter",
        "cooldown": 8,
    },
}

# ── Shared state ───────────────────────────────────────────────────────────────
lock          = threading.Lock()
cm_log: list  = []
cm_cooldowns  = {}          # cm_id → last_fired_ts
blackout_buf  = []          # timestamps confirming the blackout pattern

# ── Statistical baseline ───────────────────────────────────────────────────────
_baseline = {
    "buf":  [[] for _ in range(4)],
    "mean": [200.0, 300.0, 50.0, 50.0],
    "std":  [20.0,  30.0,  5.0,  5.0],
    "ok":   False,
    "n":    0,
}

# CUSUM state for Chlorine_Dose (index 0). We track a positive accumulator
# (Sp) and a negative one (Sn). When either exceeds the decision interval H,
# we flag a drift. Slack parameter K = half the smallest shift we care about.
_cusum = {
    "Sp": 0.0,   # positive (upward drift) accumulator
    "Sn": 0.0,   # negative (downward drift) accumulator
    "K":  15.0,  # slack — shifts smaller than this are ignored (~0.5σ of nominal)
    "H":  50.0,  # decision threshold — tune higher to reduce false positives
}


def _std(data):
    if len(data) < 2:
        return 1.0
    m = sum(data) / len(data)
    v = sum((x - m) ** 2 for x in data) / (len(data) - 1)
    return math.sqrt(v) if v > 0 else 1.0


def update_baseline(regs):
    _baseline["n"] += 1
    for j in range(4):
        _baseline["buf"][j].append(regs[j])

    if _baseline["n"] >= BASELINE_N and not _baseline["ok"]:
        _baseline["mean"] = [sum(d) / len(d) for d in _baseline["buf"]]
        _baseline["std"]  = [_std(d) for d in _baseline["buf"]]
        _baseline["ok"]   = True
        print(f"[CM] Baseline established after {BASELINE_N}s: "
              f"Cl_mean={_baseline['mean'][0]:.0f} ±{_baseline['std'][0]:.1f}")
        print(f"[CM] NOTE: {BASELINE_N}s is a demo shortcut. "
              f"Production deployments should baseline over ≥1 diurnal cycle (24h+).")


def zscore(reg_idx, value):
    m = _baseline["mean"][reg_idx]
    s = _baseline["std"][reg_idx]
    return abs(value - m) / max(s, 1.0)


def update_cusum(value):
    """
    Update the CUSUM accumulators for Chlorine_Dose.

    CUSUM is better than Z-score for detecting slow, sustained drift because
    it accumulates evidence over time instead of evaluating each reading in
    isolation. A slow drift that never crosses 3σ in any single sample will
    build up Sp or Sn until H is breached.

    Returns (Sp, Sn) after the update.
    """
    mu = _baseline["mean"][0]
    K  = _cusum["K"]
    H  = _cusum["H"]

    # Standard CUSUM update equations
    _cusum["Sp"] = max(0.0, _cusum["Sp"] + (value - mu) - K)
    _cusum["Sn"] = max(0.0, _cusum["Sn"] - (value - mu) - K)

    # Reset accumulator once we fire to avoid re-triggering every poll
    # (actual reset happens in the caller after CM-6 fires)
    return _cusum["Sp"], _cusum["Sn"]


# ── Countermeasure execution ───────────────────────────────────────────────────
def can_fire(cm_id: str) -> bool:
    cooldown = CMS[cm_id]["cooldown"]
    last = cm_cooldowns.get(cm_id, 0)
    return time.time() - last >= cooldown


def fire(client: ModbusTcpClient, cm_id: str, trigger_detail: str,
         before: str, after_fn, dry_run: bool):
    """Execute a countermeasure, log it, honour cooldown."""
    if not can_fire(cm_id):
        return

    cm_cooldowns[cm_id] = time.time()
    cm = CMS[cm_id]
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if not dry_run:
        try:
            after = after_fn(client)
        except Exception as e:
            after = f"FAILED: {e}"
    else:
        after = "[DRY RUN — no write]"

    entry = {
        "ts": ts,
        "cm_id": cm_id,
        "name": cm["name"],
        "trigger": trigger_detail,
        "action_taken": after,
        "iec62443": cm["iec62443"],
        "nist": cm["nist"],
        "mitre": cm["mitre"],
        "before": before,
        "dry_run": dry_run,
    }
    with lock:
        cm_log.append(entry)
        if len(cm_log) > LOG_MAX:
            cm_log.pop(0)

    color = "\033[91m" if not dry_run else "\033[94m"
    reset = "\033[0m"
    print(f"{color}[{cm_id}] {cm['name']}{reset}")
    print(f"  Trigger : {trigger_detail}")
    print(f"  Before  : {before}")
    print(f"  Action  : {after}")
    print(f"  IEC     : {cm['iec62443']}")
    print(f"  MITRE   : {cm['mitre']}")


def sequenced_blackout_recovery(client: ModbusTcpClient) -> str:
    """
    CM-3: Restore the plant from a blackout using a safe, ordered sequence.

    Why sequencing matters:
      If we just write System_Enable=ON and restore all registers at once,
      pumps may start before valves are confirmed open. The resulting pressure
      transient (water hammer) can exceed 10x normal pipe pressure and physically
      rupture fittings. This sequence mirrors what an operator would do manually:
      confirm valve positions before re-energising pumps.

    Step 1 — Enable system, open all valves, keep all pumps OFF
    Step 2 — 1 second dwell to let valves physically actuate (real valves take 0.5–2s)
    Step 3 — Re-enable pumps now that valve positions are confirmed
    """
    # Step 1: system on, valves open, pumps OFF
    # Coil order: Intake_Pump(0), Intake_Valve(1), Chlorine_Pump(2), Coagulant_Pump(3),
    #             Dosing_Enable(4), Filter_Valve(5), UV_System(6), Reservoir_Inlet(7),
    #             Reservoir_Outlet(8), Distribution_Pump(9), Alarm_LED(10), System_Enable(11)
    client.write_coil(11, True)   # System_Enable ON
    client.write_coil(0,  False)  # Intake_Pump OFF — don't start yet
    client.write_coil(1,  True)   # Intake_Valve OPEN
    client.write_coil(8,  True)   # Reservoir_Outlet OPEN
    client.write_coil(9,  False)  # Distribution_Pump OFF — don't start yet
    client.write_registers(0, SAFE_REGS)

    # Step 2: dwell while valves actuate
    time.sleep(1.0)

    # Step 3: re-read actual valve states before starting pumps
    rc = client.read_coils(0, count=12)
    if not rc.isError():
        coils = list(rc.bits[:12])
        intake_valve_open = coils[1]   # confirmed by reading back, not assuming
        outlet_open       = coils[8]

        if intake_valve_open:
            client.write_coil(0, True)   # Intake_Pump ON — valve confirmed open

        if outlet_open:
            client.write_coil(9, True)   # Distribution_Pump ON — outlet confirmed open

        return (f"Sequenced recovery complete — "
                f"valves confirmed: intake={intake_valve_open}, outlet={outlet_open} — "
                f"pumps started accordingly")
    else:
        # Read failed after writing — leave pumps OFF, safer than guessing
        return "Sequenced recovery: system enabled, pumps left OFF (could not confirm valve state)"


# ── Main countermeasure poll loop ─────────────────────────────────────────────
def run_countermeasures(dry_run: bool = False, poll: float = 1.0):
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    print(f"[CM Engine] Starting — PLC {PLC_HOST}:{PLC_PORT} | dry_run={dry_run}")
    print(f"[CM Engine] {len(CMS)} countermeasures loaded | baseline={BASELINE_N}s")

    while True:
        try:
            if not client.connected:
                client.connect()
                print("[CM Engine] Connected to PLC")

            rc = client.read_coils(0, count=12)
            rr = client.read_holding_registers(0, count=4)
            if rc.isError() or rr.isError():
                raise Exception("read error")

            coils = list(rc.bits[:12])
            regs  = list(rr.registers[:4])

            update_baseline(regs)

            chlorine   = regs[0]
            coagulant  = regs[1]
            dist_speed = regs[2]
            res_level  = regs[3]

            intake_pump   = coils[0]
            intake_valve  = coils[1]   # Intake_Valve
            reservoir_in  = coils[7]   # Reservoir_Inlet
            reservoir_out = coils[8]   # Reservoir_Outlet
            dist_pump     = coils[9]   # Distribution_Pump
            alarm_led     = coils[10]
            sys_enable    = coils[11]

            # ── CM-1: Chemical Overdose ────────────────────────────────────
            if chlorine > 800:
                fire(client, "CM-1",
                     f"Chlorine_Dose={chlorine} exceeds 800 (safe max)",
                     f"HR0={chlorine}",
                     lambda c: (c.write_register(0, 200), "HR0 → 200")[1],
                     dry_run)

            # ── CM-2: Alarm Suppression Recovery ──────────────────────────
            if not alarm_led and chlorine > 600:
                fire(client, "CM-2",
                     f"Alarm_LED=OFF while Chlorine_Dose={chlorine} (>600)",
                     f"coil10=OFF, HR0={chlorine}",
                     lambda c: (c.write_coil(10, True), "coil10 → ON")[1],
                     dry_run)

            # ── CM-3: System Blackout — Sequenced Recovery ────────────────
            # Confirm pattern for 2s before acting — avoids false positives
            # during normal startup (System_Enable goes OFF→ON at boot).
            if not sys_enable and not any([coils[0], coils[2], coils[3], coils[9]]):
                blackout_buf.append(time.time())
                # Trim entries older than 3 seconds
                while blackout_buf and blackout_buf[0] < time.time() - 3:
                    blackout_buf.pop(0)

                if len(blackout_buf) >= 2:
                    fire(client, "CM-3",
                         "System_Enable=OFF + all pumps OFF for 2s — blackout confirmed",
                         f"sys_enable=OFF, coils={[int(x) for x in coils]}",
                         sequenced_blackout_recovery,
                         dry_run)
                    blackout_buf.clear()
            else:
                blackout_buf.clear()

            # ── CM-4: Distribution Pump Cavitation Prevention ──────────────
            # Distribution_Pump running against a closed Reservoir_Outlet will
            # dead-head the pump — pressure builds until either the seal fails
            # or an overpressure valve blows. Kill the pump immediately.
            if dist_pump and not reservoir_out:
                fire(client, "CM-4",
                     "Distribution_Pump=ON + Reservoir_Outlet=CLOSED (dry-run / deadhead risk)",
                     f"coil9=ON, coil8=OFF",
                     lambda c: (c.write_coil(9, False), "coil9 (Distribution_Pump) → OFF")[1],
                     dry_run)

            # ── CM-4b: Intake Pump Cavitation Prevention ───────────────────
            # Same physical problem on the intake side. If Intake_Valve is
            # forced closed (attacker or valve fault) while Intake_Pump runs,
            # the pump draws a vacuum on its inlet side — impeller cavitation
            # starts within seconds. This was missing from the original engine.
            if intake_pump and not intake_valve:
                fire(client, "CM-4b",
                     "Intake_Pump=ON + Intake_Valve=CLOSED (intake cavitation risk)",
                     f"coil0=ON, coil1=OFF",
                     lambda c: (c.write_coil(0, False), "coil0 (Intake_Pump) → OFF")[1],
                     dry_run)

            # ── CM-5: Tank Overflow Prevention ────────────────────────────
            if reservoir_in and res_level > 88:
                fire(client, "CM-5",
                     f"Reservoir_Inlet=ON + Reservoir_Level={res_level}% (>88%)",
                     f"coil7=ON, HR3={res_level}",
                     lambda c: (c.write_coil(7, False), "coil7 (Reservoir_Inlet) → OFF")[1],
                     dry_run)

            # ── CM-6: Statistical Drift Detection (Z-score + CUSUM) ───────
            # We run both methods and fire if either trips. CUSUM is more
            # sensitive to slow sustained drift; Z-score catches sudden spikes.
            if _baseline["ok"]:
                z = zscore(0, chlorine)
                sp, sn = update_cusum(chlorine)

                cusum_fired = sp > _cusum["H"] or sn > _cusum["H"]
                zscore_fired = z > 3.5 and chlorine > _baseline["mean"][0]

                if cusum_fired or zscore_fired:
                    method = []
                    if zscore_fired:
                        method.append(f"Z-score={z:.2f}σ")
                    if cusum_fired:
                        method.append(f"CUSUM Sp={sp:.1f}/Sn={sn:.1f} (H={_cusum['H']})")

                    clamp = int(_baseline["mean"][0] + 2 * _baseline["std"][0])
                    clamp = min(clamp, 799)

                    def clamp_fn(c, v=clamp):
                        c.write_register(0, v)
                        return f"HR0 → {v} (mean+2σ clamp)"

                    fire(client, "CM-6",
                         f"Drift detected via {', '.join(method)}",
                         f"HR0={chlorine} (mean={_baseline['mean'][0]:.0f}, σ={_baseline['std'][0]:.1f})",
                         clamp_fn, dry_run)

                    # Reset CUSUM after firing so we don't keep retriggering
                    _cusum["Sp"] = 0.0
                    _cusum["Sn"] = 0.0

        except Exception as e:
            print(f"[CM Engine] PLC connection error: {e}")
            time.sleep(2)
            try:
                client.close()
                client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
            except Exception:
                pass

        time.sleep(poll)


# ── API helpers ───────────────────────────────────────────────────────────────
def get_cm_log() -> list:
    with lock:
        return list(cm_log)


def get_cm_summary() -> dict:
    with lock:
        hits = {}
        for e in cm_log:
            hits[e["cm_id"]] = hits.get(e["cm_id"], 0) + 1
        return {
            "total_actions": len(cm_log),
            "by_countermeasure": hits,
            "baseline_ready": _baseline["ok"],
            "baseline_samples": _baseline["n"],
            "cusum_state": {
                "Sp": round(_cusum["Sp"], 2),
                "Sn": round(_cusum["Sn"], 2),
                "H": _cusum["H"],
            },
            "countermeasures": CMS,
        }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Detect attacks but do not write to PLC")
    parser.add_argument("--poll", type=float, default=1.0,
                        help="Poll interval in seconds (default 1.0)")
    parser.add_argument("--baseline", type=int, default=60,
                        help="Baseline samples before statistical detection (default 60)")
    args = parser.parse_args()

    BASELINE_N = args.baseline

    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║         CPSS — Automated Countermeasure Engine              ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  IEC 62443-3-3 SL2 | NIST SP 800-61 Incident Response      ║
  ║  CM-3 uses sequenced valve-first recovery (water hammer     ║
  ║  prevention) | CM-6 uses Z-score + CUSUM dual detection     ║
  ╚══════════════════════════════════════════════════════════════╝
    """)
    run_countermeasures(dry_run=args.dry_run, poll=args.poll)