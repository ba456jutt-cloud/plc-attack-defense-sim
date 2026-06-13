#!/usr/bin/env python3
"""
sis.py — Safety Instrumented System (SIS)
==========================================
CPSS Project — Phase 5 Fix

A Safety Instrumented System is a second, independent controller that
monitors safety-critical signals and takes hard-cut actions if the main
PLC fails to do so. It runs as a completely separate process, polls its
own Modbus connection, and does NOT share any code path with the main
countermeasures engine.

This models the Triconex / HIMA pattern that Stuxnet's evolution targeted
in the Triton/TRISIS attack (2017, Schneider Electric Triconex at Petro Jubail).
The existence of an SIS changes which attacks succeed:
  - Logic injection into the MAIN PLC is now partially mitigated — the SIS
    still sees the real register values and hard-cuts if thresholds are crossed.
  - The only way to fully defeat the plant is to attack BOTH the main PLC
    AND the SIS simultaneously (Triton-class attack, out of scope).

SIS ACTIONS (hard-cut, no debounce, no cooldown):
  SIS-1  Chlorine_Dose > CHLORINE_HARD_LIMIT → force Chlorine_Pump OFF + Dosing_Enable OFF
  SIS-2  Reservoir_Level_Pct > OVERFLOW_LIMIT → force Reservoir_Inlet OFF
  SIS-3  Reservoir_Level_Pct < UNDERFLOW_LIMIT → force Distribution_Pump OFF
  SIS-4  Chlorine_Dose < 0 (should be impossible, checks sensor sanity)
  SIS-5  Both Level_Low AND Level_High sensors TRUE → sensor contradiction → SCRAM

SCRAM: if 2 or more SIS actions fire in the same poll cycle, initiate a full
plant SCRAM (all pumps OFF, all valves closed, System_Enable OFF). This matches
the real SIS behaviour where multiple simultaneous faults indicate either a
cyber attack or a catastrophic physical failure — either way, safest response
is controlled shutdown.

INDEPENDENCE DESIGN:
  - Separate Modbus client (own TCP connection)
  - Separate process (run as: python3 defense/sis.py)
  - No imports from countermeasures.py
  - Writes directly to coils/registers, bypassing the main PLC logic layer
  - Logs to a SEPARATE log file (sis_log.json) so attacker clearing main logs
    does not erase SIS evidence

USAGE:
  python3 defense/sis.py                       # run as daemon
  python3 defense/sis.py --dry-run             # detect but don't write
  python3 defense/sis.py --poll 0.25           # 250ms poll (faster than main CM)
  python3 defense/sis.py --status              # print current SIS state and exit
"""

import sys
import os
import time
import json
import argparse
import threading
from datetime import datetime
from pathlib import Path

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not installed. Run: pip install pymodbus==3.6.6")
    sys.exit(1)

# ── Hard-limit thresholds ─────────────────────────────────────────────────────
# These are set LOWER than the main PLC interlocks to catch cases where the
# main PLC logic has been replaced (logic injection) and its interlocks removed.
#
# Main PLC clamp:  Chlorine_Dose > 850  → clamp to 850
# SIS hard limit:  Chlorine_Dose > 700  → force pump OFF
# This 150-unit gap means the SIS fires BEFORE the main PLC clamp is reached,
# providing an independent second layer of protection.

CHLORINE_HARD_LIMIT  = 700   # above this → SIS-1 fires (main PLC clamps at 850)
OVERFLOW_LIMIT       = 90    # level % above this → SIS-2 fires (main PLC at 88)
UNDERFLOW_LIMIT      = 5     # level % below this → SIS-3 fires

# Coil addresses (from program.st variable map)
COIL_INTAKE_PUMP      = 0
COIL_INTAKE_VALVE     = 1
COIL_CHLORINE_PUMP    = 2
COIL_COAGULANT_PUMP   = 3
COIL_DOSING_ENABLE    = 4
COIL_FILTER_VALVE     = 5
COIL_UV_SYSTEM        = 6
COIL_RESERVOIR_INLET  = 7
COIL_RESERVOIR_OUTLET = 8
COIL_DISTRIBUTION_PUMP= 9
COIL_ALARM_LED        = 10
COIL_SYSTEM_ENABLE    = 11

# Register addresses
HR_CHLORINE_DOSE      = 0
HR_COAGULANT_DOSE     = 1
HR_DISTRIBUTION_SPEED = 2
HR_RESERVOIR_LEVEL    = 3

# ── Config ────────────────────────────────────────────────────────────────────
PLC_HOST     = "127.0.0.1"
PLC_PORT     = 502
POLL_DEFAULT = 0.5
LOG_DIR      = Path(__file__).parent.parent / "logs"

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED  = "\033[91m"
GRN  = "\033[92m"
YLW  = "\033[93m"
CYN  = "\033[96m"
PRP  = "\033[95m"
BOLD = "\033[1m"
RST  = "\033[0m"

# ── Shared state ──────────────────────────────────────────────────────────────
_lock         = threading.Lock()
_sis_log      = []
_scram_active = False
_actions_this_cycle = 0

def ts():
    return datetime.now().isoformat()

def log_action(action_id, trigger, write_result, dry_run):
    entry = {
        "ts":           ts(),
        "action_id":    action_id,
        "trigger":      trigger,
        "write_result": write_result,
        "dry_run":      dry_run,
        "scram":        _scram_active,
    }
    with _lock:
        _sis_log.append(entry)
    colour = YLW if dry_run else RED
    print(f"  {colour}[SIS {action_id}]{RST} {trigger}")
    if not dry_run:
        print(f"    → {write_result}")

def save_log():
    LOG_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out   = LOG_DIR / f"sis_log_{stamp}.json"
    with _lock:
        data = list(_sis_log)
    out.write_text(json.dumps({
        "system":  "SIS",
        "version": "1.0",
        "thresholds": {
            "chlorine_hard_limit":  CHLORINE_HARD_LIMIT,
            "overflow_limit":       OVERFLOW_LIMIT,
            "underflow_limit":      UNDERFLOW_LIMIT,
        },
        "events": data,
    }, indent=2), encoding="utf-8")
    print(f"  {GRN}[SIS]{RST} Log saved → {out}")

# ── SIS Actions ───────────────────────────────────────────────────────────────

def sis1_chlorine_hardcut(client, chlorine, dry_run):
    """
    SIS-1: Chlorine hard-cut.
    Forces Chlorine_Pump OFF and Dosing_Enable OFF regardless of main PLC state.
    Also writes Chlorine_Dose to safe nominal (200) so that even if logic injection
    re-enables the pump, there is no dangerous chemical in the lines immediately.
    """
    trigger = (f"Chlorine_Dose={chlorine} > HARD_LIMIT={CHLORINE_HARD_LIMIT} "
               f"— main PLC interlocks may be compromised")
    if not dry_run:
        client.write_coil(COIL_CHLORINE_PUMP,  False)
        client.write_coil(COIL_DOSING_ENABLE,  False)
        client.write_register(HR_CHLORINE_DOSE, 200)
        result = "Chlorine_Pump=OFF, Dosing_Enable=OFF, Chlorine_Dose→200"
    else:
        result = "[DRY RUN]"
    log_action("SIS-1", trigger, result, dry_run)


def sis2_overflow_hardcut(client, level, dry_run):
    """
    SIS-2: Reservoir overflow hard-cut.
    Forces Reservoir_Inlet OFF. The main PLC shuts the inlet at 88%;
    the SIS fires at 90% as a backup in case that logic was replaced.
    """
    trigger = (f"Reservoir_Level_Pct={level}% > OVERFLOW_LIMIT={OVERFLOW_LIMIT}% "
               f"— reservoir overflow imminent")
    if not dry_run:
        client.write_coil(COIL_RESERVOIR_INLET, False)
        result = "Reservoir_Inlet=OFF"
    else:
        result = "[DRY RUN]"
    log_action("SIS-2", trigger, result, dry_run)


def sis3_underflow_hardcut(client, level, dry_run):
    """
    SIS-3: Reservoir underflow hard-cut.
    Forces Distribution_Pump OFF. Running the distribution pump against
    an empty reservoir dry-runs the impeller within seconds.
    """
    trigger = (f"Reservoir_Level_Pct={level}% < UNDERFLOW_LIMIT={UNDERFLOW_LIMIT}% "
               f"— distribution pump cavitation risk")
    if not dry_run:
        client.write_coil(COIL_DISTRIBUTION_PUMP, False)
        result = "Distribution_Pump=OFF"
    else:
        result = "[DRY RUN]"
    log_action("SIS-3", trigger, result, dry_run)


def sis4_sensor_contradiction(client, dry_run):
    """
    SIS-4/5: Sensor contradiction (both Low and High TRUE simultaneously).
    This is physically impossible in a working plant. Indicates either:
      a) Sensor hardware failure
      b) Attacker has written both discrete inputs to TRUE via Modbus
    Either way, we cannot trust the level reading — initiate SCRAM.
    """
    trigger = "Level_Low_Sensor=TRUE AND Level_High_Sensor=TRUE — sensor contradiction"
    if not dry_run:
        result = "SCRAM initiated (see below)"
    else:
        result = "[DRY RUN]"
    log_action("SIS-4", trigger, result, dry_run)


def scram(client, reason, dry_run):
    """
    Full plant SCRAM: all pumps OFF, all valves closed, System_Enable OFF.

    Triggered when 2+ SIS actions fire in the same poll cycle, indicating
    either a multi-vector cyber attack or a catastrophic physical failure.

    This is the ICS equivalent of a nuclear reactor SCRAM (Safety Control
    Rod Axe Man) — unconditional, immediate, irreversible without operator
    re-enable. The plant must be manually inspected before restarting.

    Note: writing System_Enable=FALSE here means the main PLC watchdog
    (Prev_System_Enable logic) will trip Watchdog_Tripped on the next scan,
    which is CORRECT — we want the PLC's own alarm to record this event.
    """
    global _scram_active
    _scram_active = True

    print(f"\n  {BOLD}{RED}╔══════════════════════════════════════════╗{RST}")
    print(f"  {BOLD}{RED}║   SIS SCRAM INITIATED                    ║{RST}")
    print(f"  {BOLD}{RED}║   Reason: {reason[:30]:<30} ║{RST}")
    print(f"  {BOLD}{RED}╚══════════════════════════════════════════╝{RST}\n")

    if not dry_run:
        # Order: stop pumps first (no water hammer — valves close after)
        client.write_coil(COIL_INTAKE_PUMP,       False)
        client.write_coil(COIL_CHLORINE_PUMP,     False)
        client.write_coil(COIL_COAGULANT_PUMP,    False)
        client.write_coil(COIL_DISTRIBUTION_PUMP, False)
        time.sleep(0.5)  # brief dwell before closing valves

        # Now close valves
        client.write_coil(COIL_INTAKE_VALVE,      False)
        client.write_coil(COIL_FILTER_VALVE,      False)
        client.write_coil(COIL_RESERVOIR_INLET,   False)
        client.write_coil(COIL_RESERVOIR_OUTLET,  False)
        client.write_coil(COIL_UV_SYSTEM,         False)
        client.write_coil(COIL_DOSING_ENABLE,     False)

        # Disable system — triggers main PLC watchdog on its next scan
        client.write_coil(COIL_SYSTEM_ENABLE,     False)

        # Force alarm LED ON (may be suppressed by injected logic — we override)
        client.write_coil(COIL_ALARM_LED,         True)

        result = "ALL PUMPS OFF, ALL VALVES CLOSED, System_Enable=OFF, Alarm_LED=ON"
    else:
        result = "[DRY RUN] SCRAM would have fired"

    log_action("SCRAM", f"Multi-fault condition: {reason}", result, dry_run)
    save_log()

# ── Main poll loop ─────────────────────────────────────────────────────────────
def run_sis(dry_run=False, poll=POLL_DEFAULT):
    global _scram_active, _actions_this_cycle

    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    print(f"  {GRN}[SIS]{RST} Starting — PLC {PLC_HOST}:{PLC_PORT} | poll={poll}s | dry_run={dry_run}")
    print(f"  {GRN}[SIS]{RST} Thresholds: Cl>{CHLORINE_HARD_LIMIT} | Level>{OVERFLOW_LIMIT}% | Level<{UNDERFLOW_LIMIT}%")
    print(f"  {GRN}[SIS]{RST} SCRAM on: 2+ simultaneous SIS actions, or sensor contradiction")
    print(f"  {YLW}[SIS]{RST} Independence: this process has no shared code with countermeasures.py\n")

    consecutive_errors = 0

    while True:
        if _scram_active:
            print(f"  {RED}[SIS]{RST} SCRAM active — polling suspended. Operator reset required.")
            time.sleep(10)
            continue

        try:
            if not client.connected:
                client.connect()
                print(f"  {GRN}[SIS]{RST} Connected to PLC")
                consecutive_errors = 0

            # Read all registers and coils in one pass
            rr = client.read_holding_registers(0, 4)
            rc = client.read_coils(0, 12)
            di = client.read_discrete_inputs(0, 4)

            if rr.isError() or rc.isError():
                raise Exception("Modbus read error")

            regs  = list(rr.registers[:4])
            coils = list(rc.bits[:12])

            chlorine   = regs[0]
            level      = regs[3]

            level_low  = di.bits[0] if not di.isError() else False
            level_high = di.bits[1] if not di.isError() else False

            _actions_this_cycle = 0

            # ── SIS-1: Chlorine hard-cut ───────────────────────────────────
            if chlorine > CHLORINE_HARD_LIMIT:
                sis1_chlorine_hardcut(client, chlorine, dry_run)
                _actions_this_cycle += 1

            # ── SIS-2: Overflow hard-cut ───────────────────────────────────
            if level > OVERFLOW_LIMIT:
                sis2_overflow_hardcut(client, level, dry_run)
                _actions_this_cycle += 1

            # ── SIS-3: Underflow hard-cut ──────────────────────────────────
            if level < UNDERFLOW_LIMIT:
                sis3_underflow_hardcut(client, level, dry_run)
                _actions_this_cycle += 1

            # ── SIS-4: Sensor contradiction → immediate SCRAM ──────────────
            if level_low and level_high:
                sis4_sensor_contradiction(client, dry_run)
                _actions_this_cycle += 1
                scram(client, "sensor contradiction — Level_Low AND Level_High both TRUE", dry_run)
                continue  # skip multi-fault check, already SCRAM'd

            # ── Multi-fault SCRAM ──────────────────────────────────────────
            # Two or more SIS actions in one cycle = multi-vector attack or
            # catastrophic physical failure. SCRAM the plant.
            if _actions_this_cycle >= 2:
                scram(client,
                      f"{_actions_this_cycle} simultaneous SIS actions fired",
                      dry_run)

            consecutive_errors = 0

        except Exception as e:
            consecutive_errors += 1
            print(f"  {YLW}[SIS]{RST} Connection error ({consecutive_errors}): {e}")
            if consecutive_errors >= 5:
                # SIS itself cannot reach the PLC — this is a failure condition.
                # Log it and alert; a real SIS would have a hardwired failsafe relay.
                print(f"  {RED}[SIS]{RST} CRITICAL: SIS cannot reach PLC for {consecutive_errors} polls")
                print(f"  {RED}[SIS]{RST} In a real plant, hardwired relay would now cut power to pumps")
                log_action("SIS-COMM-FAIL",
                           f"SIS lost PLC connection for {consecutive_errors} consecutive polls",
                           "Hardwired relay would cut power (not modeled in simulation)",
                           dry_run)
                save_log()
            time.sleep(2)
            try:
                client.close()
                client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
            except Exception:
                pass

        time.sleep(poll)

# ── Status check ──────────────────────────────────────────────────────────────
def print_status():
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    if not client.connect():
        print(f"[SIS STATUS] Cannot connect to PLC at {PLC_HOST}:{PLC_PORT}")
        return

    rr = client.read_holding_registers(0, 4)
    rc = client.read_coils(0, 12)
    di = client.read_discrete_inputs(0, 4)
    client.close()

    regs  = list(rr.registers[:4]) if not rr.isError()  else ["ERR"]*4
    coils = list(rc.bits[:12])     if not rc.isError()  else ["ERR"]*12
    dis   = list(di.bits[:4])      if not di.isError()  else ["ERR"]*4

    names_r = ["Chlorine_Dose", "Coagulant_Dose", "Dist_Speed", "Reservoir_Level_Pct"]
    names_c = ["Intake_Pump","Intake_Valve","Chlorine_Pump","Coagulant_Pump",
               "Dosing_Enable","Filter_Valve","UV_System","Reservoir_Inlet",
               "Reservoir_Outlet","Distribution_Pump","Alarm_LED","System_Enable"]
    names_d = ["Level_Low", "Level_High", "Filter_Pressure_OK", "Flow_Sensor"]

    print(f"\n  {BOLD}[SIS STATUS]{RST}")
    print(f"  {'─'*40}")
    for n, v in zip(names_r, regs):
        flag = ""
        if n == "Chlorine_Dose"       and isinstance(v, int) and v > CHLORINE_HARD_LIMIT: flag = f" {RED}⚠ EXCEEDS SIS LIMIT{RST}"
        if n == "Reservoir_Level_Pct" and isinstance(v, int) and v > OVERFLOW_LIMIT:      flag = f" {RED}⚠ OVERFLOW RISK{RST}"
        if n == "Reservoir_Level_Pct" and isinstance(v, int) and v < UNDERFLOW_LIMIT:     flag = f" {RED}⚠ UNDERFLOW RISK{RST}"
        print(f"  {n:<25} = {v}{flag}")
    print()
    for n, v in zip(names_c, coils):
        print(f"  {n:<25} = {v}")
    print()
    for n, v in zip(names_d, dis):
        flag = ""
        if n in ("Level_Low", "Level_High") and v: flag = f" {YLW}(check for contradiction){RST}"
        print(f"  {n:<25} = {v}{flag}")

# ── API helper (for dashboard integration) ────────────────────────────────────
def get_sis_status():
    with _lock:
        return {
            "scram_active":       _scram_active,
            "actions_this_cycle": _actions_this_cycle,
            "thresholds": {
                "chlorine_hard_limit": CHLORINE_HARD_LIMIT,
                "overflow_limit":      OVERFLOW_LIMIT,
                "underflow_limit":     UNDERFLOW_LIMIT,
            },
            "recent_events": list(_sis_log[-10:]),
        }

# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SIS — Safety Instrumented System")
    parser.add_argument("--dry-run", action="store_true",
                        help="Detect faults but do not write to PLC")
    parser.add_argument("--poll",   type=float, default=POLL_DEFAULT,
                        help=f"Poll interval in seconds (default {POLL_DEFAULT})")
    parser.add_argument("--status", action="store_true",
                        help="Print current PLC state and SIS threshold check, then exit")
    global PLC_HOST, PLC_PORT
    parser.add_argument("--plc-host", default=PLC_HOST)
    parser.add_argument("--plc-port", default=PLC_PORT, type=int)
    args = parser.parse_args()

    PLC_HOST = args.plc_host
    PLC_PORT = args.plc_port

    print(f"""
  {BOLD}{CYN}╔══════════════════════════════════════════════════════════════╗
  ║    SIS — Safety Instrumented System                          ║
  ║    CPSS Project — Independent Safety Layer                   ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Models: Triconex / HIMA SIS pattern                        ║
  ║  Relevant attack: Triton/TRISIS (2017) targeted this layer  ║
  ║  Independence: separate process, separate Modbus connection  ║
  ║  SCRAM: 2+ simultaneous faults → full plant shutdown         ║
  ╚══════════════════════════════════════════════════════════════╝{RST}
    """)

    if args.status:
        print_status()
        return

    try:
        run_sis(dry_run=args.dry_run, poll=args.poll)
    except KeyboardInterrupt:
        print(f"\n  {YLW}[SIS]{RST} Shutting down — saving log...")
        save_log()

if __name__ == "__main__":
    main()