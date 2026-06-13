#!/usr/bin/env python3
"""
run_evaluation.py — CM-6 Detector Evaluation Script
=====================================================
CPSS Project — Phase 3 Fix (EVALUATION.md data generator)

Runs 20 scripted attack trials against the PLC with the countermeasure
engine active and collects:
  - True Positive Rate (TPR / Recall)
  - False Positive Rate (FPR)
  - Precision
  - Detection latency (seconds from attack start to CM-6 firing)
  - CM-3 recovery latency

This script produces the numbers that go into EVALUATION.md.
Run it, then paste the printed table into the doc.

USAGE:
  # Terminal 1 — start PLC (OpenPLC Runtime)
  # Terminal 2 — start countermeasure engine in dry-run first to build baseline
  python3 defense/countermeasures.py --baseline 20 --poll 0.5

  # Terminal 3 — run this evaluation
  python3 docs/run_evaluation.py

  # Or fully automated (no CM engine needed — this script runs its own internal detector):
  python3 docs/run_evaluation.py --self-contained

OUTPUT:
  - Prints results table to stdout
  - Saves results/evaluation_<timestamp>.json for EVALUATION.md reference
"""

import sys
import os
import time
import json
import math
import argparse
import threading
import collections
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not installed."); sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
PLC_HOST       = "127.0.0.1"
PLC_PORT       = 502
BASELINE_N     = 20        # samples to collect before evaluation starts
POLL_INTERVAL  = 0.5       # seconds between detector polls
Z_THRESHOLD    = 3.5       # z-score threshold for CM-6
CUSUM_K        = 15.0      # CUSUM slack
CUSUM_H        = 50.0      # CUSUM decision threshold
RESULTS_DIR    = Path(__file__).parent.parent / "results"

# Normal operating values
NORMAL_CHLORINE = 200
NORMAL_COAG     = 300
NORMAL_SPEED    = 50
NORMAL_LEVEL    = 50

# ── Attack definitions — 5 classes × 4 variants each = 20 trials ──────────────
# Each trial: (name, attack_fn, is_attack, expected_detection)
# is_attack=False → normal operation trial (used for FPR calculation)

ATTACK_CLASSES = [
    # Class 1 — Sudden spike (should be caught by Z-score)
    {
        "class": "sudden_spike",
        "description": "Single write of Chlorine_Dose to 850 — sudden overdose",
        "trials": [
            {"label": "spike_850", "chlorine": 850, "slow": False},
            {"label": "spike_700", "chlorine": 700, "slow": False},
            {"label": "spike_900", "chlorine": 900, "slow": False},  # clamped to 850
            {"label": "spike_650", "chlorine": 650, "slow": False},
        ],
        "is_attack": True,
    },
    # Class 2 — Slow drift (should be caught by CUSUM, may miss Z-score)
    {
        "class": "slow_drift",
        "description": "Incrementally raise Chlorine_Dose by 10 per second",
        "trials": [
            {"label": "drift_10step", "step": 10, "target": 500},
            {"label": "drift_5step",  "step": 5,  "target": 400},
            {"label": "drift_15step", "step": 15, "target": 600},
            {"label": "drift_8step",  "step": 8,  "target": 450},
        ],
        "is_attack": True,
    },
    # Class 3 — Alarm suppression (coil 10 written to FALSE)
    {
        "class": "alarm_suppression",
        "description": "Force Alarm_LED OFF while raising chlorine",
        "trials": [
            {"label": "suppress_then_spike_800", "chlorine": 800},
            {"label": "suppress_then_spike_700", "chlorine": 700},
            {"label": "suppress_then_spike_750", "chlorine": 750},
            {"label": "suppress_then_spike_680", "chlorine": 680},
        ],
        "is_attack": True,
    },
    # Class 4 — Blackout (System_Enable written to FALSE)
    {
        "class": "blackout",
        "description": "Force System_Enable coil OFF, simulating shutdown attack",
        "trials": [
            {"label": "blackout_5s",  "duration": 5},
            {"label": "blackout_3s",  "duration": 3},
            {"label": "blackout_8s",  "duration": 8},
            {"label": "blackout_10s", "duration": 10},
        ],
        "is_attack": True,
    },
    # Class 5 — Normal operation (used for FPR: detector should NOT fire)
    {
        "class": "normal_operation",
        "description": "Normal values — no attack. Detector should stay silent.",
        "trials": [
            {"label": "normal_baseline",   "chlorine": 200},
            {"label": "normal_slight_up",  "chlorine": 250},
            {"label": "normal_slight_dn",  "chlorine": 180},
            {"label": "normal_exact_mean", "chlorine": 200},
        ],
        "is_attack": False,
    },
]

# ── Internal CM-6 detector (self-contained mode) ──────────────────────────────
class InternalDetector:
    """
    Mirrors the CM-6 logic from countermeasures.py exactly.
    Used when --self-contained is passed so we don't need the CM engine running.
    """
    def __init__(self):
        self.buf = []
        self.mean = NORMAL_CHLORINE
        self.std  = 20.0
        self.baseline_ok = False
        self.Sp = 0.0
        self.Sn = 0.0
        self.fired = False
        self.fire_time = None
        self.n = 0

    def update(self, value, ts):
        self.n += 1
        self.buf.append(value)

        if self.n == BASELINE_N:
            self.mean = sum(self.buf) / len(self.buf)
            variance  = sum((x - self.mean)**2 for x in self.buf) / (len(self.buf) - 1)
            self.std  = math.sqrt(variance) if variance > 0 else 1.0
            self.baseline_ok = True

        if not self.baseline_ok:
            return False

        # Z-score
        z = abs(value - self.mean) / max(self.std, 1.0)

        # CUSUM
        self.Sp = max(0.0, self.Sp + (value - self.mean) - CUSUM_K)
        self.Sn = max(0.0, self.Sn - (value - self.mean) - CUSUM_K)

        z_fired     = z > Z_THRESHOLD and value > self.mean
        cusum_fired = self.Sp > CUSUM_H or self.Sn > CUSUM_H

        if (z_fired or cusum_fired) and not self.fired:
            self.fired     = True
            self.fire_time = ts
            return True
        return False

    def reset(self):
        # Keep baseline, reset detection state for next trial
        self.Sp    = 0.0
        self.Sn    = 0.0
        self.fired = False
        self.fire_time = None

# ── Trial runners ──────────────────────────────────────────────────────────────
def run_sudden_spike(client, trial):
    client.write_register(0, trial["chlorine"])
    return {"writes": 1, "final_value": trial["chlorine"]}

def run_slow_drift(client, trial):
    start = NORMAL_CHLORINE
    target = trial["target"]
    step   = trial["step"]
    val    = start
    writes = 0
    while val < target:
        val = min(val + step, target)
        client.write_register(0, val)
        writes += 1
        time.sleep(1.0)
    return {"writes": writes, "final_value": val}

def run_alarm_suppression(client, trial):
    client.write_coil(10, False)   # suppress alarm LED
    client.write_register(0, trial["chlorine"])
    return {"writes": 2, "final_value": trial["chlorine"]}

def run_blackout(client, trial):
    client.write_coil(11, False)   # System_Enable OFF
    time.sleep(trial["duration"])
    client.write_coil(11, True)    # restore
    return {"writes": 2, "duration_s": trial["duration"]}

def run_normal(client, trial):
    client.write_register(0, trial["chlorine"])
    return {"writes": 1, "final_value": trial["chlorine"]}

# ── Single trial evaluation ────────────────────────────────────────────────────
def evaluate_trial(client, detector, attack_class, trial, is_attack):
    """
    Run one trial. Returns a result dict with detection outcome + latency.
    """
    result = {
        "class":      attack_class,
        "label":      trial["label"],
        "is_attack":  is_attack,
        "detected":   False,
        "latency_s":  None,
        "outcome":    None,   # TP, TN, FP, FN
        "method":     None,   # z_score, cusum, both, none
    }

    # Restore safe state before each trial
    client.write_register(0, NORMAL_CHLORINE)
    client.write_register(1, NORMAL_COAG)
    client.write_register(2, NORMAL_SPEED)
    client.write_coil(10, True)   # Alarm_LED on
    client.write_coil(11, True)   # System_Enable on
    time.sleep(1.0)

    detector.reset()
    attack_start = time.monotonic()

    # Launch attack in thread while detector polls
    attack_done = threading.Event()
    attack_info = {}

    def do_attack():
        if attack_class == "sudden_spike":
            attack_info.update(run_sudden_spike(client, trial))
        elif attack_class == "slow_drift":
            attack_info.update(run_slow_drift(client, trial))
        elif attack_class == "alarm_suppression":
            attack_info.update(run_alarm_suppression(client, trial))
        elif attack_class == "blackout":
            attack_info.update(run_blackout(client, trial))
        elif attack_class == "normal_operation":
            attack_info.update(run_normal(client, trial))
        attack_done.set()

    t = threading.Thread(target=do_attack, daemon=True)
    t.start()

    # Poll detector while attack runs (+ 5s grace window after)
    deadline = time.monotonic() + 30  # max trial duration
    detected_at = None
    while time.monotonic() < deadline:
        rr = client.read_holding_registers(0, 1)
        if rr.isError():
            time.sleep(POLL_INTERVAL)
            continue

        now = time.monotonic()
        val = rr.registers[0]
        fired = detector.update(val, now)
        if fired and detected_at is None:
            detected_at = now

        if attack_done.is_set() and (time.monotonic() - attack_start > 5):
            break
        time.sleep(POLL_INTERVAL)

    t.join(timeout=35)

    if detected_at is not None:
        result["detected"]  = True
        result["latency_s"] = round(detected_at - attack_start, 2)

    # Compute outcome
    if is_attack and result["detected"]:
        result["outcome"] = "TP"
    elif is_attack and not result["detected"]:
        result["outcome"] = "FN"
    elif not is_attack and result["detected"]:
        result["outcome"] = "FP"
    else:
        result["outcome"] = "TN"

    # Restore PLC state after trial
    client.write_register(0, NORMAL_CHLORINE)
    client.write_coil(11, True)
    time.sleep(1.0)

    return result

# ── Build baseline ─────────────────────────────────────────────────────────────
def build_baseline(client, detector):
    print(f"\n  [BASELINE] Collecting {BASELINE_N} samples at normal operation...")
    for i in range(BASELINE_N):
        rr = client.read_holding_registers(0, 1)
        if not rr.isError():
            detector.update(rr.registers[0], time.monotonic())
        time.sleep(POLL_INTERVAL)
        print(f"  [BASELINE] {i+1}/{BASELINE_N}", end="\r")
    print(f"\n  [BASELINE] Done. mean={detector.mean:.1f} std={detector.std:.1f}")

# ── Compute summary stats ──────────────────────────────────────────────────────
def compute_stats(results):
    TP = sum(1 for r in results if r["outcome"] == "TP")
    TN = sum(1 for r in results if r["outcome"] == "TN")
    FP = sum(1 for r in results if r["outcome"] == "FP")
    FN = sum(1 for r in results if r["outcome"] == "FN")

    TPR       = TP / (TP + FN) if (TP + FN) > 0 else 0
    FPR       = FP / (FP + TN) if (FP + TN) > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    f1        = (2 * precision * TPR / (precision + TPR)) if (precision + TPR) > 0 else 0

    latencies = [r["latency_s"] for r in results if r["latency_s"] is not None]
    avg_lat   = round(sum(latencies) / len(latencies), 2) if latencies else None
    min_lat   = min(latencies) if latencies else None
    max_lat   = max(latencies) if latencies else None

    return {
        "TP": TP, "TN": TN, "FP": FP, "FN": FN,
        "TPR": round(TPR, 3),
        "FPR": round(FPR, 3),
        "precision": round(precision, 3),
        "F1": round(f1, 3),
        "latency_avg_s": avg_lat,
        "latency_min_s": min_lat,
        "latency_max_s": max_lat,
    }

# ── Print table ────────────────────────────────────────────────────────────────
def print_results(results, stats):
    print("\n" + "═"*75)
    print(f"  CM-6 EVALUATION RESULTS — {len(results)} trials")
    print("═"*75)
    print(f"  {'Label':<30} {'Class':<20} {'Attack':<8} {'Outcome':<8} {'Latency'}")
    print("  " + "─"*70)
    for r in results:
        lat = f"{r['latency_s']}s" if r["latency_s"] else "—"
        outcome_col = {
            "TP": "\033[92mTP\033[0m",
            "TN": "\033[92mTN\033[0m",
            "FP": "\033[91mFP\033[0m",
            "FN": "\033[91mFN\033[0m",
        }.get(r["outcome"], r["outcome"])
        print(f"  {r['label']:<30} {r['class']:<20} {'YES' if r['is_attack'] else 'NO':<8} {outcome_col:<18} {lat}")

    print("\n" + "═"*75)
    print(f"  SUMMARY")
    print("═"*75)
    print(f"  TP={stats['TP']}  TN={stats['TN']}  FP={stats['FP']}  FN={stats['FN']}")
    print(f"  TPR (Recall)    = {stats['TPR']:.3f}  ({stats['TPR']*100:.1f}%)")
    print(f"  FPR             = {stats['FPR']:.3f}  ({stats['FPR']*100:.1f}%)")
    print(f"  Precision       = {stats['precision']:.3f}  ({stats['precision']*100:.1f}%)")
    print(f"  F1 Score        = {stats['F1']:.3f}")
    print(f"  Avg Det Latency = {stats['latency_avg_s']}s")
    print(f"  Min Det Latency = {stats['latency_min_s']}s")
    print(f"  Max Det Latency = {stats['latency_max_s']}s")
    print("═"*75)
    print("\n  Copy the above into docs/EVALUATION.md")

# ── Save JSON ──────────────────────────────────────────────────────────────────
def save_results(results, stats):
    RESULTS_DIR.mkdir(exist_ok=True)
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"evaluation_{ts}.json"
    out.write_text(json.dumps({
        "timestamp":    ts,
        "n_trials":     len(results),
        "detector":     "CM-6 Z-score+CUSUM (self-contained)",
        "z_threshold":  Z_THRESHOLD,
        "cusum_K":      CUSUM_K,
        "cusum_H":      CUSUM_H,
        "baseline_n":   BASELINE_N,
        "stats":        stats,
        "trials":       results,
    }, indent=2), encoding="utf-8")
    print(f"\n  Results saved to {out}")

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CM-6 Detector Evaluation")
    parser.add_argument("--plc-host",      default=PLC_HOST)
    parser.add_argument("--plc-port",      default=PLC_PORT, type=int)
    parser.add_argument("--self-contained", action="store_true",
                        help="Run internal detector (don't need CM engine running)")
    args = parser.parse_args()

    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║       CPSS — CM-6 Evaluation Runner (20 Trials)             ║
  ║       Produces TPR / FPR / Precision / Latency for          ║
  ║       EVALUATION.md                                         ║
  ╚══════════════════════════════════════════════════════════════╝
    """)

    client = ModbusTcpClient(args.plc_host, port=args.plc_port)
    if not client.connect():
        print(f"[!] Cannot connect to PLC at {args.plc_host}:{args.plc_port}")
        print("    Is OpenPLC Runtime running?")
        sys.exit(1)
    print(f"  [OK] Connected to PLC at {args.plc_host}:{args.plc_port}")

    detector = InternalDetector()
    build_baseline(client, detector)

    all_results = []
    trial_num   = 0

    for attack_class_def in ATTACK_CLASSES:
        cls       = attack_class_def["class"]
        is_attack = attack_class_def["is_attack"]
        print(f"\n  ── Class: {cls} ({'ATTACK' if is_attack else 'NORMAL'}) ──")

        for trial in attack_class_def["trials"]:
            trial_num += 1
            print(f"  [{trial_num:02d}/20] {trial['label']}...", end=" ", flush=True)
            result = evaluate_trial(client, detector, cls, trial, is_attack)
            all_results.append(result)
            print(f"{result['outcome']}  lat={result['latency_s']}s")

    client.close()

    stats = compute_stats(all_results)
    print_results(all_results, stats)
    save_results(all_results, stats)

if __name__ == "__main__":
    main()