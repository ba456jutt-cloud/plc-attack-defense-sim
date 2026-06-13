#!/usr/bin/env python3
"""
modbus_firewall.py — ICS Protocol-Aware Modbus Firewall
=========================================================
CPSS End-Semester Project — Defense & Mitigation Layer

Implements a real Modbus TCP proxy-firewall that sits between attackers
and the PLC on port 5502, forwarding legitimate traffic to port 502.

Architecture:
    [Attacker/Client] ──► [Port 5502: Firewall] ──► [Port 502: PLC]
                                   ↓
                            Rule evaluation
                            Rate limiting
                            Value range checks
                            Coil state integrity
                            Event logging

Rules modeled after IEC 62443-3-3 SR 3.5 (Input Validation) and
NIST SP 800-82 Section 6.2 (Protective Technology).

Usage:
    python3 defense/modbus_firewall.py          # runs on port 5502
    python3 defense/modbus_firewall.py --status # show live stats
"""

import socket, threading, time, json, collections, logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Packet capture (imported lazily to avoid circular import) ──────────────────
try:
    from defense import packet_capture as _cap
    _CAPTURE = True
except ImportError:
    try:
        import packet_capture as _cap
        _CAPTURE = True
    except ImportError:
        _CAPTURE = False

# ── Config ────────────────────────────────────────────────────────────────────
LISTEN_HOST  = "0.0.0.0"
LISTEN_PORT  = 5502          # firewall ingress
PLC_HOST     = "127.0.0.1"
PLC_PORT     = 502           # real PLC
LOG_MAX      = 500

# ── Modbus Function Codes ──────────────────────────────────────────────────────
FC_READ_COILS           = 0x01
FC_READ_DISCRETE        = 0x02
FC_READ_HOLDING_REGS    = 0x03
FC_READ_INPUT_REGS      = 0x04
FC_WRITE_SINGLE_COIL    = 0x05
FC_WRITE_SINGLE_REG     = 0x06
FC_WRITE_MULTIPLE_COILS = 0x0F
FC_WRITE_MULTIPLE_REGS  = 0x10

FC_NAMES = {
    0x01: "READ_COILS",      0x02: "READ_DISCRETE",
    0x03: "READ_HOLDING",    0x04: "READ_INPUT",
    0x05: "WRITE_COIL",      0x06: "WRITE_REG",
    0x0F: "WRITE_COILS",     0x10: "WRITE_REGS",
}

# ── Register/Coil metadata ─────────────────────────────────────────────────────
REG_NAMES   = ["Chlorine_Dose", "Coagulant_Dose", "Distribution_Speed", "Reservoir_Level_Pct"]
COIL_NAMES  = [
    "Intake_Pump","Intake_Valve","Chlorine_Pump","Coagulant_Pump",
    "Dosing_Enable","Filter_Valve","UV_System","Reservoir_Inlet",
    "Reservoir_Outlet","Distribution_Pump","Alarm_LED","System_Enable"
]

# ── Firewall Rule Engine ───────────────────────────────────────────────────────
# Rules follow IEC 62443 Security Level 2 requirements
# SL2: Protection against intentional violation with moderate resources

RULES = [
    # ── Value range enforcement (IEC 62443-3-3 SR 3.5) ─────────────────────
    # Block any write to Chlorine_Dose (HR0) above safe limit (800)
    {
        "id": "VAL-001",
        "name": "Chlorine Overdose Block",
        "type": "value_range",
        "fc": FC_WRITE_SINGLE_REG,
        "register": 0,
        "max_value": 800,
        "action": "BLOCK",
        "severity": "CRITICAL",
        "mitre": "T0831",  # Manipulation of Control
        "description": "Blocks Chlorine_Dose writes exceeding safe limit (IEC 62443 SR 3.5)",
    },
    {
        "id": "VAL-002",
        "name": "Coagulant Overdose Block",
        "type": "value_range",
        "fc": FC_WRITE_SINGLE_REG,
        "register": 1,
        "max_value": 600,
        "action": "BLOCK",
        "severity": "HIGH",
        "mitre": "T0831",
        "description": "Blocks Coagulant_Dose writes exceeding safe limit",
    },
    {
        "id": "VAL-003",
        "name": "Distribution Speed Range",
        "type": "value_range",
        "fc": FC_WRITE_SINGLE_REG,
        "register": 2,
        "min_value": 15,
        "max_value": 85,
        "action": "BLOCK",
        "severity": "MEDIUM",
        "mitre": "T0836",  # Modify Parameter
        "description": "Blocks Distribution_Speed writes outside safe operating range (15–85)",
    },
    # ── Rate limiting (IEC 62443-3-3 SR 7.2) ───────────────────────────────
    {
        "id": "RATE-001",
        "name": "Write Flood Detection",
        "type": "rate_limit",
        "fc": [FC_WRITE_SINGLE_COIL, FC_WRITE_MULTIPLE_COILS, FC_WRITE_SINGLE_REG, FC_WRITE_MULTIPLE_REGS],
        "max_per_second": 10,
        "window_seconds": 3,
        "action": "BLOCK_AND_BAN",
        "ban_seconds": 30,
        "severity": "CRITICAL",
        "mitre": "T0814",  # Denial of Service
        "description": "Blocks flood attacks — >10 write commands in 3 seconds",
    },
    # ── Alarm integrity (IEC 62443-3-3 SR 6.1) ─────────────────────────────
    {
        "id": "INT-001",
        "name": "Alarm Suppression Block",
        "type": "alarm_suppress",
        "coil": 10,           # Alarm_LED
        "force_off": False,
        "action": "BLOCK",
        "severity": "CRITICAL",
        "mitre": "T0838",  # Modify Alarm Settings
        "description": "Blocks attempts to force Alarm_LED OFF (alarm suppression attack)",
    },
    # ── System-wide coil blanket write ─────────────────────────────────────
    {
        "id": "INT-002",
        "name": "System Blackout Block",
        "type": "bulk_coil_write",
        "fc": FC_WRITE_MULTIPLE_COILS,
        "min_coils": 8,
        "all_false": True,
        "action": "BLOCK",
        "severity": "CRITICAL",
        "mitre": "T0816",  # Device Restart/Shutdown
        "description": "Blocks bulk coil-OFF writes (system blackout pattern)",
    },
    # ── Reservoir inlet with spoofed level ────────────────────────────────
    {
        "id": "INT-003",
        "name": "Tank Overflow Pattern",
        "type": "suspicious_sequence",
        "action": "BLOCK",
        "severity": "HIGH",
        "mitre": "T0855",  # Unauthorized Command Message
        "description": "Blocks sequence: Reservoir_Inlet ON + Reservoir_Level write within 2s",
    },
    # ── Slow drift / rate-of-change detection ─────────────────────────────
    {
        "id": "VAL-007",
        "name": "Chlorine Rate-of-Change Block",
        "type": "rate_of_change",
        "register": 0,           # HR0 — Chlorine_Dose
        "max_delta": 60,         # block if total drift exceeds 60 units in window
        "window_seconds": 20,    # within 20 seconds
        "action": "BLOCK",
        "severity": "HIGH",
        "mitre": "T0873",        # Project File Infection / slow manipulation
        "description": "Blocks slow drift: Chlorine_Dose cumulative change >60 in 20s",
    },
]

# ── Firewall State ─────────────────────────────────────────────────────────────
@dataclass
class FirewallStats:
    packets_seen:    int = 0
    packets_allowed: int = 0
    packets_blocked: int = 0
    packets_alerted: int = 0
    unique_clients:  set = field(default_factory=set)
    banned_ips:      dict = field(default_factory=dict)   # ip → unban_time
    rule_hits:       dict = field(default_factory=dict)   # rule_id → count
    start_time:      float = field(default_factory=time.time)

stats = FirewallStats()
event_log: list = []
rate_tracker: dict = {}   # ip → deque of timestamps
seq_tracker:  dict = {}   # ip → {last_coil7_ts, last_reg3_ts}
roc_tracker:  dict = {}   # reg_addr → deque of (timestamp, value) tuples
stats_lock = threading.Lock()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [FIREWALL] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("firewall")

def emit_event(action: str, rule_id: str, rule_name: str, src_ip: str,
               fc: int, detail: str, severity: str, mitre: str = ""):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = {
        "ts": ts, "action": action, "rule_id": rule_id,
        "rule_name": rule_name, "src_ip": src_ip,
        "fc": FC_NAMES.get(fc, f"0x{fc:02X}"), "fc_code": fc,
        "detail": detail, "severity": severity, "mitre": mitre,
    }
    with stats_lock:
        event_log.append(entry)
        if len(event_log) > LOG_MAX:
            event_log.pop(0)
        stats.rule_hits[rule_id] = stats.rule_hits.get(rule_id, 0) + 1
    color = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
             "MEDIUM": "\033[94m", "LOW": "\033[96m"}.get(severity, "")
    reset = "\033[0m"
    marker = "🚫 BLOCKED" if action == "BLOCK" else "⚠️  ALERT " if action == "ALERT" else "🔨 BANNED "
    log.info(f"{color}{marker} [{rule_id}] {rule_name} | src={src_ip} | {detail}{reset}")

# ── Modbus Packet Parser ───────────────────────────────────────────────────────
def parse_modbus(data: bytes) -> Optional[dict]:
    """Parse Modbus TCP ADU. Returns dict or None if too short."""
    if len(data) < 8:
        return None
    try:
        txn_id  = int.from_bytes(data[0:2], "big")
        proto   = int.from_bytes(data[2:4], "big")
        length  = int.from_bytes(data[4:6], "big")
        unit_id = data[6]
        fc      = data[7]
        payload = data[8:]
        return {"txn_id": txn_id, "proto": proto, "length": length,
                "unit_id": unit_id, "fc": fc, "payload": payload, "raw": data}
    except Exception:
        return None

def build_exception_response(pkt: dict, exception_code: int = 0x01) -> bytes:
    """Build Modbus exception response (FC | 0x80, exception_code)."""
    fc_err = pkt["fc"] | 0x80
    resp_payload = bytes([pkt["unit_id"], fc_err, exception_code])
    length = len(resp_payload)
    return (pkt["txn_id"].to_bytes(2, "big") + b"\x00\x00" +
            length.to_bytes(2, "big") + resp_payload)

# ── Rule Evaluation ────────────────────────────────────────────────────────────
def evaluate_rules(pkt: dict, src_ip: str) -> tuple[str, str, str, str, str]:
    """
    Returns (verdict, rule_id, rule_name, detail, severity)
    verdict: "ALLOW" | "BLOCK" | "ALERT" | "BAN"
    """
    fc = pkt["fc"]
    payload = pkt["payload"]
    now = time.time()

    # ── Check if IP is banned ──────────────────────────────────────────────
    with stats_lock:
        if src_ip in stats.banned_ips:
            if now < stats.banned_ips[src_ip]:
                remaining = int(stats.banned_ips[src_ip] - now)
                return ("BLOCK", "BAN-ACTIVE", "IP Banned",
                        f"IP {src_ip} banned — {remaining}s remaining", "CRITICAL")
            else:
                del stats.banned_ips[src_ip]

    for rule in RULES:
        rtype = rule["type"]

        # ── Value Range ────────────────────────────────────────────────────
        if rtype == "value_range" and fc == rule["fc"]:
            if len(payload) < 4:
                continue
            reg_addr = int.from_bytes(payload[0:2], "big")
            value    = int.from_bytes(payload[2:4], "big")
            if reg_addr == rule["register"]:
                max_v = rule.get("max_value", 65535)
                min_v = rule.get("min_value", 0)
                if value > max_v or value < min_v:
                    detail = (f"HR{reg_addr} ({REG_NAMES[reg_addr]}) "
                              f"write={value} violates range [{min_v}–{max_v}]")
                    return (rule["action"], rule["id"], rule["name"],
                            detail, rule["severity"])

        # ── Rate Limiting ──────────────────────────────────────────────────
        elif rtype == "rate_limit":
            allowed_fcs = rule["fc"] if isinstance(rule["fc"], list) else [rule["fc"]]
            if fc in allowed_fcs:
                window = rule["window_seconds"]
                max_rate = rule["max_per_second"] * window
                with stats_lock:
                    if src_ip not in rate_tracker:
                        rate_tracker[src_ip] = collections.deque()
                    dq = rate_tracker[src_ip]
                    dq.append(now)
                    # prune old
                    while dq and dq[0] < now - window:
                        dq.popleft()
                    count = len(dq)
                if count > max_rate:
                    detail = (f"Write flood: {count} write-commands in {window}s "
                              f"(limit {max_rate})")
                    if rule["action"] == "BLOCK_AND_BAN":
                        with stats_lock:
                            stats.banned_ips[src_ip] = now + rule["ban_seconds"]
                    return ("BLOCK", rule["id"], rule["name"],
                            detail, rule["severity"])

        # ── Alarm Suppression ──────────────────────────────────────────────
        elif rtype == "alarm_suppress":
            if fc == FC_WRITE_SINGLE_COIL:
                if len(payload) < 4:
                    continue
                coil_addr = int.from_bytes(payload[0:2], "big")
                coil_val  = int.from_bytes(payload[2:4], "big")
                # Modbus: 0x0000 = OFF, 0xFF00 = ON
                if coil_addr == rule["coil"] and coil_val == 0x0000:
                    detail = (f"Alarm_LED (coil 10) force-OFF attempt "
                              f"— alarm suppression signature (MITRE {rule['mitre']})")
                    return (rule["action"], rule["id"], rule["name"],
                            detail, rule["severity"])

        # ── Bulk Coil Write / Blackout ────────────────────────────────────
        elif rtype == "bulk_coil_write":
            if fc == FC_WRITE_MULTIPLE_COILS:
                if len(payload) < 5:
                    continue
                start_addr = int.from_bytes(payload[0:2], "big")
                qty        = int.from_bytes(payload[2:4], "big")
                byte_count = payload[4]
                coil_bytes = payload[5:5+byte_count]
                if qty >= rule["min_coils"]:
                    # Check if all coils being set to 0
                    all_zero = all(b == 0 for b in coil_bytes)
                    if rule.get("all_false") and all_zero:
                        detail = (f"Bulk coil write: {qty} coils → ALL OFF "
                                  f"starting addr {start_addr} — blackout pattern")
                        return (rule["action"], rule["id"], rule["name"],
                                detail, rule["severity"])

        # ── Suspicious Sequence: Tank Overflow ───────────────────────────
        elif rtype == "suspicious_sequence":
            with stats_lock:
                if src_ip not in seq_tracker:
                    seq_tracker[src_ip] = {}
                st = seq_tracker[src_ip]

            if fc == FC_WRITE_SINGLE_COIL and len(payload) >= 4:
                coil_addr = int.from_bytes(payload[0:2], "big")
                coil_val  = int.from_bytes(payload[2:4], "big")
                if coil_addr == 7 and coil_val == 0xFF00:
                    with stats_lock:
                        seq_tracker[src_ip]["last_coil7_ts"] = now
            elif fc == FC_WRITE_SINGLE_REG and len(payload) >= 4:
                reg_addr = int.from_bytes(payload[0:2], "big")
                if reg_addr == 3:  # Reservoir_Level spoofed to 0
                    val = int.from_bytes(payload[2:4], "big")
                    with stats_lock:
                        coil7_ts = seq_tracker[src_ip].get("last_coil7_ts", 0)
                    if now - coil7_ts < 2.0 and val < 10:
                        detail = (f"Tank overflow sequence: Reservoir_Inlet ON then "
                                  f"Reservoir_Level→{val} within 2s")
                        return (rule["action"], rule["id"], rule["name"],
                                detail, rule["severity"])

        # ── Rate-of-Change: Slow Drift Detection ─────────────────────────
        elif rtype == "rate_of_change":
            reg_addr   = rule.get("register", 0)
            max_delta  = rule.get("max_delta", 60)
            window     = rule.get("window_seconds", 20)

            if fc == FC_WRITE_SINGLE_REG and len(payload) >= 4:
                pkt_reg = int.from_bytes(payload[0:2], "big")
                pkt_val = int.from_bytes(payload[2:4], "big")
                if pkt_reg == reg_addr:
                    with stats_lock:
                        if reg_addr not in roc_tracker:
                            roc_tracker[reg_addr] = collections.deque()
                        dq = roc_tracker[reg_addr]
                        dq.append((now, pkt_val))
                        # Purge old entries outside window
                        while dq and now - dq[0][0] > window:
                            dq.popleft()
                        if len(dq) >= 2:
                            oldest_val = dq[0][1]
                            cumulative_delta = abs(pkt_val - oldest_val)
                            if cumulative_delta > max_delta:
                                detail = (f"Slow drift detected: HR{reg_addr} changed "
                                          f"{cumulative_delta} units in {window}s "
                                          f"(max allowed {max_delta})")
                                return (rule["action"], rule["id"], rule["name"],
                                        detail, rule["severity"])

    return ("ALLOW", "", "", "", "")

# ── Proxy Connection Handler ───────────────────────────────────────────────────
def handle_client(client_sock: socket.socket, src_ip: str):
    """Handle one client connection — proxy allowed traffic to PLC."""
    plc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        plc_sock.connect((PLC_HOST, PLC_PORT))
        plc_sock.settimeout(5.0)
        client_sock.settimeout(5.0)
    except Exception as e:
        log.error(f"Cannot reach PLC: {e}")
        client_sock.close()
        return

    with stats_lock:
        stats.unique_clients.add(src_ip)

    try:
        while True:
            try:
                data = client_sock.recv(512)
            except socket.timeout:
                break
            if not data:
                break

            pkt = parse_modbus(data)
            if not pkt:
                # Malformed — drop silently
                with stats_lock:
                    stats.packets_seen += 1
                    stats.packets_blocked += 1
                break

            with stats_lock:
                stats.packets_seen += 1

            verdict, rule_id, rule_name, detail, severity = evaluate_rules(pkt, src_ip)
            mitre_hit = next((r["mitre"] for r in RULES if r["id"] == rule_id), "")

            if verdict == "ALLOW":
                with stats_lock:
                    stats.packets_allowed += 1
                # Forward to PLC and relay response
                try:
                    plc_sock.sendall(data)
                    response = plc_sock.recv(512)
                    client_sock.sendall(response)
                    if _CAPTURE:
                        _cap.record(data, src_ip, 0, "REQUEST", "ALLOW", rule_id, rule_name, mitre_hit)
                        _cap.record(response, src_ip, 0, "RESPONSE", "ALLOW", "", "", "")
                except Exception:
                    break

            elif verdict == "ALERT":
                with stats_lock:
                    stats.packets_alerted += 1
                emit_event("ALERT", rule_id, rule_name, src_ip,
                           pkt["fc"], detail, severity, mitre_hit)
                # Still forward — alert-only rule
                try:
                    plc_sock.sendall(data)
                    response = plc_sock.recv(512)
                    client_sock.sendall(response)
                    if _CAPTURE:
                        _cap.record(data, src_ip, 0, "REQUEST", "ALERT", rule_id, rule_name, mitre_hit)
                        _cap.record(response, src_ip, 0, "RESPONSE", "ALLOW", "", "", "")
                except Exception:
                    break

            else:  # BLOCK or BAN
                with stats_lock:
                    stats.packets_blocked += 1
                emit_event("BLOCK", rule_id, rule_name, src_ip,
                           pkt["fc"], detail, severity, mitre_hit)
                if _CAPTURE:
                    _cap.record(data, src_ip, 0, "REQUEST", "BLOCK", rule_id, rule_name, mitre_hit)
                # Send Modbus exception response — attacker gets feedback but PLC is untouched
                try:
                    client_sock.sendall(build_exception_response(pkt, exception_code=0x01))
                except Exception:
                    pass

    finally:
        client_sock.close()
        plc_sock.close()

# ── Server ────────────────────────────────────────────────────────────────────
def run_firewall():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(20)
    log.info(f"Modbus Firewall listening on port {LISTEN_PORT} → forwarding to {PLC_HOST}:{PLC_PORT}")
    log.info(f"Loaded {len(RULES)} rules (IEC 62443-3-3 SL2 profile)")
    while True:
        try:
            conn, addr = srv.accept()
            src_ip = addr[0]
            t = threading.Thread(target=handle_client, args=(conn, src_ip), daemon=True)
            t.start()
        except Exception as e:
            log.error(f"Accept error: {e}")

# ── Status API (for dashboard) ────────────────────────────────────────────────
def get_stats_json() -> dict:
    with stats_lock:
        uptime = int(time.time() - stats.start_time)
        return {
            "uptime_seconds": uptime,
            "packets_seen":    stats.packets_seen,
            "packets_allowed": stats.packets_allowed,
            "packets_blocked": stats.packets_blocked,
            "packets_alerted": stats.packets_alerted,
            "block_rate_pct":  round(100 * stats.packets_blocked / max(1, stats.packets_seen), 1),
            "unique_clients":  list(stats.unique_clients),
            "banned_ips":      {ip: int(t - time.time()) for ip, t in stats.banned_ips.items()
                                if t > time.time()},
            "rule_hits":       dict(stats.rule_hits),
            "rules":           [{"id": r["id"], "name": r["name"],
                                  "severity": r["severity"], "action": r["action"],
                                  "mitre": r.get("mitre",""),
                                  "description": r["description"]} for r in RULES],
            "recent_events":   event_log[-30:],
        }

# ── Entry point ───────────────────────────────────────────────────────────────
def run_stats_http(port: int = 5503):
    """Tiny HTTP server that exposes get_stats_json() on port 5503.
    This lets server.py (a separate process) read live rule_hits counts."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import json as _json

    class StatsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = _json.dumps(get_stats_json()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass  # suppress HTTP access logs

    srv = HTTPServer(("127.0.0.1", port), StatsHandler)
    log.info(f"Stats HTTP server on 127.0.0.1:{port}")
    srv.serve_forever()

if __name__ == "__main__":
    import sys
    if "--status" in sys.argv:
        # Print current stats as JSON (for external polling)
        print(json.dumps(get_stats_json(), indent=2))
    else:
        # Start stats HTTP server in background thread
        t_stats = threading.Thread(target=run_stats_http, daemon=True)
        t_stats.start()
        run_firewall()