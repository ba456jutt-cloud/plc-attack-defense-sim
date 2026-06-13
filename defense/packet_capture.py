#!/usr/bin/env python3
"""
packet_capture.py — Modbus TCP Packet Capture & Deep Inspection Engine
=======================================================================
CPSS End-Semester Project — Network Traffic Panel

Hooks into the firewall's handle_client() pipeline and records every
Modbus TCP packet with full decode: MBAP header, function code, register
address, value, raw hex, and verdict (ALLOW / BLOCK / ALERT).

Also runs as a standalone passive sniffer on port 502 if needed.

Decoded fields per packet:
  - Timestamp (ms precision)
  - Source IP + port
  - Direction: REQUEST (client→PLC) or RESPONSE (PLC→client)
  - Transaction ID, Unit ID
  - Function code (name + number)
  - Register/coil address
  - Value(s) written or quantity read
  - Raw hex dump (formatted)
  - Verdict from firewall rule engine
  - Rule ID that matched (if any)
  - MITRE technique (if blocked/alerted)
  - Payload size in bytes

Statistics tracked:
  - Packets per second (rolling 5s window)
  - FC distribution (pie data)
  - Per-IP packet counts
  - BLOCK/ALLOW/ALERT counts
  - Session table (src_ip → first_seen, last_seen, packet_count)
"""

import time, threading, collections
from datetime import datetime
from typing import Optional

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_PACKETS = 1000   # ring buffer size
MAX_SESSIONS = 50

FC_NAMES = {
    0x01: "READ_COILS",
    0x02: "READ_DISCRETE_INPUTS",
    0x03: "READ_HOLDING_REGISTERS",
    0x04: "READ_INPUT_REGISTERS",
    0x05: "WRITE_SINGLE_COIL",
    0x06: "WRITE_SINGLE_REGISTER",
    0x0F: "WRITE_MULTIPLE_COILS",
    0x10: "WRITE_MULTIPLE_REGISTERS",
    0x11: "REPORT_SLAVE_ID",
    0x17: "READ_WRITE_MULTIPLE_REGISTERS",
}

FC_CATEGORY = {
    0x01: "read",  0x02: "read",  0x03: "read",  0x04: "read",
    0x05: "write", 0x06: "write", 0x0F: "write", 0x10: "write",
}

REG_NAMES  = ["Chlorine_Dose", "Coagulant_Dose", "Distribution_Speed", "Reservoir_Level_Pct"]
COIL_NAMES = [
    "Intake_Pump","Intake_Valve","Chlorine_Pump","Coagulant_Pump",
    "Dosing_Enable","Filter_Valve","UV_System","Reservoir_Inlet",
    "Reservoir_Outlet","Distribution_Pump","Alarm_LED","System_Enable"
]

# ── Shared state ───────────────────────────────────────────────────────────────
_lock          = threading.Lock()
_packets       = collections.deque(maxlen=MAX_PACKETS)
_sessions      = {}          # src_ip → session dict
_rate_buf      = collections.deque()  # timestamps for pps calculation
_seq           = 0           # packet sequence number

_stats = {
    "total":   0,
    "allowed": 0,
    "blocked": 0,
    "alerted": 0,
    "bytes":   0,
    "fc_dist": collections.defaultdict(int),
    "ip_dist": collections.defaultdict(int),
    "start_ts": time.time(),
}

# ── Hex dump formatter ────────────────────────────────────────────────────────
def _hex_dump(data: bytes, width: int = 16) -> str:
    """Format bytes as '00 01 02 … | ASCII' rows."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)

# ── Modbus deep decode ─────────────────────────────────────────────────────────
def decode_modbus(data: bytes, direction: str) -> dict:
    """
    Full Modbus TCP decode.
    Returns a rich dict describing the packet contents.
    """
    result = {
        "direction": direction,
        "raw_hex":   data.hex(" ").upper(),
        "hex_dump":  _hex_dump(data),
        "size":      len(data),
        "fc":        None,
        "fc_name":   "UNKNOWN",
        "fc_cat":    "unknown",
        "txn_id":    None,
        "unit_id":   None,
        "addr":      None,
        "addr_name": None,
        "value":     None,
        "quantity":  None,
        "values":    [],
        "summary":   "",
        "mbap": {},
    }

    if len(data) < 8:
        result["summary"] = f"[MALFORMED] only {len(data)} bytes"
        return result

    try:
        txn_id  = int.from_bytes(data[0:2], "big")
        proto   = int.from_bytes(data[2:4], "big")
        length  = int.from_bytes(data[4:6], "big")
        unit_id = data[6]
        fc      = data[7]
        payload = data[8:]

        result["txn_id"]  = txn_id
        result["unit_id"] = unit_id
        result["fc"]      = fc
        result["fc_name"] = FC_NAMES.get(fc, f"FC_0x{fc:02X}")
        result["fc_cat"]  = FC_CATEGORY.get(fc, "other")
        result["mbap"]    = {
            "transaction_id": txn_id,
            "protocol_id":    proto,
            "length":         length,
            "unit_id":        unit_id,
        }

        # ── Decode by FC ──────────────────────────────────────────────────
        if fc in (0x01, 0x02, 0x03, 0x04) and len(payload) >= 4:
            # Read request: start_addr, quantity
            addr = int.from_bytes(payload[0:2], "big")
            qty  = int.from_bytes(payload[2:4], "big")
            result["addr"]     = addr
            result["quantity"] = qty
            tag = _resolve_name(fc, addr)
            result["addr_name"] = tag
            result["summary"] = f"{result['fc_name']} addr={addr}({tag}) qty={qty}"

        elif fc == 0x05 and len(payload) >= 4:
            # Write single coil
            addr = int.from_bytes(payload[0:2], "big")
            val  = int.from_bytes(payload[2:4], "big")
            on   = val == 0xFF00
            name = COIL_NAMES[addr] if addr < len(COIL_NAMES) else f"coil_{addr}"
            result["addr"]      = addr
            result["addr_name"] = name
            result["value"]     = 1 if on else 0
            result["summary"]   = f"WRITE_COIL {addr}({name}) → {'ON' if on else 'OFF'}"

        elif fc == 0x06 and len(payload) >= 4:
            # Write single register
            addr = int.from_bytes(payload[0:2], "big")
            val  = int.from_bytes(payload[2:4], "big")
            name = REG_NAMES[addr] if addr < len(REG_NAMES) else f"HR{addr}"
            result["addr"]      = addr
            result["addr_name"] = name
            result["value"]     = val
            result["summary"]   = f"WRITE_REG {addr}({name}) → {val}"

        elif fc == 0x0F and len(payload) >= 5:
            # Write multiple coils
            addr  = int.from_bytes(payload[0:2], "big")
            qty   = int.from_bytes(payload[2:4], "big")
            bcnt  = payload[4]
            cbytes = payload[5:5+bcnt]
            vals  = []
            for i in range(qty):
                byte_i = i // 8
                bit_i  = i % 8
                if byte_i < len(cbytes):
                    vals.append(bool(cbytes[byte_i] & (1 << bit_i)))
            result["addr"]     = addr
            result["quantity"] = qty
            result["values"]   = [int(v) for v in vals]
            result["summary"]  = (f"WRITE_COILS addr={addr} qty={qty} "
                                   f"vals=[{','.join(str(int(v)) for v in vals[:6])}"
                                   f"{'…' if len(vals)>6 else ''}]")

        elif fc == 0x10 and len(payload) >= 5:
            # Write multiple registers
            addr  = int.from_bytes(payload[0:2], "big")
            qty   = int.from_bytes(payload[2:4], "big")
            bcnt  = payload[4]
            vals  = []
            for i in range(qty):
                off = 5 + i*2
                if off+2 <= len(payload):
                    vals.append(int.from_bytes(payload[off:off+2], "big"))
            result["addr"]     = addr
            result["quantity"] = qty
            result["values"]   = vals
            result["summary"]  = f"WRITE_REGS addr={addr} qty={qty} vals={vals}"

        elif fc & 0x80:
            # Exception response
            exc = payload[0] if payload else 0xFF
            exc_msgs = {1:"Illegal Function",2:"Illegal Address",3:"Illegal Value",4:"Slave Failure"}
            result["summary"] = f"EXCEPTION FC=0x{fc&0x7F:02X} code={exc}({exc_msgs.get(exc,'?')})"
            result["fc_cat"]  = "exception"

        else:
            result["summary"] = f"{result['fc_name']} payload={data[8:].hex()}"

    except Exception as e:
        result["summary"] = f"[DECODE ERROR] {e}"

    return result

def _resolve_name(fc: int, addr: int) -> str:
    """Return human name for a register/coil address."""
    if fc in (0x01, 0x02, 0x05, 0x0F):
        return COIL_NAMES[addr] if addr < len(COIL_NAMES) else f"coil_{addr}"
    elif fc in (0x03, 0x04, 0x06, 0x10):
        return REG_NAMES[addr] if addr < len(REG_NAMES) else f"HR{addr}"
    return f"addr_{addr}"

# ── Public API: record a packet ───────────────────────────────────────────────
def record(data: bytes, src_ip: str, src_port: int,
           direction: str = "REQUEST",
           verdict: str = "ALLOW",
           rule_id: str = "",
           rule_name: str = "",
           mitre: str = ""):
    """
    Called by the firewall for every packet seen.
    direction: "REQUEST" | "RESPONSE"
    verdict:   "ALLOW" | "BLOCK" | "ALERT"
    """
    global _seq
    now = time.time()
    ts  = datetime.fromtimestamp(now).strftime("%H:%M:%S.%f")[:-3]

    decoded = decode_modbus(data, direction)

    with _lock:
        _seq += 1
        seq = _seq

        pkt = {
            "seq":       seq,
            "ts":        ts,
            "ts_epoch":  now,
            "src_ip":    src_ip,
            "src_port":  src_port,
            "direction": direction,
            "verdict":   verdict,
            "rule_id":   rule_id,
            "rule_name": rule_name,
            "mitre":     mitre,
            **decoded,
        }
        _packets.append(pkt)
        _rate_buf.append(now)

        # Stats
        _stats["total"]  += 1
        _stats["bytes"]  += len(data)
        _stats["ip_dist"][src_ip] += 1
        if decoded["fc"] is not None:
            _stats["fc_dist"][decoded["fc_name"]] += 1
        if verdict == "ALLOW":   _stats["allowed"] += 1
        elif verdict == "BLOCK": _stats["blocked"] += 1
        elif verdict == "ALERT": _stats["alerted"] += 1

        # Sessions
        if src_ip not in _sessions:
            _sessions[src_ip] = {
                "src_ip":     src_ip,
                "first_seen": ts,
                "last_seen":  ts,
                "packets":    0,
                "blocked":    0,
                "bytes":      0,
                "fcs":        set(),
            }
        s = _sessions[src_ip]
        s["last_seen"] = ts
        s["packets"]  += 1
        s["bytes"]    += len(data)
        if verdict == "BLOCK": s["blocked"] += 1
        if decoded["fc"]:      s["fcs"].add(decoded["fc_name"])

        # Prune rate buffer (keep 5s)
        while _rate_buf and _rate_buf[0] < now - 5:
            _rate_buf.popleft()

    return pkt

# ── Public API: queries ───────────────────────────────────────────────────────
def get_packets(limit: int = 100, verdict_filter: str = None,
                fc_filter: str = None, ip_filter: str = None) -> list:
    with _lock:
        pkts = list(_packets)

    # Apply filters
    if verdict_filter:
        pkts = [p for p in pkts if p["verdict"] == verdict_filter]
    if fc_filter:
        pkts = [p for p in pkts if p["fc_name"] == fc_filter]
    if ip_filter:
        pkts = [p for p in pkts if p["src_ip"] == ip_filter]

    # Return most recent first
    return list(reversed(pkts))[:limit]

def get_packet_by_seq(seq: int) -> Optional[dict]:
    with _lock:
        for p in _packets:
            if p["seq"] == seq:
                return p
    return None

def get_stats() -> dict:
    with _lock:
        now  = time.time()
        # pps over last 5 seconds
        recent = sum(1 for t in _rate_buf if t > now - 5)
        pps    = round(recent / 5, 1)

        # pps history — last 60 readings (1/s buckets)
        sessions_out = []
        for s in list(_sessions.values())[:MAX_SESSIONS]:
            sc = dict(s)
            sc["fcs"] = list(sc["fcs"])
            sessions_out.append(sc)

        return {
            "total":        _stats["total"],
            "allowed":      _stats["allowed"],
            "blocked":      _stats["blocked"],
            "alerted":      _stats["alerted"],
            "bytes":        _stats["bytes"],
            "pps":          pps,
            "uptime":       int(now - _stats["start_ts"]),
            "fc_dist":      dict(_stats["fc_dist"]),
            "ip_dist":      dict(_stats["ip_dist"]),
            "sessions":     sessions_out,
            "buffer_used":  len(_packets),
            "buffer_max":   MAX_PACKETS,
        }

def clear():
    with _lock:
        _packets.clear()
        _sessions.clear()
        _rate_buf.clear()
        _stats["total"] = _stats["allowed"] = _stats["blocked"] = 0
        _stats["alerted"] = _stats["bytes"] = 0
        _stats["fc_dist"].clear()
        _stats["ip_dist"].clear()
        _stats["start_ts"] = time.time()