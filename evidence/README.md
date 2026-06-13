# evidence/README.md
# CPSS Project — Network Evidence Directory

## Contents

This directory contains real network-level forensic evidence of the attacks
demonstrated in this project. Unlike the application-layer logs in
`defense/packet_capture.py`, these are actual `.pcap` files captured at the
OS network stack and verifiable with standard forensic tools.

```
evidence/
├── README.md                    ← this file
├── capture_attack.py            ← capture script (run with sudo)
├── attack_capture_<ts>.pcap     ← real pcap (generated at runtime)
└── attack_annotations.json      ← packet index → attack phase map
```

---

## How to Generate the PCAP

```bash
# Terminal 1: start OpenPLC Runtime
cd OpenPLC_v3/webserver && python3 webserver.py

# Terminal 2: run capture (requires root for raw socket access)
sudo python3 evidence/capture_attack.py

# macOS: use lo0 instead of lo
sudo python3 evidence/capture_attack.py --iface lo0

# Dry run: capture traffic without writing attack values to PLC
sudo python3 evidence/capture_attack.py --dry-run
```

The script runs a 6-phase scripted attack sequence while simultaneously
capturing all TCP port 502 traffic on the loopback interface. On exit it
saves a `.pcap` file and an annotation JSON that maps packet numbers to
attack phases.

---

## Opening in Wireshark

1. File → Open → select `attack_capture_<timestamp>.pcap`
2. Apply display filter: `mbtcp` (Wireshark's native Modbus/TCP dissector)
3. Wireshark automatically decodes:
   - MBAP header (Transaction ID, Protocol ID, Length, Unit ID)
   - Function code (FC01 Read Coils, FC05 Write Single Coil, FC06 Write Single Register, etc.)
   - Register address and value
4. Cross-reference the `attack_annotations.json` file to find which packet
   number corresponds to each attack phase

### What Each Phase Looks Like in Wireshark

| Phase | Filter | What to Look For |
|---|---|---|
| P1_RECON | `mbtcp.func_code == 3` | FC03 Read Holding Registers, qty=4 |
| P2_OVERDOSE | `mbtcp.func_code == 6` | FC06, ref=0x0000, value=0x0352 (850 dec) |
| P3_ALARM_SUPPRESS | `mbtcp.func_code == 5` | FC05, ref=0x000A, value=0x0000 (OFF) |
| P4_REG_FLOOD | `mbtcp.func_code == 6` | Burst of FC06 frames within 50–100ms |
| P5_BLACKOUT | `mbtcp.func_code == 5` | FC05, ref=0x000B, value=0x0000 (System_Enable OFF) |
| P6_RESTORE | `mbtcp.func_code == 6` | FC06, ref=0x0000, value=0x00C8 (200 dec) |

### Useful Wireshark Filters

```
mbtcp                                   # all Modbus/TCP frames
mbtcp.func_code == 6                    # write single register only (attacks)
mbtcp.func_code == 5                    # write single coil only
mbtcp.reference_num == 0               # register 0 = Chlorine_Dose
tcp.flags.reset == 1                    # TCP resets (connection issues)
frame.number >= 12 && frame.number <= 25  # specific frame range
```

---

## Analysis with Zeek

```bash
# Zeek natively parses Modbus in modbus.log
zeek -r attack_capture_<timestamp>.pcap

# Key fields in modbus.log:
#   ts, uid, id.orig_h, id.resp_h, func, exception, track
cat modbus.log | zeek-cut ts func | sort | uniq -c | sort -rn
```

---

## Analysis with Snort / Suricata ICS Rules

The Emerging Threats ICS ruleset includes rules for anomalous Modbus FC ranges.
Example rules triggered by this capture:

```
# ET ICS MODBUS TCP - Unit ID 0 (often used by scanners)
alert tcp any any -> any 502 (msg:"ET ICS MODBUS TCP ..."; ...)

# Custom rule for write to register 0 (Chlorine_Dose) above safe value
alert tcp any any -> any 502 (
  msg:"CPSS Chlorine_Dose overdose write";
  content:"|00 06 00 00|";  # FC06 addr=0 
  byte_test:2,>,800,8,big;  # value > 800
  sid:9000001; rev:1;
)
```

---

## Forensic Value vs. Application-Layer Logging

| Property | `packet_capture.py` (old) | `capture_attack.py` (this) |
|---|---|---|
| Capture layer | Application (inside proxy) | OS network stack |
| File format | JSON log | `.pcap` (libpcap) |
| Wireshark compatible | No | Yes |
| Zeek/Snort compatible | No | Yes |
| Timestamp source | `time.time()` | NIC hardware timestamp |
| Verifiable | No (log can be edited) | Yes (pcap checksum) |
| Attacker can clear | Yes (same process) | No (separate process) |
| Captures pre-proxy traffic | No | Yes |