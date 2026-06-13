# Defense & Mitigation Strategies
### CPSS Project — Water Treatment Plant ICS Security

---

## Why Defense Matters in This Project

Every attack demonstrated in this project succeeds for **one root cause**: Modbus TCP has no authentication and no encryption. Any host that can reach port 502 can read or write any register. Understanding how to fix this is as important as understanding how to exploit it.

This document maps each attack to its countermeasure and explains what real water utilities should deploy.

---

## Vulnerability Root Cause Analysis

| Root Cause | Description | Attacks It Enables |
|------------|-------------|-------------------|
| No authentication on Modbus TCP | Any client can connect and write | All attacks |
| No encryption | Traffic is plaintext — readable on network | Passive recon (Scenario 4) |
| No write access control | All coils and registers writable by anyone | Attacks 1–7, Scenarios 1–6 |
| No command logging | PLC does not log who sent which command | Alarm suppression goes undetected |
| Safety interlocks in software only | Can be bypassed by overriding coil values | Attacks 2, 3, 6 |
| Flat network — attacker reaches port 502 directly | No segmentation between IT and OT | All attacks |

---

## Defense Layer 1: Network Segmentation (Most Important)

**Problem:** The attack tool reaches port 502 directly from the same network.

**Fix:** Industrial Control Systems must be on an **isolated OT (Operational Technology) network**, completely separated from IT networks and the internet. Access should only be possible through a **DMZ with a data diode or firewall**.

```
[Internet] ──► [IT Network] ──► [Firewall/DMZ] ──► [OT Network] ──► [PLC Port 502]
                                      ↑
                          Only authorized jump server
                          can reach OT network
```

**Implementation:**
- VLAN separation between IT and OT
- Unidirectional security gateway (data diode) — data flows out of OT for monitoring, but commands cannot flow in without explicit authorization
- Block all inbound connections to port 502 from outside OT network
- Whitelist only specific engineering workstation IPs to reach the PLC

**Effectiveness against demonstrated attacks:** Prevents ALL remote attacks. Physical access to OT network would still be required.

---

## Defense Layer 2: Modbus TCP Firewall / Deep Packet Inspection

**Problem:** Even within the OT network, any authorized device can send any Modbus command.

**Fix:** Deploy an **industrial protocol-aware firewall** (e.g., Claroty, Dragos, Nozomi Networks) that performs Deep Packet Inspection (DPI) on Modbus traffic and enforces:
- Which **Function Codes** are allowed (e.g., block FC05/FC15 write commands entirely from monitoring stations)
- Which **register ranges** each client can read/write
- **Rate limiting** — flag clients that send hundreds of write packets per second (flood attack detection)
- **Value range enforcement** — block any write to HR0 (Chlorine_Dose) with value > 600

**Example rule set:**
```
ALLOW  FC01 (Read Coils)               FROM any_OT_host     TO PLC:502
ALLOW  FC03 (Read Holding Registers)   FROM any_OT_host     TO PLC:502
ALLOW  FC05 (Write Coil)               FROM eng_workstation  TO PLC:502
DENY   FC05 (Write Coil)               FROM any             TO PLC:502  [default block]
DENY   FC06 HR0 value > 600            FROM any             TO PLC:502  [overdose block]
ALERT  FC05 rate > 50/sec              FROM any             TO PLC:502  [flood detection]
```

**Effectiveness against demonstrated attacks:**

| Attack | Blocked? |
|--------|----------|
| Force-ON / Force-OFF Flood | ✅ Rate limit + FC05 source restriction |
| Chemical Overdose | ✅ Value range rule on HR0 |
| Tank Overflow | ✅ FC05 source restriction |
| Pump Cavitation | ✅ FC05 source restriction |
| System Blackout | ✅ FC15 rate limit |
| Alarm Suppression | ✅ FC05 source restriction |
| Rapid Scan Flood | ✅ Rate limiting |
| Passive Recon | ❌ Read-only — cannot block without disabling monitoring |

---

## Defense Layer 3: Modbus Authentication (Modbus Secure / TLS)

**Problem:** Standard Modbus TCP has no authentication at the protocol level.

**Fix:** **Modbus Security (Modbus/TCP Security)** — an extension published by the Modbus Organization that wraps Modbus TCP in TLS 1.2/1.3 with client certificate authentication. Only clients with a valid certificate can connect.

Alternatively, use **OPC UA** instead of Modbus for new deployments — OPC UA has authentication, encryption, and role-based access control built in from the ground up.

**Implementation steps for OpenPLC:**
1. Enable TLS in OpenPLC Runtime configuration
2. Generate CA certificate + client certificates for each authorized device
3. Configure firewall to reject non-TLS connections on port 502
4. Rotate certificates periodically

**Effectiveness:** Eliminates all unauthenticated access. An attacker without a valid certificate cannot connect at all — attacks 1–7 and all scenarios become impossible without first compromising a certificate.

---

## Defense Layer 4: Hardware Safety Interlocks (Defense in Depth)

**Problem:** The PLC's software safety interlocks (chlorine overdose detection, level sensor cutoffs) can be bypassed by overwriting the coil values that implement them.

**Fix:** Critical safety thresholds must be enforced in **hardware**, not software:
- **Hardware High-Level Switch:** A physical float switch that mechanically closes the reservoir inlet valve regardless of what the PLC outputs. Cannot be overridden by a Modbus write.
- **Hardware Chemical Metering Pump:** A mechanical flow restrictor that physically limits maximum chlorine flow rate, independent of the PLC dosing register value.
- **Safety Instrumented System (SIS):** A separate, independent controller (e.g., Triconex) that monitors sensor values and can physically cut power to pumps if limits are exceeded. Isolated from the main PLC network.

**Effectiveness against Scenario 1 (Silent Overdose):** Even if attacker writes HR0 = 1000 and suppresses the alarm LED, a hardware flow restrictor prevents actual overdosing. The attack succeeds on the PLC level but fails in the physical world.

---

## Defense Layer 5: Anomaly Detection & Monitoring

**Problem:** The Slow Degradation attack (Scenario 6) and Alarm Suppression (Attack 6) are specifically designed to avoid triggering alerts.

**Fix:** Deploy an **ICS-aware intrusion detection system** that baselines normal PLC behavior and alerts on deviations:
- **Behavioral baseline:** Record normal coil state sequences and register value ranges over 2–4 weeks
- **Statistical anomaly detection:** Alert if chlorine dose drifts more than 50 units over 10 minutes without an operator command
- **Sequence integrity checking:** Alert if Alarm_LED goes OFF while Chlorine_Overdose internal variable is TRUE (alarm suppression signature)
- **Command source logging:** Log every Modbus write command with source IP, timestamp, function code, register address, and value

**Tools:** Claroty, Dragos Platform, Nozomi Guardian, Zeek with ICS plugins, or a custom SIEM with Modbus log parsing.

**Effectiveness against Scenario 6 (Slow Degradation):** Anomaly detection catches the gradual chlorine drift that would go unnoticed by a human operator watching a panel.

---

## Defense Layer 6: Principle of Least Privilege

**Problem:** Every host on the OT network has full read/write access to every register.

**Fix:**
- Engineering workstations: read/write access (FC01, FC03, FC05, FC06, FC15, FC16)
- SCADA/HMI displays: read-only access (FC01, FC03 only)
- Historian servers: read-only access to specific registers only
- No device should have write access to safety-critical registers (Level sensors, Alarm coils) from the network — these should only be settable by physical field devices

---

## Summary: Defense vs. Attack Matrix

| Defense Measure | Flood Attacks | Overdose | Overflow | Cavitation | Blackout | Alarm Suppression | Slow Drift | Recon |
|----------------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Network segmentation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Modbus firewall + DPI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| Modbus/TLS authentication | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hardware safety interlocks | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| Anomaly detection / IDS | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ |
| Least privilege access | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ |

✅ = Fully prevented | ⚠️ = Partially mitigated | ❌ = Not addressed by this measure

---

## Real-World Standards & Frameworks

| Standard | Relevance |
|----------|-----------|
| IEC 62443 | Industrial cybersecurity standard — defines security levels for ICS |
| NIST SP 800-82 | Guide to ICS security (US government) |
| NERC CIP | Critical infrastructure protection for power grid |
| CISA ICS-CERT Advisories | Ongoing vulnerability disclosures for ICS products |
| ISA/IEC 62443-3-3 | System security requirements and security levels |

---

## Key Takeaway

No single defense is sufficient. The Oldsmar water plant (2021) was attacked because it had no network segmentation and no Modbus authentication. The Ukraine power grid (2015) was attacked because SCADA commands required no authentication. Stuxnet (2010) succeeded because hardware safety systems were software-controlled and shared the same network as the attack vector.

**Defense in depth** — multiple independent layers — is the only approach that holds when any one layer fails.
---

## Defense Layer 7: SCADA Historian as Forensic Evidence

### Why Historian Data Matters

The Cover Tracks stage (Stage 7) of the APT simulation restores PLC registers
to plausible nominal values. A human operator checking the current HMI display
would see nothing wrong. But **this is not the same as erasing evidence.**

Real water treatment plants and industrial facilities use **SCADA historians** —
time-series databases that record every register change, every coil state
transition, and every setpoint modification with high-resolution timestamps
(typically millisecond precision). Historians run on a separate server, with
separate credentials, and are generally append-only by design.

Restoring Modbus register values to baseline does **not** delete historian entries.
Every value written during the attack is already persisted. A forensic analyst
with historian access can reconstruct the complete attack timeline after the fact.

### What a Historian Captures During This Attack

| Time (approx) | Historian Record |
|---------------|-----------------|
| Stage 6A      | Alarm_LED: repeated WRITE=FALSE at 20 Hz for ~8 seconds |
| Stage 6B      | Chlorine_Dose: stepped 300 → 750 in 50-unit increments, 2s apart |
| Stage 6C      | Chlorine_Dose: held at 1000 for ~20 continuous seconds |
| Stage 6D      | Reservoir_Outlet: WRITE=CLOSED while Distribution_Pump=ON |
| Stage 7       | Chlorine_Dose: sudden single write to exactly 200 — the "clean" value itself is anomalous in the historian trace |

The Stage 7 write of `Chlorine_Dose = 200` is particularly telling. In normal
operations, chlorine dose changes gradually via operator setpoint adjustments.
A sudden jump from 1000 to exactly 200 in one Modbus packet — immediately after
an abnormal period — is itself an attack signature in the historian record.

### What a Real Attacker Must Also Do

To properly cover their tracks, an attacker with historian awareness would need to:

1. **Identify the historian server** — typically a Windows Server running OSIsoft
   PI, Wonderware InTouch, or Ignition Historian, on a separate OT host.
2. **Gain access to the historian** — usually requires separate credentials from
   the PLC. This is a second compromise step, not covered in this simulation.
3. **Delete or modify the time-series records** for the attack window — this is
   non-trivial; most historians have audit trails on their own deletion events.
4. **Account for out-of-band captures** — network TAPs, Dragos/Claroty sensors,
   or packet captures running independently of the historian may have recorded
   the raw Modbus TCP stream regardless of what the historian says.
5. **Account for remote backups** — enterprise historians typically replicate
   to offsite or cloud storage. Deleting local records may not delete replicas.

### Simulation Gap

**This simulation has no historian.** The gap is intentional scope limitation —
modeling a historian server would require a second process, a time-series
database, and a query interface that would add significant complexity to the demo.

The gap is significant: it means Stage 7 "Cover Tracks" is less complete than
its real-world equivalent would need to be. A real forensic investigation of
this attack would recover the complete timeline from historian records even
if the attacker perfectly restored all PLC register values.

### Recommended Tools for Historian-Based ICS Forensics

| Tool | Use |
|------|-----|
| OSIsoft PI | Industry-standard historian; logs to SQL-queryable event frames |
| Dragos Platform | Passive network monitoring; captures Modbus traffic independently of PLC |
| Claroty CTD | Builds behavioral baselines from historian + network traffic |
| Zeek + ICSNPP | Open-source packet capture with ICS protocol dissectors |
| SANS ICS515 methodology | Structured ICS incident response using historian evidence |

### Impact on the Defense Matrix

Adding historian monitoring to the defense matrix from Defense Layer 5:

| Attack | Detected by historian? |
|--------|----------------------|
| Chemical overdose (Stage 6C) | ✅ Timestamp + value spike |
| Alarm suppression (Stage 6A) | ✅ Coil OFF at abnormal rate |
| Slow drift (Stage 6B) | ✅ Stepped increments visible in trend |
| Cavitation setup (Stage 6D) | ✅ Conflicting coil states timestamped |
| Cover tracks attempt (Stage 7) | ✅ Anomalous single-write to clean value |

A historian-equipped plant would detect and reconstruct this entire attack
from its records even if the attacker's only mistake was failing to erase them.