# THREAT_MODEL.md
# CPSS Project — Water Treatment Plant PLC Attack Simulation

## 1. System Overview

The target is a simulated water treatment plant controlled by a PLC running IEC 61131-3 Structured Text on OpenPLC Runtime. The plant has five treatment stages: intake, chemical dosing, filtration, UV disinfection, and reservoir distribution. It is monitored via a Flask-based HMI dashboard and exposes a Modbus TCP interface on port 502.

The system models a small municipal water treatment facility serving a population of roughly 50,000 people, consistent with the scale of the Oldsmar, Florida attack (2021).

---

## 2. Assets and CIA Priorities

In ICS environments the priority order is reversed from typical IT:
**Availability > Integrity > Confidentiality**

A plant that is safely shut down is better than one distributing contaminated water. A plant distributing contaminated water is better than one whose operators do not know something is wrong (integrity failure).

| Asset | Description | CIA Priority |
|---|---|---|
| PLC Program (program.st) | The running IEC 61131-3 logic that controls all actuators | Integrity >> Availability |
| Modbus Interface (:502) | Unauthenticated TCP interface for register/coil read-write | Availability > Integrity |
| OpenPLC Web UI (:8080) | Web interface for program upload, compile, and runtime control | Integrity >> Availability |
| Auth Proxy (:5020) | HMAC-SHA1 challenge-response gate in front of Modbus | Availability > Integrity |
| HMI Dashboard (:5000) | Operator view of plant state; Flask SSE server | Availability = Integrity |
| Chlorine Dosing System | Physical pump + register HR0 (Chlorine_Dose) | Integrity >> Availability (wrong dose = harm) |
| Reservoir Level Sensor | Register HR3 (Reservoir_Level_Pct) | Integrity (spoofed level → overflow or empty) |
| Alarm System | Coil 10 (Alarm_LED) + internal Alarm_Active flag | Integrity (suppressed alarm hides attacks) |
| Historian / Event Log | apt_log_*.json files, proxy_traffic.log | Integrity >> Confidentiality |

---

## 3. Trust Boundaries

```
[INTERNET / ATTACKER]
        |
        | TCP
        v
+------------------+     +---------------------+
| Auth Proxy :5020 |     | OpenPLC Web UI :8080 |  <-- NO auth on web UI by default
+------------------+     +---------------------+
        |                        |
        | authenticated          | HTTP (program upload / run)
        | Modbus TCP             |
        v                        v
+--------------------------------------------------+
|              OpenPLC Runtime Process             |
|  +--------------------------------------------+ |
|  |   PLC Program (program.st compiled .so)    | |  <-- TRUST BOUNDARY: once replaced,
|  |   Scan cycle: 20ms                         | |      no Modbus write can restore safety
|  +--------------------------------------------+ |
|  Modbus TCP listener :502 (NO authentication)   |  <-- EXPOSED, bypassable
+--------------------------------------------------+
        |
        | Physical actuation
        v
[ Pumps | Valves | Chlorine Pump | UV System | Reservoir ]

[HMI Dashboard :5000] reads from PLC via Modbus, shows operator view
```

Key boundary violations demonstrated in this project:

- Port 502 is inside the trust boundary but directly reachable from outside — the auth proxy is a parallel path, not an in-line gate.
- The OpenPLC web UI (:8080) has no IP restrictions and ships with default credentials (admin:openplc), placing it in the same trust zone as the attacker.
- The compiled PLC program (a `.so` shared library) runs as root on Linux — compromise of the web UI means OS-level code execution.

---

## 4. Adversary Model

We model three capability tiers. This project primarily demonstrates Tier 2.

### Tier 1 — Opportunistic / Script Kiddie
Capability: network access to port 502, basic Modbus tooling (mbtget, ModbusPal).
Goal: disruption, curiosity.
Techniques: raw FC06 single-register writes, coil flips, denial of service.
Covered by: attack_tool.py modes 1-5.

### Tier 2 — Targeted Insider / Knowledgeable Attacker
Capability: network access to both port 502 and port 8080, knowledge of ICS protocols, ability to craft IEC 61131-3 ST code.
Goal: safety system bypass, contamination, covert persistent damage.
Techniques: logic injection (our new attack), auth proxy bypass, APT kill chain.
Covered by: logic_injection.py, bypass_auth.py, apt_scenario.py.

### Tier 3 — Nation-State APT
Capability: supply chain access, insider recruitment, ability to modify firmware or replace hardware.
Techniques: SIS targeting (Triton/TRISIS pattern), historian manipulation, firmware rootkits.
Status: modeled in narrative only (apt_scenario.py Stage 0 and Stage 7 notes).

---

## 5. STRIDE Analysis

STRIDE applied per asset. Each cell states the threat and whether this project demonstrates it.

### 5.1 Modbus Interface (port 502)

| STRIDE | Threat | Demonstrated |
|---|---|---|
| Spoofing | Attacker sends Modbus frames with any unit ID, appearing as legitimate SCADA master | Yes — attack_tool.py sends frames with unit_id=1 (same as the real HMI) |
| Tampering | FC06/FC16 writes modify Chlorine_Dose, Reservoir_Level_Pct, coil states | Yes — core of all register-manipulation attacks |
| Repudiation | No Modbus audit log at the protocol level; attacker writes leave no signed trace | Yes — demonstrated by cover_tracks stage in apt_scenario.py |
| Information Disclosure | FC03/FC01 reads expose full plant state, process values, alarm status | Yes — recon stage reads all 12 coils and 4 registers |
| Denial of Service | Rapid coil writes (Intake_Pump OFF) starve the process, or flood port 502 | Yes — attack_tool.py mode "blackout" |
| Elevation of Privilege | FC06 writes can change System_Enable (coil 11) — operator-level control | Yes — apt_scenario.py Stage 6 |

### 5.2 OpenPLC Web UI (port 8080)

| STRIDE | Threat | Demonstrated |
|---|---|---|
| Spoofing | Default admin:openplc credentials allow any attacker to authenticate as admin | Yes — logic_injection.py Stage A |
| Tampering | /upload-program replaces the running PLC logic entirely | Yes — logic_injection.py Stage D (title-justifying attack) |
| Repudiation | Web UI login events are not forwarded to external syslog by default | Noted, not demonstrated |
| Information Disclosure | Dashboard exposes full program source, variable names, and runtime values | Yes — visible at /dashboard without additional auth post-login |
| Denial of Service | /stop-plc endpoint stops the PLC; /run-plc with invalid code bricks it | Yes — logic_injection.py Stage E side-effect if compile fails |
| Elevation of Privilege | Web UI runs OpenPLC as root; arbitrary .st upload = arbitrary code execution | Demonstrated conceptually — malicious .st contains only ST, not shell |

### 5.3 Auth Proxy (port 5020)

| STRIDE | Threat | Demonstrated |
|---|---|---|
| Spoofing | Attacker replays a captured valid HMAC token | Partially — bypass_auth.py reads proxy_traffic.log |
| Tampering | Post-auth TCP stream is plaintext Modbus; MITM can inject frames | Noted in bypass_auth.py comments, not fully demonstrated |
| Repudiation | Proxy logs hex but logs are on the same host the attacker may control | Yes — attacker can delete proxy_traffic.log |
| Information Disclosure | Traffic log written to cwd in plaintext; any process on the host can read it | Yes — bypass_auth.py reads it directly |
| Denial of Service | Proxy is single-threaded per connection; flooding port 5020 delays legitimate access | Not demonstrated |
| Elevation of Privilege | Bypass: port 502 is directly reachable, making the proxy irrelevant | Yes — bypass_auth.py Technique 1 |

### 5.4 PLC Program (program.st / compiled .so)

| STRIDE | Threat | Demonstrated |
|---|---|---|
| Spoofing | Malicious logic reports false sensor values to HMI (Reservoir_Level_Pct := 50) | Yes — logic_injection.py Malicious Rung 3 |
| Tampering | Logic is replaced entirely; safety interlocks removed | Yes — logic_injection.py core attack |
| Repudiation | HardClamped flags cleared at end of scan — historian records no clamp events | Yes — logic_injection.py Malicious Rung 4 |
| Information Disclosure | Compiled .so is world-readable on disk; disassembly reveals PLC internals | Not demonstrated |
| Denial of Service | Malicious logic can deadlock the scan cycle or force infinite loop | Not demonstrated |
| Elevation of Privilege | Replaced program runs with same OS privileges as OpenPLC process (root) | Yes — conceptually demonstrated |

---

## 6. Attack Tree

Primary goal: contaminate water supply without triggering operator response.

```
[ROOT] Contaminate water without operator detection
├── [A] Modbus register manipulation (Tier 1/2)
│   ├── [A1] Write Chlorine_Dose = 850 via FC06
│   │   └── BLOCKED by: BLOCK 0 clamp fires, Chlorine_HardClamped set, Alarm_LED ON
│   └── [A2] Suppress alarm after write (coil 10 := FALSE via FC05)
│       └── BLOCKED by: Alarm_Active is internal, not writable; LED resets next scan
│
├── [B] Logic injection via OpenPLC web UI (Tier 2) *** THIS PROJECT ***
│   ├── [B1] Authenticate with default credentials → SUCCESS (admin:openplc)
│   ├── [B2] Upload malicious program.st
│   │   ├── Rung 1: Alarm_LED := FALSE (suppresses alarm permanently)
│   │   ├── Rung 2: Chlorine_Pump := System_Ready (bypasses Dosing_Enable check)
│   │   ├── Rung 3: Reservoir_Level_Pct := 50 (hides real level)
│   │   └── Rung 4: HardClamped := FALSE (clears forensic evidence)
│   └── [B3] Trigger /run-plc → malicious logic active in <5s
│       └── DETECTION: web UI timestamp changes; file integrity monitor on .st
│
└── [C] Firmware/bootloader modification (Tier 3, out of scope)
    ├── [C1] Modify OpenPLC .so directly on disk
    └── [C2] Replace matiec compiler to produce malicious binary from clean source
```

Path B is the one this project demonstrates. Path A is what all the other attack tools do. Path C is modeled in narrative only (Tier 3 nation-state).

---

## 7. Probability and Impact (Likelihood × Impact Matrix)

Scale: Likelihood 1-5 (1=rare, 5=near-certain). Impact 1-5 (1=negligible, 5=catastrophic).
Risk Score = Likelihood × Impact.

| Attack | Likelihood | Impact | Risk Score | Notes |
|---|---|---|---|---|
| Modbus coil/register write (Tier 1) | 4 | 3 | 12 | High likelihood — port 502 open, no auth. Impact limited by BLOCK 0 clamps. |
| Logic injection via web UI (Tier 2) | 3 | 5 | 15 | Requires web UI access + credentials. Impact is total: all interlocks bypassed. |
| Auth proxy bypass (direct :502) | 5 | 3 | 15 | Trivially bypassed since :502 is always open. Impact same as Tier 1 attack. |
| Alarm suppression only | 3 | 4 | 12 | Doubles impact of any concurrent attack by removing operator awareness. |
| Historian tampering | 2 | 3 | 6 | Requires host-level access. Reduces forensic traceability. |
| APT full kill chain (all stages) | 2 | 5 | 10 | Nation-state level. Full chain has no automated defense. |

Highest-risk finding: Logic injection (score 15) and auth proxy bypass (score 15) tie at the top. Logic injection is higher consequence per incident because it persists across Modbus sessions and survives PLC power cycles (uploaded program is stored on disk).

---

## 8. Existing Mitigations and Residual Risk

| Mitigation | Implemented | Residual Risk |
|---|---|---|
| BLOCK 0 input clamps in program.st | Yes | Eliminated by logic injection — clamps live in the program being replaced |
| Modbus firewall (modbus_firewall.py) | Yes | Bypassed by direct :502 access; does not inspect web UI traffic |
| Auth proxy (auth_proxy.py) | Yes | Cosmetic — :502 exposed in parallel |
| CM-1 to CM-6 countermeasures | Yes | CM-3/CM-6 detect register anomalies but not logic replacement (no behavioral diff for first 20ms) |
| OpenPLC web UI password | Default only | admin:openplc is the published default; not changed in this setup |
| Network segmentation | No | All services on localhost; no VLAN separation |
| SIS (Safety Instrumented System) | No | Critical gap — no independent safety layer exists |
| File integrity monitoring on program.st | No | Logic injection would be caught if this existed |

---

## 9. Out of Scope

The following are acknowledged gaps documented here for academic completeness:

- True lateral movement between network segments (everything is localhost)
- SIS/safety layer bypass (Triton-class attacks)
- Historian database direct manipulation
- Firmware modification of OpenPLC binary
- Physical sensor tampering (only software simulation of sensors)
- Supply chain attacks on matiec compiler or pymodbus library

These are Tier 3 (nation-state) capabilities that exceed the academic scope of this project.

---

## 10. References

This threat model follows:
- STRIDE methodology: Shostack, "Threat Modeling: Designing for Security" (2014)
- ICS-specific STRIDE: IEC 62443-3-2 Security Risk Assessment
- Asset priority (A > I > C in ICS): NIST SP 800-82 Rev 3 (2023), Section 3.2
- Attack tree notation: Schneier, "Attack Trees" (1999), Dr. Dobb's Journal