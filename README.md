# Cyber-Physical Systems Security (CPSS) Simulator
### Water Treatment Plant: PLC Attack & Defense Framework (IEC 62443-3-3 SL2 Aligned)

[![PLC Status](https://img.shields.io/badge/OpenPLC-Running-green)](#)
[![Firewall Profile](https://img.shields.io/badge/IEC%2062443--3--3-SL2%20Compliant-blue)](#)
[![Framework](https://img.shields.io/badge/Backend-Flask%20%7C%20PyModbus-orange)](#)

## 📌 Project Overview
This repository contains a high-fidelity **Cyber-Physical Systems (CPS) Security Simulator** modeled after a modern 6-stage municipal water treatment facility. The project demonstrates real-world cyber-physical vulnerabilities—specifically **MITRE ATT&CK ICS-T0873 (Slow Drift)** and advanced parameter manipulation—and validates a layered, defense-in-depth mitigation architecture.

The simulation environment explicitly binds physics-based process dynamics with deterministic industrial control systems running an **IEC 61131-3 Structured Text** PLC engine on a strict 20ms scan cycle.

---

## 🏗️ System Architecture & Subsystems
The infrastructure decouples into three main components operating concurrently across isolated networking boundaries:

1. **OpenPLC Runtime (Port 502):** Executes the core industrial control logic (`program.st`) governing physical process states (pumps, automated dosing valves, and indicators).
2. **Modbus TCP Proxy Firewall (Port 5502):** A custom Deep Packet Inspection (DPI) proxy sitting in front of the PLC. It evaluates payload matrices against **7 deterministic rules** paired with a **CM-6 statistical anomaly engine** running Z-score calculations.
3. **Flask Web Dashboard (Port 5000):** Real-time SCADA HMI featuring an SVG-mapped process rendering pipeline, dynamic parameter metrics, an exploit execution panel, and explicit layer-by-layer tracking.

---

## 📂 Repository File Structure
```text
├── defense/                  # Layer 1 & 3: Threat Mitigation Subsystem
│   ├── modbus_firewall.py    # Main TCP Proxy; handles rule parsing (VAL/INT series)
│   ├── countermeasures.py    # CM-6 Anomaly Engine; drives sliding-window Z-score & RoC
│   └── sis.py                # Layer 2: Hardened Safety Instrumented System
├── water_treatment/          # Layered Process Engineering Core
│   ├── program.st            # Main IEC 61131-3 Structured Text PLC Code
│   ├── main.ld               # Alternate Ladder Diagram mapping for OpenPLC
│   ├── VARIABLES.csv         # Direct Modbus Register mappings (Coils 0-11, HR0-HR3)
│   └── physics.py            # Real-time background simulation of tank physical constants
├── attacker/                 # Vulnerability and Threat Emulation Suite
│   ├── attack_tool.py        # Core CLI Modbus packet crafter and payload injector
│   ├── logic_injection.py    # 15-step graduated slow-drift implementation
│   └── apt_scenario.py       # Advanced Persistent Threat multi-tier campaign chain
├── dashboard/                # SCADA HMI Visual Client Layer
│   ├── server.py             # Main Flask backend driving SSE streams (1300+ LOC)
│   └── templates/
│       └── dashboard.html    # Frontend engine with interactive SVG state updates
└── docs/                     # Analytical Threat Models & Architectural Specs
```

## 🕹️ The 3-Act Demonstration Narrative
The presentation flow structures into a 3-Act sequence designed to display the stark contrast between unprotected critical infrastructure and a hardened environment:

- **Act 1: Normal Operations:** The facility maintains steady-state metrics: Chlorine (Cl) = 200 ppm, Coagulant = 300 mg/L, Distribution Speed = 50%, and the Reservoir sits at a safe 50% equilibrium.
- **Act 2: Attack in Progress (Firewall Offline):** The Modbus firewall is pulled offline. Exploit payloads communicate directly with Port 502, manipulating registers to trigger catastrophic failure models with zero perimeter resistance.
- **Act 3: Defense Response (Firewall Active):** The Modbus Firewall proxy is enabled at Port 5502. Malicious packets are instantly captured, inspected, and dropped by the enforcement layers, keeping system parameters safe.

## 🛡️ Exploit Matrix vs. Defense Mappings (IEC 62443 Compliance)

| Attack Profile | MITRE ICS ID | Primary Rule | Analytical Engine Mechanics | System Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Chlorine Overdose** | T0831 | VAL-001 | Drops explicit Function Code 06 requests targeting HR0 that exceed 800 ppm limits (IEC 62443 SR 3.5). | **BLOCKED** |
| **Alarm Suppression** | T0838 | VAL-004 / INT-001 | Prevents force-OFF commands to Coil 10 (Alarm LED) when chemical registers maintain elevated thresholds (SR 3.6). | **BLOCKED** |
| **System Blackout** | T0816 | INT-002 | Pattern-matching engine flags and drops malicious bulk FC15 commands writing all-FALSE to process switches (SR 7.1). | **BLOCKED** |
| **Tank Overflow** | T0803 | INT-003 | Captures the stateful correlation signature of forcing an inlet valve ON (Coil 7=TRUE) while spoofing the reservoir level sensor (HR3=0%). | **BLOCKED** |
| **Slow Drift / Logic Inject** | T0873 | VAL-007 | Stuxnet Emulation: CM-6 monitors a rolling 30s window. If delta drift exceeds 60 units over 20s, or statistical variance breaks an absolute Z-score of 3, the engine trips. | **BLOCKED (Step 7)** |

## 🔧 Refactoring & Real Bug Fix Manifest
During development and system hardening, several logical and operational bugs were fixed:
- **HMI Health Checks (Bug #1):** Fixed the hardcoded dashboard status indicator by building an independent `GET /defense/firewall/health` TCP verification loop over port 5502 to track live status.
- **Outbound Real Verdicts (Bug #3):** Resolved hardcoded "Write Succeeded" banners on the UI by spinning up an auxiliary HTTP statistics registry over port 5503 to query real-time rule tracking.
- **PLC Watchdog Trips (Bug #4):** Fixed programmatic execution dependencies in `program.st` by re-routing the `Timer_Startup` query to block false latching triggers during state recoveries.
- **Sustained Blackouts (Bug #6):** Refactored the threat tool to run an active loop calling FC15 drops every 50ms for 6s, neutralizing immediate scan cycle overruns.
- **Drift Protection (Bug #8):** Upgraded `modbus_firewall.py` with the VAL-007 rule to monitor low-and-slow manipulation that previously slipped past static thresholds.

## 🚀 Step-by-Step System Deployment
Follow this exact initialization order to set up and run the simulator platform:

**1. Environment & Package Initialization**
```bash
cd complete_project
source venv/bin/activate
pip install -r requirements.txt
```
*(Activates the isolated Python virtual environment containing all required control dependencies).*

**2. Configure and Execute OpenPLC**
- Direct your browser to `http://127.0.0.1:8080` (Credentials: `openplc` / `openplc`).
- Navigate to the **Programs** menu and upload `water_treatment/program.st`.
- Wait for compilation verification, then hit **Start PLC** to open up the port 502 communication pipeline.

**3. Deploy the Modbus Firewall Layer**
```bash
python defense/modbus_firewall.py
```
*Expected console output: `[FIREWALL] Modbus Firewall listening on port 5502 -> forwarding to 127.0.0.1:502`.*

**4. Initialize the SCADA Dashboard Web Client**
```bash
python dashboard/server.py
```
*Open `http://127.0.0.1:5000/dashboard` in your browser to view the real-time simulation panel. Use the `RESTORE SAFE STATE` initialization trigger if parameters default to empty arrays upon cold boot.*

## 👤 Author & Contact
- **Author:** Ahmad Ejaz
- **Institution:** The Islamia University of Bahawalpur
- **Course:** Industrial Control Systems Security / End-Semester Project
- **Year:** 2026
