# Demo Flow Guide
### CPSS Presentation — Water Treatment Plant PLC Attack

---

## Terminal Layout (set up before presenting)

```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│  Terminal 1      │  Terminal 2      │  Terminal 3      │  Terminal 4      │
│  auth_proxy.py   │  monitor.py      │  attack_tool.py  │  bypass_auth.py  │
│                  │  (always open)   │  or scenarios    │  (auth demo)     │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

**T1:**
```bash
cd ~/complete_project && source venv/bin/activate
python3 auth_proxy.py
```

**T2:**
```bash
python3 attacker/monitor.py
```

**T3:**
```bash
python3 attacker/attack_tool.py
```

**T4:**
```bash
python3 attacker/bypass_auth.py
```

---

## Demo Script (~20 minutes)

---

### Part 1 — Context (2 min)

Point at T2 (monitor dashboard).

> "This is a live Water Treatment Plant PLC — 5 stages: intake, chemical dosing, filtration, UV, and reservoir distribution. Every actuator state and every sensor register is visible here. I have not logged in. There is no username, no password. This is how Modbus TCP works — by design, any host on the network gets full visibility."

---

### Part 2 — Passive Recon (2 min)

T3 → **Mode 8**

> "Before attacking, a real adversary observes. In under 10 seconds I know which pumps are running, the exact chlorine setpoint, alarm state, reservoir level. MITRE T0840 — network enumeration. No special tools, just raw Modbus FC01 and FC03 reads."

Ctrl+C after ~30 seconds.

---

### Part 3 — Force Coil / Silent Disable (2 min)

T3 → **Mode 1** → Coil 6 (UV_System) → OFF

> "I've disabled UV disinfection. The PLC ladder logic tries to restore it every 20ms — my tool writes FALSE faster. Water passes through without treatment. The rest of the dashboard looks completely normal."

Stop → watch coil 6 restore automatically.

---

### Part 4 — Chemical Overdose + Alarm Suppression (3 min)

T3 → `python3 attacker/exploit_scenarios.py --run 1`

> "This is the Oldsmar 2021 attack. Chlorine dose climbs to 1000 — threshold is 800. Simultaneously I force the Alarm LED OFF. An operator watching the physical panel sees all-clear. The water is toxic. The board says normal. This is MITRE T0836 plus T0878 — modify parameter plus alarm suppression."

---

### Part 5 — Auth Proxy "Defense" (2 min)

Point at T1 (auth_proxy.py running).

> "Let's say the defender added authentication. They've put a token-based proxy gate on port 5020. Clients must perform an HMAC-SHA1 challenge-response handshake before they get Modbus access. Sounds good."

T2 → restart monitor with proxy:
```bash
python3 attacker/monitor.py --port 5020 --auth-token cpss2026
```

> "Legitimate clients authenticate through port 5020. The proxy logs everything to proxy_traffic.log."

---

### Part 6 — Bypass the Auth (3 min)

T4 → **Option 3** (both bypasses)

**Bypass 1:**
> "Bypass one: ignore the proxy entirely. Port 502 is still open. I connect directly — no handshake, no token. Full read and write. The auth proxy on 5020 is completely irrelevant. This is why network segmentation matters — application-layer auth alone is not enough."

**Bypass 2:**
> "Bypass two: I parse proxy_traffic.log — simulating a network tap or Wireshark capture on the LAN. I extract the challenge nonce and token from a previous session, run a dictionary attack to recover the secret 'cpss2026', then compute a fresh valid token and authenticate through the proxy legitimately. Full bypass. MITRE T0856 — spoof command message."

---

### Part 7 — Blackout Finale (1 min)

T3 → **Mode 5**

> "To close — system blackout. All 12 coils to OFF in one Modbus frame. No authentication. No delay. Complete plant shutdown."

---

### Part 8 — Defense (3 min)

Refer to `docs/defense_and_mitigation.md`.

Five layers:
1. **Network segmentation** — OT network isolated, port 502 unreachable from outside
2. **Modbus/TLS** — protocol-level auth with client certificates
3. **ICS-aware firewall** — block FC05 writes from non-engineering hosts, value range enforcement
4. **Hardware interlocks** — physical float switches and flow restrictors that software cannot override
5. **Anomaly detection** — statistical baseline catches slow-drift attacks

> "Oldsmar 2021, Ukraine grid 2015, Stuxnet 2010 — all succeeded because one or more of these layers was missing. Defense in depth."

---

## Reset After Demo

```bash
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('127.0.0.1', port=502)
c.connect()
c.write_coils(0, [False]*12)
c.write_registers(0, [200, 300, 50, 50])
c.write_coil(11, True)
c.close()
print('Reset OK')
"
```

## If Something Breaks

**Port 502 not listening:**
```bash
sudo ss -tlnp | grep 502
# Go to http://localhost:8080 → Start PLC
```

**Modbus connection refused:**
```bash
# Port 502 needs root on Linux
sudo python3 attacker/attack_tool.py
```

**pymodbus import error:**
```bash
source venv/bin/activate
pip install pymodbus
```

**proxy_traffic.log empty (Bypass 2 fails):**
```bash
# Run monitor through proxy at least once first
python3 attacker/monitor.py --port 5020 --auth-token cpss2026
# Then run bypass_auth.py again
```