# Modbus Register Map — Water Treatment Plant PLC

**Target:** OpenPLC Runtime v4  
**Protocol:** Modbus TCP  
**Port:** 502  
**Slave ID:** 1  

---

## Output Coils (Read/Write) — FC01 Read, FC05/FC15 Write

These are the PLC's **digital output signals** — pumps, valves, actuators.  
An attacker writing to these overrides whatever value the ladder logic computed.

| Coil # | IEC Address | Variable Name      | Description                        | Normal State |
|--------|-------------|--------------------|------------------------------------|--------------|
| 0      | %QX0.0      | Intake_Pump        | Raw water intake pump              | ON when running |
| 1      | %QX0.1      | Intake_Valve       | Inlet gate valve                   | OPEN when running |
| 2      | %QX0.2      | Chlorine_Pump      | Chlorine chemical dosing pump      | Pulsed ON/OFF |
| 3      | %QX0.3      | Coagulant_Pump     | Coagulant chemical dosing pump     | Pulsed ON/OFF |
| 4      | %QX0.4      | Dosing_Enable      | Chemical dosing master enable      | ON during dosing cycle |
| 5      | %QX0.5      | Filter_Valve       | Sand filter inlet valve            | OPEN after dosing |
| 6      | %QX0.6      | UV_System          | UV disinfection system             | ON after filter (3s delay) |
| 7      | %QX0.7      | Reservoir_Inlet    | Reservoir fill valve               | OPEN when UV active + not full |
| 8      | %QX1.0      | Reservoir_Outlet   | Reservoir outlet to distribution   | OPEN when pump running |
| 9      | %QX1.1      | Distribution_Pump  | Final distribution pump            | ON when level > 10% |
| 10     | %QX1.2      | Alarm_LED          | Physical alarm indicator LED       | OFF (ON = fault) |
| 11     | %QX1.3      | System_Enable      | Master system ON/OFF switch        | ON = system running |

---

## Discrete Inputs (Read Only) — FC02 Read

These are **sensor readings** fed into the PLC. In a real system these come from physical sensors. In OpenPLC simulation, you can write to them via FC05 to simulate sensor manipulation.

| Input # | IEC Address | Variable Name       | Description                              | Normal State |
|---------|-------------|---------------------|------------------------------------------|--------------|
| 0       | %IX0.0      | Level_Low_Sensor    | Reservoir critically low                 | FALSE (not low) |
| 1       | %IX0.1      | Level_High_Sensor   | Reservoir full                           | FALSE (not full) |
| 2       | %IX0.2      | Filter_Pressure_OK  | Filter pressure within safe range        | TRUE (OK) |
| 3       | %IX0.3      | Flow_Sensor         | Water flow detected in main pipe         | TRUE when flowing |

---

## Holding Registers (Read/Write) — FC03 Read, FC06/FC16 Write

These are **analog setpoints and measurements** — 16-bit integer values.

| Register # | IEC Address | Variable Name        | Description                        | Safe Range | DANGER Threshold |
|------------|-------------|----------------------|------------------------------------|------------|-----------------|
| 0          | %QW0        | Chlorine_Dose        | Chlorine dosing rate               | 0–500      | > 800 = OVERDOSE |
| 1          | %QW1        | Coagulant_Dose       | Coagulant dosing rate              | 0–600      | > 900 = fault |
| 2          | %QW2        | Distribution_Speed   | Pump speed setpoint (RPM scale)    | 20–80      | 0 = stall, 100 = overspeed |
| 3          | %QW3        | Reservoir_Level_Pct  | Calculated reservoir level %       | 10–90      | 0 = dry run, 100 = overflow |

---

## Attack Surface Summary

### High-Impact Single-Coil Attacks

| Target | Write Value | Effect |
|--------|-------------|--------|
| Coil 6 (UV_System) | FALSE | Unfiltered/unchlorinated water enters reservoir |
| Coil 7 (Reservoir_Inlet) | TRUE | Fill valve stuck open → overflow (no level cutoff) |
| Coil 9 (Distribution_Pump) | TRUE | Pump runs dry if Coil 8 (Outlet) is FALSE → cavitation |
| Coil 10 (Alarm_LED) | FALSE | Suppress alarm indicator — operator unaware of fault |
| Coil 11 (System_Enable) | FALSE | Entire plant shuts down — denial of service |

### High-Impact Register Attacks

| Target | Write Value | Effect |
|--------|-------------|--------|
| HR 0 (Chlorine_Dose) | 1000 | Triggers overdose interlock → halts dosing, raises alarm |
| HR 0 (Chlorine_Dose) | 850 | Just above threshold — slow-creep attack, harder to detect |
| HR 2 (Distribution_Speed) | 0 | Pump stall — zero output flow |
| HR 3 (Reservoir_Level_Pct) | 0 | Spoofs empty reservoir → stops distribution pump |

### Combined Multi-Step Attack (Pump Cavitation)
1. Write Coil 8 (Reservoir_Outlet) = FALSE  — close outlet valve
2. Write Coil 9 (Distribution_Pump) = TRUE  — force pump ON with no water
3. Result: pump runs against closed valve → physical damage scenario

---

## Modbus Function Codes Reference

| FC | Name                    | Used For                        |
|----|-------------------------|---------------------------------|
| 01 | Read Coils              | Read output coil states         |
| 02 | Read Discrete Inputs    | Read sensor states              |
| 03 | Read Holding Registers  | Read analog setpoints           |
| 05 | Write Single Coil       | Override one output coil        |
| 06 | Write Single Register   | Set one analog register         |
| 15 | Write Multiple Coils    | Override multiple coils at once |
| 16 | Write Multiple Registers| Set multiple registers at once  |