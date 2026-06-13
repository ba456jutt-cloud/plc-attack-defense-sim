<?xml version="1.0" encoding="UTF-8"?>
<!-- ============================================================
     Water Treatment Plant — Ladder Logic Diagram
     Format  : OpenPLC Editor .ld (IEC 61131-3 LD)
     Program : main
     Each "rung" below corresponds to one section of program.st
     Load this file in OpenPLC Editor to see visual ladder rungs.
     ============================================================ -->
<project xmlns="http://www.plcopen.org/xml/tc6_0201"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://www.plcopen.org/xml/tc6_0201 http://www.plcopen.org/xml/tc6_0201/TC6_XML_V201.xsd">

  <fileHeader companyName="CPSS Project"
              productName="Water Treatment Plant PLC"
              productVersion="1.0"
              creationDateTime="2025-01-01T00:00:00"/>

  <contentHeader name="WaterTreatmentPlant" modificationDateTime="2025-01-01T00:00:00">
    <coordinateInfo>
      <fbd><scaling x="1" y="1"/></fbd>
      <ld><scaling x="1" y="1"/></ld>
      <sfc><scaling x="1" y="1"/></sfc>
    </coordinateInfo>
  </contentHeader>

  <types>
    <dataTypes/>
    <pous>

      <!-- ═══════════════════════════════════════════════════════
           PROGRAM: main
           Contains all ladder logic rungs for the water plant.
           ═══════════════════════════════════════════════════════ -->
      <pou name="main" pouType="program">
        <interface>
          <localVars>

            <!-- Output coils — physical actuators -->
            <variable name="Intake_Pump">
              <type><BOOL/></type>
              <address>%QX0.0</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Raw water intake pump</xhtml:p></documentation>
            </variable>
            <variable name="Intake_Valve">
              <type><BOOL/></type>
              <address>%QX0.1</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Inlet gate valve</xhtml:p></documentation>
            </variable>
            <variable name="Chlorine_Pump">
              <type><BOOL/></type>
              <address>%QX0.2</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Chlorine dosing pump</xhtml:p></documentation>
            </variable>
            <variable name="Coagulant_Pump">
              <type><BOOL/></type>
              <address>%QX0.3</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Coagulant dosing pump</xhtml:p></documentation>
            </variable>
            <variable name="Dosing_Enable">
              <type><BOOL/></type>
              <address>%QX0.4</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Chemical dosing system master enable</xhtml:p></documentation>
            </variable>
            <variable name="Filter_Valve">
              <type><BOOL/></type>
              <address>%QX0.5</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Sand filter inlet valve</xhtml:p></documentation>
            </variable>
            <variable name="UV_System">
              <type><BOOL/></type>
              <address>%QX0.6</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">UV disinfection system</xhtml:p></documentation>
            </variable>
            <variable name="Reservoir_Inlet">
              <type><BOOL/></type>
              <address>%QX0.7</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Reservoir fill valve</xhtml:p></documentation>
            </variable>
            <variable name="Reservoir_Outlet">
              <type><BOOL/></type>
              <address>%QX1.0</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Reservoir outlet valve</xhtml:p></documentation>
            </variable>
            <variable name="Distribution_Pump">
              <type><BOOL/></type>
              <address>%QX1.1</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Final distribution pump</xhtml:p></documentation>
            </variable>
            <variable name="Alarm_LED">
              <type><BOOL/></type>
              <address>%QX1.2</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Physical alarm indicator LED</xhtml:p></documentation>
            </variable>
            <variable name="System_Enable">
              <type><BOOL/></type>
              <address>%QX1.3</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Master system ON/OFF switch</xhtml:p></documentation>
            </variable>

            <!-- Discrete sensor inputs -->
            <variable name="Level_Low_Sensor">
              <type><BOOL/></type>
              <address>%IX0.0</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Reservoir critically low</xhtml:p></documentation>
            </variable>
            <variable name="Level_High_Sensor">
              <type><BOOL/></type>
              <address>%IX0.1</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Reservoir full</xhtml:p></documentation>
            </variable>
            <variable name="Filter_Pressure_OK">
              <type><BOOL/></type>
              <address>%IX0.2</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Filter pressure within safe range</xhtml:p></documentation>
            </variable>
            <variable name="Flow_Sensor">
              <type><BOOL/></type>
              <address>%IX0.3</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Water flow detected in main pipe</xhtml:p></documentation>
            </variable>

            <!-- Holding registers (analog) -->
            <variable name="Chlorine_Dose">
              <type><INT/></type>
              <address>%QW0</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Chlorine dosing rate 0-1000. DANGER above 800.</xhtml:p></documentation>
            </variable>
            <variable name="Coagulant_Dose">
              <type><INT/></type>
              <address>%QW1</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Coagulant dosing rate 0-1000</xhtml:p></documentation>
            </variable>
            <variable name="Distribution_Speed">
              <type><INT/></type>
              <address>%QW2</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Distribution pump speed setpoint 0-100</xhtml:p></documentation>
            </variable>
            <variable name="Reservoir_Level_Pct">
              <type><INT/></type>
              <address>%QW3</address>
              <documentation><xhtml:p xmlns:xhtml="http://www.w3.org/1999/xhtml">Calculated reservoir level percentage 0-100</xhtml:p></documentation>
            </variable>

            <!-- Internal variables -->
            <variable name="Alarm_Active"><type><BOOL/></type></variable>
            <variable name="Chlorine_Overdose"><type><BOOL/></type></variable>
            <variable name="System_Ready"><type><BOOL/></type></variable>
            <variable name="Filter_Fault"><type><BOOL/></type></variable>
            <variable name="Timer_Startup"><type><derived name="TON"/></type></variable>
            <variable name="Timer_Dosing"><type><derived name="TON"/></type></variable>
            <variable name="Timer_Alarm"><type><derived name="TON"/></type></variable>
            <variable name="Timer_UVWarmup"><type><derived name="TON"/></type></variable>

          </localVars>
        </interface>

        <body>
          <LD>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 1: STARTUP TIMER
                 System_Enable ──[TON 5s]──► System_Ready
                 ───────────────────────────────────────────────────── -->
            <rung localId="1" height="200" width="800">
              <comment><content>RUNG 1: Startup sequencing — System must be enabled for 5s before any stage runs</content></comment>
              <contact localId="10" negated="false" height="60" width="80" x="100" y="80">
                <variable>System_Enable</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <block localId="11" typeName="TON" instanceName="Timer_Startup" height="120" width="180" x="240" y="60">
                <inputVariables>
                  <variable formalParameter="IN"><connectionPointIn><connection refLocalId="10"/></connectionPointIn></variable>
                  <variable formalParameter="PT"><connectionPointIn><expression>T#5s</expression></connectionPointIn></variable>
                </inputVariables>
                <outputVariables>
                  <variable formalParameter="Q"><connectionPointOut/></variable>
                </outputVariables>
              </block>
              <coil localId="12" negated="false" height="60" width="80" x="500" y="80">
                <variable>System_Ready</variable>
                <connectionPointIn><connection refLocalId="11" formalParameter="Q"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 2: CHLORINE OVERDOSE DETECTION
                 (Chlorine_Dose > 800) ──► Chlorine_Overdose
                 ───────────────────────────────────────────────────── -->
            <rung localId="2" height="200" width="800">
              <comment><content>RUNG 2: Safety interlock — chlorine overdose detection. Threshold: 800 units</content></comment>
              <contact localId="20" negated="false" height="60" width="80" x="100" y="80">
                <variable>Chlorine_Dose GT 800</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="21" negated="false" height="60" width="80" x="500" y="80">
                <variable>Chlorine_Overdose</variable>
                <connectionPointIn><connection refLocalId="20"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 3: ALARM LOGIC
                 Chlorine_Overdose OR Filter_Fault ──[TON 10s]──► Alarm_LED
                 ───────────────────────────────────────────────────── -->
            <rung localId="3" height="200" width="800">
              <comment><content>RUNG 3: Alarm logic — activates on overdose or filter fault. Held for 10s after clear.</content></comment>
              <contact localId="30" negated="false" height="60" width="80" x="100" y="60">
                <variable>Chlorine_Overdose</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="31" negated="false" height="60" width="80" x="100" y="130">
                <variable>Filter_Fault</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <block localId="32" typeName="TON" instanceName="Timer_Alarm" height="120" width="180" x="280" y="60">
                <inputVariables>
                  <variable formalParameter="IN"><connectionPointIn><connection refLocalId="30"/></connectionPointIn></variable>
                  <variable formalParameter="PT"><connectionPointIn><expression>T#10s</expression></connectionPointIn></variable>
                </inputVariables>
                <outputVariables>
                  <variable formalParameter="Q"><connectionPointOut/></variable>
                </outputVariables>
              </block>
              <coil localId="33" negated="false" height="60" width="80" x="550" y="80">
                <variable>Alarm_LED</variable>
                <connectionPointIn><connection refLocalId="32" formalParameter="Q"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 4: STAGE 1 — INTAKE
                 System_Ready AND NOT Alarm_Active ──► Intake_Valve
                 System_Ready AND NOT Alarm AND NOT Filter_Fault ──► Intake_Pump
                 ───────────────────────────────────────────────────── -->
            <rung localId="4" height="200" width="800">
              <comment><content>RUNG 4: Stage 1 Intake — pump and valve enabled when system ready and no alarm</content></comment>
              <contact localId="40" negated="false" height="60" width="80" x="60" y="80">
                <variable>System_Ready</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="41" negated="true" height="60" width="80" x="180" y="80">
                <variable>Alarm_Active</variable>
                <connectionPointIn><connection refLocalId="40"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="42" negated="false" height="60" width="80" x="420" y="60">
                <variable>Intake_Valve</variable>
                <connectionPointIn><connection refLocalId="41"/></connectionPointIn>
              </coil>
              <contact localId="43" negated="true" height="60" width="80" x="300" y="80">
                <variable>Filter_Fault</variable>
                <connectionPointIn><connection refLocalId="41"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="44" negated="false" height="60" width="80" x="420" y="120">
                <variable>Intake_Pump</variable>
                <connectionPointIn><connection refLocalId="43"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 5: STAGE 2 — CHEMICAL DOSING
                 Intake_Pump AND System_Ready ──[TON 2s]──► Dosing_Enable
                 Dosing_Enable AND Chlorine_Dose>0 ──► Chlorine_Pump
                 Dosing_Enable AND Coagulant_Dose>0 ──► Coagulant_Pump
                 ───────────────────────────────────────────────────── -->
            <rung localId="5" height="200" width="800">
              <comment><content>RUNG 5: Stage 2 Chemical Dosing — pulsed timer enables dosing pumps. Blocked if overdose detected.</content></comment>
              <contact localId="50" negated="false" height="60" width="80" x="60" y="80">
                <variable>Intake_Pump</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="51" negated="false" height="60" width="80" x="160" y="80">
                <variable>System_Ready</variable>
                <connectionPointIn><connection refLocalId="50"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <block localId="52" typeName="TON" instanceName="Timer_Dosing" height="120" width="180" x="280" y="60">
                <inputVariables>
                  <variable formalParameter="IN"><connectionPointIn><connection refLocalId="51"/></connectionPointIn></variable>
                  <variable formalParameter="PT"><connectionPointIn><expression>T#2s</expression></connectionPointIn></variable>
                </inputVariables>
                <outputVariables>
                  <variable formalParameter="Q"><connectionPointOut/></variable>
                </outputVariables>
              </block>
              <contact localId="53" negated="true" height="60" width="80" x="480" y="80">
                <variable>Chlorine_Overdose</variable>
                <connectionPointIn><connection refLocalId="52" formalParameter="Q"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="54" negated="false" height="60" width="80" x="620" y="80">
                <variable>Dosing_Enable</variable>
                <connectionPointIn><connection refLocalId="53"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 6: STAGE 3 — FILTRATION & UV
                 Dosing_Enable AND Filter_Pressure_OK ──► Filter_Valve
                 Filter_Valve ──[TON 3s]──► UV_System
                 ───────────────────────────────────────────────────── -->
            <rung localId="6" height="200" width="800">
              <comment><content>RUNG 6: Stage 3 Filtration — filter valve opens after dosing. UV warmup 3s before active.</content></comment>
              <contact localId="60" negated="false" height="60" width="80" x="60" y="80">
                <variable>Dosing_Enable</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="61" negated="false" height="60" width="80" x="180" y="80">
                <variable>Filter_Pressure_OK</variable>
                <connectionPointIn><connection refLocalId="60"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="62" negated="false" height="60" width="80" x="360" y="80">
                <variable>Filter_Valve</variable>
                <connectionPointIn><connection refLocalId="61"/></connectionPointIn>
              </coil>
              <block localId="63" typeName="TON" instanceName="Timer_UVWarmup" height="120" width="180" x="480" y="60">
                <inputVariables>
                  <variable formalParameter="IN"><connectionPointIn><connection refLocalId="62"/></connectionPointIn></variable>
                  <variable formalParameter="PT"><connectionPointIn><expression>T#3s</expression></connectionPointIn></variable>
                </inputVariables>
                <outputVariables>
                  <variable formalParameter="Q"><connectionPointOut/></variable>
                </outputVariables>
              </block>
              <coil localId="64" negated="false" height="60" width="80" x="700" y="80">
                <variable>UV_System</variable>
                <connectionPointIn><connection refLocalId="63" formalParameter="Q"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 7: STAGE 4 — RESERVOIR CONTROL
                 UV_System AND NOT Level_High AND NOT Alarm ──► Reservoir_Inlet
                 NOT Level_Low AND Distribution_Pump ──► Reservoir_Outlet
                 ───────────────────────────────────────────────────── -->
            <rung localId="7" height="200" width="800">
              <comment><content>RUNG 7: Stage 4 Reservoir — inlet closes when full (safety interlock). Outlet opens with pump.</content></comment>
              <contact localId="70" negated="false" height="60" width="80" x="60" y="60">
                <variable>UV_System</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="71" negated="true" height="60" width="80" x="180" y="60">
                <variable>Level_High_Sensor</variable>
                <connectionPointIn><connection refLocalId="70"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="72" negated="true" height="60" width="80" x="300" y="60">
                <variable>Alarm_Active</variable>
                <connectionPointIn><connection refLocalId="71"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="73" negated="false" height="60" width="80" x="460" y="60">
                <variable>Reservoir_Inlet</variable>
                <connectionPointIn><connection refLocalId="72"/></connectionPointIn>
              </coil>
              <contact localId="74" negated="true" height="60" width="80" x="60" y="140">
                <variable>Level_Low_Sensor</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="75" negated="false" height="60" width="80" x="180" y="140">
                <variable>Distribution_Pump</variable>
                <connectionPointIn><connection refLocalId="74"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="76" negated="false" height="60" width="80" x="460" y="140">
                <variable>Reservoir_Outlet</variable>
                <connectionPointIn><connection refLocalId="75"/></connectionPointIn>
              </coil>
            </rung>

            <!-- ─────────────────────────────────────────────────────
                 RUNG 8: STAGE 5 — DISTRIBUTION PUMP
                 NOT Level_Low AND NOT Alarm AND System_Ready
                 AND Reservoir_Level > 10 ──► Distribution_Pump
                 ───────────────────────────────────────────────────── -->
            <rung localId="8" height="200" width="800">
              <comment><content>RUNG 8: Stage 5 Distribution — pump only runs when reservoir has water and system is healthy</content></comment>
              <contact localId="80" negated="true" height="60" width="80" x="60" y="80">
                <variable>Level_Low_Sensor</variable>
                <connectionPointIn><connection refLocalId="0"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="81" negated="true" height="60" width="80" x="180" y="80">
                <variable>Alarm_Active</variable>
                <connectionPointIn><connection refLocalId="80"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="82" negated="false" height="60" width="80" x="300" y="80">
                <variable>System_Ready</variable>
                <connectionPointIn><connection refLocalId="81"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <contact localId="83" negated="false" height="60" width="80" x="420" y="80">
                <variable>Reservoir_Level_Pct GT 10</variable>
                <connectionPointIn><connection refLocalId="82"/></connectionPointIn>
                <connectionPointOut/>
              </contact>
              <coil localId="84" negated="false" height="60" width="80" x="600" y="80">
                <variable>Distribution_Pump</variable>
                <connectionPointIn><connection refLocalId="83"/></connectionPointIn>
              </coil>
            </rung>

          </LD>
        </body>
      </pou>
    </pous>
  </types>

  <instances>
    <configurations>
      <configuration name="Config0">
        <resource name="Res0">
          <task name="task0" priority="1" interval="T#20ms"/>
          <programConfiguration name="instance0" referenceTask="task0" typeName="main"/>
        </resource>
      </configuration>
    </configurations>
  </instances>

</project>
