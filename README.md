UDS Diagnostic Test Automation
> Automated ECU diagnostics validation using Python, pytest, and UDS (ISO 14229) — no hardware required.
![Tests](https://img.shields.io/badge/tests-20%20passed-brightgreen)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Protocol](https://img.shields.io/badge/protocol-UDS%20ISO%2014229-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
**---
What this is
A Python test automation framework for validating ECU diagnostic behaviour over the UDS protocol. It covers the three areas that appear in almost every automotive test specification — session control, data identifier access, and fault memory management — with 20 automated test cases and a mock ECU that runs entirely in software.
The mock ECU is a TCP server that behaves identically to a real device from the test's perspective. Swapping it for real hardware means changing one connection string. The test cases themselves do not change.
---
Protocol background
UDS (ISO 14229) is the standard protocol for communicating with automotive ECUs — reading data, writing calibration values, triggering resets, and managing fault codes.
SOVD (Service-Oriented Vehicle Diagnostics) is the next-generation diagnostic interface for software-defined vehicles, exposing ECU capabilities as discoverable API-style services rather than low-level byte requests.
DoIP (ISO 13400) carries UDS messages over Ethernet/IP instead of CAN, enabling the higher bandwidth needed for modern zonal architectures and rapid software flashing.
SOME/IP is the AUTOSAR middleware protocol used for service-to-service communication over Automotive Ethernet — relevant because infotainment and gateway ECUs increasingly use it alongside UDS.
Why SDVs raise the bar
Software-defined vehicles receive over-the-air updates throughout their lifetime. Every update needs to be validated diagnostically — session transitions, security access, DID integrity, fault memory — before it can be approved for rollout. That is not a job for manual testing. It is a job for automated diagnostic regression.
---**
Project structure
```
uds_diagnostics_demo/
├── services/
│   ├── uds_constants.py       # All SIDs, NRCs, session types, DIDs, seed-key algorithm
│   ├── mock_ecu.py            # TCP-based simulated ECU — replaces real hardware
│   └── uds_client.py          # Typed Python client: read_did, write_did, unlock_security
├── utils/
│   └── can_utils.py           # python-can setup + udsoncan real-hardware reference
├── tests/
│   ├── conftest.py            # Fixtures: ECU session-scoped, client resets per test
│   └── test_uds_diagnostics.py
└── requirements.txt
```
---
Getting started
Install dependencies
```bash
pip install -r requirements.txt
```
Run all tests
```bash
pytest tests/ -v
```
Generate HTML report
```bash
pytest tests/ -v --html=report.html --self-contained-html
```
> Open `report.html` in your browser to see the full test report with pass/fail status per case.
---
Test suite 1 — Diagnostic session control
`0x10 DiagnosticSessionControl` + `0x3E TesterPresent`
Session management is the foundation of everything else in UDS. If it is wrong, no other test is meaningful. The ECU must start in default session, enforce access restrictions by session, and handle the TesterPresent heartbeat accurately.
Sequence — session timeout without TesterPresent
> The ECU silently falls back to default session when the heartbeat stops. Without this test, this failure mode only shows up in production as random, unreproducible NRC errors.

![Session Timeout Sequence Diagram]("C:\Users\himan\Pictures\Screenshots\Screenshot 2026-03-29 095359.png")
```python
def test_tc01_session_timeout_without_tester_present(self, client, ecu):
    client.set_session(DiagSession.EXTENDED)
    assert ecu.state.session == DiagSession.EXTENDED

    # Shorten timeout for test speed
    ecu.state.session_timeout = 0.2
    time.sleep(0.4)

    # ECU checks timeout on next incoming request
    with pytest.raises(UDSNegativeResponse) as exc_info:
        client.read_did(DID.AUDIO_VOLUME_CODING)

    assert ecu.state.session == DiagSession.DEFAULT
    assert exc_info.value.nrc_code == NRC.CONDITIONS_NOT_CORRECT
```
What the log looks like when this runs:
```
09:14:22  INFO   MockECU   Session timeout → returning to DEFAULT, security locked
09:14:22  DEBUG  UDSClient → 22 01 01
09:14:22  DEBUG  MockECU   NRC 7F 22 22 (CONDITIONS_NOT_CORRECT)
09:14:22  DEBUG  UDSClient ← 7F 22 22
```
**Test	Validates
`test_tc01_default_session_on_startup`	DID 0xF186 returns 0x01 (DEFAULT) on power-on
`test_tc01_transition_to_extended_session`	0x10 0x03 returns 0x50 0x03, state changes
`test_tc01_coding_did_blocked_in_default_session`	Coding DID returns NRC 0x22 in default session
`test_tc01_session_timeout_without_tester_present`	ECU falls back to default after heartbeat stops
`test_tc01_tester_present_keeps_session_alive`	0x3E refreshes timer; session stays active
---**
Test suite 2 — Security access and DID read / write
`0x27 SecurityAccess` + `0x22 ReadDataByIdentifier` + `0x2E WriteDataByIdentifier`
Security access is the most commonly misimplemented service in ECU diagnostics. These tests cover the full positive path, the expected negative paths, and the boundary conditions for writable coding values.
Sequence — seed-key exchange
> A wrong key must return NRC 0x35. Three consecutive failures must trigger NRC 0x36 and a 10-second lockout. An ECU that does not lock out is a security violation.


![Security Access Sequence Diagram]("C:\Users\himan\Pictures\Screenshots\Screenshot 2026-03-29 095420.png")
```python
def test_tc02_security_access_seed_key_flow(self, client, ecu):
    assert not ecu.state.security_unlocked

    client.set_session(DiagSession.EXTENDED)
    result = client.unlock_security()

    assert result is True
    assert ecu.state.security_unlocked is True
```
The client's `unlock_security()` handles the full sequence internally:
```python
def unlock_security(self, level=SecurityLevel.REQUEST_SEED_L1) -> bool:
    # Step 1 — request seed
    seed_resp = self._send(bytes([SID.SECURITY_ACCESS, int(level)]))
    seed = (seed_resp[2] << 8) | seed_resp[3]

    # Step 2 — compute key using OEM algorithm
    key = compute_key(seed)   # seed XOR 0xA5A5

    # Step 3 — send key
    self._send(bytes([
        SID.SECURITY_ACCESS,
        level + 1,
        (key >> 8) & 0xFF,
        key & 0xFF,
    ]))
    return True
```
What the ECU log looks like:
```
09:14:23  INFO   MockECU   SecurityAccess: seed=0x5A3C
09:14:23  INFO   MockECU   SecurityAccess: UNLOCKED
09:14:23  INFO   MockECU   Write DID 0x0101: audio_volume_max = 90
```
Negative path — wrong key:
```
09:14:24  WARN   MockECU   SecurityAccess: invalid key (attempt 1)
09:14:24  DEBUG  UDSClient ← 7F 27 35   (NRC INVALID_KEY)

09:14:24  WARN   MockECU   SecurityAccess: LOCKED OUT after 3 failed attempts
09:14:24  DEBUG  UDSClient ← 7F 27 36   (NRC EXCEED_NUMBER_OF_ATTEMPTS)
```
Boundary value test — DID write range:
```python
def test_tc02_write_did_boundary_values(self, extended_client, ecu):
    # Valid boundaries — all must be accepted
    for valid_val in (0, 50, 100):
        extended_client.write_did(DID.AUDIO_VOLUME_CODING, bytes([valid_val]))
        assert extended_client.read_did_byte(DID.AUDIO_VOLUME_CODING) == valid_val

    # Out of range — must be rejected
    with pytest.raises(UDSNegativeResponse) as exc_info:
        extended_client.write_did(DID.AUDIO_VOLUME_CODING, bytes([101]))

    assert exc_info.value.nrc_code == NRC.REQUEST_OUT_OF_RANGE
```
> The ordering of NRC checks also matters. An ECU that returns NRC 0x33 (security denied) in default session is revealing its internal check order — it should be checking session first, security second. That is a spec violation.
Test	Validates
`test_tc02_read_identification_dids_in_default_session`	VIN, SW version, HW version readable in any session
`test_tc02_security_access_seed_key_flow`	Full 0x27 seed-key sequence succeeds
`test_tc02_security_access_denied_without_extended_session`	Seed request in default returns NRC 0x22
`test_tc02_invalid_key_returns_nrc`	Wrong key returns NRC 0x35
`test_tc02_write_coding_did_full_flow`	Extended + unlocked: write accepted, read-back matches
`test_tc02_write_did_boundary_values`	0/50/100 accepted; 101 returns NRC 0x31
`test_tc02_write_did_blocked_without_security`	Extended but no unlock returns NRC 0x33
`test_tc02_write_did_blocked_in_default_session`	Default session returns NRC 0x22
`test_tc02_multiple_coding_dids`	Brightness, language, speed limit written independently
---
Test suite 3 — DTC fault memory
`0x19 ReadDTCInformation` + `0x14 ClearDiagnosticInformation`
Fault memory is safety-relevant. A DTC stored with the wrong status byte, not stored at all, or not properly cleared after the `0x14` command can mask a real fault in production.
Sequence — inject, verify status bits, clear, re-verify
> The status mask filtering test is the most nuanced. It verifies the ECU correctly applies the 8-bit mask — returning only DTCs whose status byte has the requested bits set. This is where many ECU implementations diverge from spec.

![DTC Fault Memory Sequence Diagram]("C:\Users\himan\Pictures\Screenshots\Screenshot 2026-03-29 095434.png")
```python
def test_tc03_status_mask_filtering(self, client, ecu):
    # Inject two DTCs with different status bytes
    ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT,    DTCStatus.CONFIRMED_DTC)
    ecu.inject_dtc(DTCCode.NAVIGATION_ANTENNA_FAULT, DTCStatus.PENDING_DTC)

    # Query with mask=0x08 — confirmed only
    confirmed = client.read_dtcs(status_mask=DTCStatus.CONFIRMED_DTC)
    confirmed_codes = {d["code"] for d in confirmed}
    assert int(DTCCode.AUDIO_HARDWARE_FAULT)      in confirmed_codes
    assert int(DTCCode.NAVIGATION_ANTENNA_FAULT) not in confirmed_codes

    # Query with mask=0x04 — pending only
    pending = client.read_dtcs(status_mask=DTCStatus.PENDING_DTC)
    pending_codes = {d["code"] for d in pending}
    assert int(DTCCode.NAVIGATION_ANTENNA_FAULT) in pending_codes
    assert int(DTCCode.AUDIO_HARDWARE_FAULT)     not in pending_codes
```
Status byte breakdown:
```
Status byte 0x09 = 0b00001001
                         ||||
                         |||+-- bit 0: TEST_FAILED         (currently failing)
                         ||+--- bit 1: TEST_FAILED_THIS_CYCLE
                         |+---- bit 2: PENDING_DTC
                         +----- bit 3: CONFIRMED_DTC       (debounce passed)
```
Clear and verify — always in one test:
```python
def test_tc03_clear_all_dtcs(self, client, ecu):
    ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT)
    ecu.inject_dtc(DTCCode.OVERVOLTAGE_FAULT)

    assert client.read_dtc_count(0xFF) == 2

    client.clear_dtcs(group=0xFFFFFF)   # 0xFFFFFF = clear all groups

    # Always verify after clear — never assume it worked
    assert client.read_dtc_count(0xFF) == 0
    assert len(ecu.state.dtcs) == 0
```
**Test	Validates
`test_tc03_no_dtcs_on_clean_ecu`	Fresh ECU returns count = 0
`test_tc03_inject_and_read_single_dtc`	DTC code and status byte match injected values
`test_tc03_multiple_dtcs_all_returned`	Three injected faults all appear in 0x19 0x02 response
`test_tc03_status_mask_filtering`	0xFF all; 0x08 confirmed only; 0x04 pending only
`test_tc03_clear_all_dtcs`	0x14 0xFF 0xFF 0xFF clears all, count verified as 0
`test_tc03_dtc_status_bits_correct`	TEST_FAILED, CONFIRMED_DTC, WARNING_INDICATOR bits verified
---**
How this connects to real hardware
The only change needed to run against a physical ECU is replacing the TCP socket in `uds_client.py` with a `udsoncan` + `python-can` connection over CAN or DoIP over Ethernet.
```python
# This project — simulated ECU over TCP
with UDSClient(host="127.0.0.1", port=13400) as client:
    client.set_session(DiagSession.EXTENDED)
    client.unlock_security()
    vin = client.read_did_str(DID.VIN)
```
```python
# Real hardware — Vector CANalyzer over CAN + ISO-TP
import can, udsoncan
from udsoncan.connections import PythonIsoTpConnection

bus  = can.Bus(interface="vector", channel=0, bitrate=500_000)
conn = PythonIsoTpConnection(bus, rxid=0x7E8, txid=0x7DF)

config = {
    "exception_on_negative_response": True,
    "security_algo": my_seed_key_function,
    "p2_timeout": 1,
    "p2_star_timeout": 5,
}

with udsoncan.Client(conn, config=config) as client:
    client.change_session(
        udsoncan.services.DiagnosticSessionControl.Session.extendedDiagnosticSession
    )
    client.unlock_security_access(level=1)
    result = client.read_data_by_identifier(0xF190)
    vin = result.service_data.values[0xF190].raw_value.decode()
```
---
Test results
```
============================= test session starts ==============================
collected 20 items

tests/test_uds_diagnostics.py::TestSessionControl::test_tc01_default_session_on_startup            PASSED
tests/test_uds_diagnostics.py::TestSessionControl::test_tc01_transition_to_extended_session        PASSED
tests/test_uds_diagnostics.py::TestSessionControl::test_tc01_coding_did_blocked_in_default_session PASSED
tests/test_uds_diagnostics.py::TestSessionControl::test_tc01_session_timeout_without_tester_present PASSED
tests/test_uds_diagnostics.py::TestSessionControl::test_tc01_tester_present_keeps_session_alive    PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_read_identification_dids_in_default_session PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_security_access_seed_key_flow           PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_security_access_denied_without_extended_session PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_invalid_key_returns_nrc                 PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_write_coding_did_full_flow              PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_write_did_boundary_values               PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_write_did_blocked_without_security      PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_write_did_blocked_in_default_session    PASSED
tests/test_uds_diagnostics.py::TestReadWriteDID::test_tc02_multiple_coding_dids                    PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_no_dtcs_on_clean_ecu                     PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_inject_and_read_single_dtc               PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_multiple_dtcs_all_returned               PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_status_mask_filtering                    PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_clear_all_dtcs                           PASSED
tests/test_uds_diagnostics.py::TestDTCHandling::test_tc03_dtc_status_bits_correct                  PASSED

============================== 20 passed in 1.57s ==============================
```
---
**Tech stack
Tool	Purpose
`python-can`	CAN bus abstraction (Vector, PCAN, SocketCAN, virtual)
`udsoncan`	UDS ISO 14229 diagnostic client over CAN
`pytest`	Test runner with session and function scoped fixtures
`pytest-html`	HTML test report generation
TCP sockets	Transport layer for the simulated ECU (replaces CAN / DoIP in hardware setup)
---**
