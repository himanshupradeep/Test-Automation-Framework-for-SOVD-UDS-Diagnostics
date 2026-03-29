"""
UDS Diagnostics Test Suite — ISO 14229
=======================================
Three test classes covering the core UDS services:

  TC_01  Diagnostic Session Control  (0x10) + Tester Present (0x3E)
  TC_02  Security Access (0x27) + Read/Write DID (0x22 / 0x2E)
  TC_03  DTC Handling — Read (0x19) + Clear (0x14)

Test structure per case:
  1. Precondition  — verify ECU is in a known state
  2. Action        — send UDS request(s)
  3. Verify        — assert response + ECU internal state
  4. Postcondition — handled by fixture reset in conftest.py
"""

import pytest

from services.uds_constants import (
    SID, NRC, DID, DiagSession, SecurityLevel, ResetType,
    DTCCode, DTCStatus, compute_key,
)
from services.uds_client import UDSClient, UDSNegativeResponse


# ═══════════════════════════════════════════════════════════════════════════════
# TC_01  DIAGNOSTIC SESSION CONTROL + TESTER PRESENT
# ═══════════════════════════════════════════════════════════════════════════════

class TestSessionControl:
    """
    Verifies UDS Session Control (0x10) and Tester Present (0x3E).

    Requirements covered
    --------------------
    REQ-SESS-001: ECU shall start in Default session after power-on / reset
    REQ-SESS-002: ECU shall accept transition to Extended session via 0x10 0x03
    REQ-SESS-003: Coding DIDs shall be inaccessible in Default session (NRC 0x22)
    REQ-SESS-004: ECU shall return to Default session after TesterPresent timeout
    REQ-SESS-005: TesterPresent shall refresh the session keep-alive timer
    """

    def test_tc01_default_session_on_startup(self, client: UDSClient, ecu):
        """
        TC_01_A  ECU starts in Default session
        ----------------------------------------
        Precondition : ECU just powered on (fixture default)
        Action       : Read active session DID 0xF186
        Verify       : Returns DiagSession.DEFAULT (0x01)
        """
        # Precondition — fixture guarantees DEFAULT
        assert ecu.state.session == DiagSession.DEFAULT

        # Action — read DID 0xF186 = "active session" identifier
        session_byte = client.read_did_byte(DID.ACTIVE_SESSION)

        # Verify
        assert session_byte == int(DiagSession.DEFAULT), (
            f"Expected DEFAULT (0x01), got 0x{session_byte:02X}"
        )

    def test_tc01_transition_to_extended_session(self, client: UDSClient, ecu):
        """
        TC_01_B  Transition Default → Extended
        ----------------------------------------
        Precondition : session = DEFAULT
        Action       : 0x10 0x03 (extended)
        Verify       : Response 0x50 0x03, ECU state = EXTENDED
        """
        assert ecu.state.session == DiagSession.DEFAULT

        resp = client.set_session(DiagSession.EXTENDED)

        # Positive response SID = 0x10 + 0x40 = 0x50
        assert resp[0] == SID.positive(SID.DIAGNOSTIC_SESSION_CONTROL)
        assert resp[1] == int(DiagSession.EXTENDED)
        assert ecu.state.session == DiagSession.EXTENDED

    def test_tc01_coding_did_blocked_in_default_session(self, client: UDSClient):
        """
        TC_01_C  Coding DID inaccessible in Default session
        ------------------------------------------------------
        Try reading a coding DID in Default → must get NRC 0x22 Conditions not correct
        This is the classic "session restriction" negative test.
        """
        with pytest.raises(UDSNegativeResponse) as exc_info:
            client.read_did(DID.AUDIO_VOLUME_CODING)

        assert exc_info.value.nrc_code == NRC.CONDITIONS_NOT_CORRECT, (
            f"Expected 0x22, got 0x{exc_info.value.nrc_code:02X}"
        )

    def test_tc01_session_timeout_without_tester_present(self, client: UDSClient, ecu):
        """
        TC_01_D  Session timeout — ECU falls back to Default
        -------------------------------------------------------
        Precondition : session = EXTENDED
        Action       : Do NOT send TesterPresent for > session_timeout seconds
        Verify       : ECU returns to DEFAULT session, coding DID blocked again

        Note: session_timeout is set to 5s by default.
              We temporarily shorten it to 0.2s for test speed.
        """
        client.set_session(DiagSession.EXTENDED)
        assert ecu.state.session == DiagSession.EXTENDED

        # Shorten timeout for test speed
        original_timeout = ecu.state.session_timeout
        ecu.state.session_timeout = 0.2

        import time
        time.sleep(0.4)   # wait longer than timeout

        # The ECU checks timeout on every incoming request
        # Trigger the check by sending a request
        with pytest.raises(UDSNegativeResponse) as exc_info:
            client.read_did(DID.AUDIO_VOLUME_CODING)

        ecu.state.session_timeout = original_timeout   # restore

        assert ecu.state.session == DiagSession.DEFAULT
        assert exc_info.value.nrc_code == NRC.CONDITIONS_NOT_CORRECT

    def test_tc01_tester_present_keeps_session_alive(self, client: UDSClient, ecu):
        """
        TC_01_E  TesterPresent refreshes keep-alive timer
        ----------------------------------------------------
        Precondition : session = EXTENDED
        Action       : Send TesterPresent before timeout; wait; read coding DID
        Verify       : Session still EXTENDED — coding DID readable
        """
        original_timeout = ecu.state.session_timeout
        ecu.state.session_timeout = 0.3

        client.set_session(DiagSession.EXTENDED)

        import time
        time.sleep(0.15)
        client.tester_present()       # refresh the timer
        time.sleep(0.15)
        client.tester_present()       # refresh again

        # Coding DID should still work — session is alive
        val = client.read_did_byte(DID.AUDIO_VOLUME_CODING)
        assert val == ecu.state.audio_volume_max

        ecu.state.session_timeout = original_timeout


# ═══════════════════════════════════════════════════════════════════════════════
# TC_02  SECURITY ACCESS + READ/WRITE DID
# ═══════════════════════════════════════════════════════════════════════════════

class TestReadWriteDID:
    """
    Verifies Security Access (0x27), Read DID (0x22), Write DID (0x2E).

    Requirements covered
    --------------------
    REQ-DID-001: Identification DIDs (VIN, SW version) readable in all sessions
    REQ-DID-002: Coding DIDs require Extended session to read
    REQ-DID-003: Coding DIDs require Extended session + security unlock to write
    REQ-DID-004: Write shall be rejected with NRC 0x31 for out-of-range values
    REQ-DID-005: Security access seed-key must match OEM algorithm
    REQ-DID-006: Three failed key attempts lock the ECU for 10 seconds
    """

    def test_tc02_read_identification_dids_in_default_session(self, client: UDSClient, ecu):
        """
        TC_02_A  Identification DIDs readable in Default session
        ----------------------------------------------------------
        Precondition : session = DEFAULT
        Verify       : VIN, SW version, HW version readable — no session restriction
        """
        vin = client.read_did_str(DID.VIN)
        assert vin == ecu.state.vin, f"VIN mismatch: {vin!r}"
        assert len(vin) == 17, "VIN must be exactly 17 characters"

        sw  = client.read_did_str(DID.SOFTWARE_VERSION)
        assert sw == ecu.state.sw_version

        hw  = client.read_did_str(DID.ECU_HARDWARE_VERSION)
        assert hw == ecu.state.hw_version

    def test_tc02_security_access_seed_key_flow(self, client: UDSClient, ecu):
        """
        TC_02_B  Full security access unlock sequence
        -----------------------------------------------
        Precondition : session = DEFAULT, security_unlocked = False
        Step 1       : Enter extended session
        Step 2       : Request seed (0x27 0x01) → receive seed
        Step 3       : Compute key, send (0x27 0x02) → UNLOCKED
        Verify       : ecu.state.security_unlocked == True
        """
        assert not ecu.state.security_unlocked

        # Must be in extended session first
        client.set_session(DiagSession.EXTENDED)

        result = client.unlock_security()

        assert result is True
        assert ecu.state.security_unlocked is True

    def test_tc02_security_access_denied_without_extended_session(self, client: UDSClient):
        """
        TC_02_C  Security access rejected in Default session
        -------------------------------------------------------
        Requesting a seed in Default session → NRC 0x22 Conditions not correct
        """
        with pytest.raises(UDSNegativeResponse) as exc_info:
            client.unlock_security()

        assert exc_info.value.nrc_code == NRC.CONDITIONS_NOT_CORRECT

    def test_tc02_invalid_key_returns_nrc(self, client: UDSClient, ecu):
        """
        TC_02_D  Wrong key returns NRC 0x35 Invalid Key
        --------------------------------------------------
        Manually send wrong key after requesting seed.
        """
        import struct
        client.set_session(DiagSession.EXTENDED)

        # Request seed
        seed_resp = client._send(bytes([SID.SECURITY_ACCESS, SecurityLevel.REQUEST_SEED_L1]))
        seed = (seed_resp[2] << 8) | seed_resp[3]

        # Send a deliberately wrong key
        wrong_key = compute_key(seed) ^ 0x1234

        with pytest.raises(UDSNegativeResponse) as exc_info:
            client._send(bytes([
                SID.SECURITY_ACCESS,
                SecurityLevel.SEND_KEY_L1,
                (wrong_key >> 8) & 0xFF,
                wrong_key & 0xFF,
            ]))

        assert exc_info.value.nrc_code == NRC.INVALID_KEY

    def test_tc02_write_coding_did_full_flow(self, extended_client: UDSClient, ecu):
        """
        TC_02_E  Write coding DID — full success flow
        -----------------------------------------------
        Precondition : extended session + security unlocked (extended_client fixture)
        Action       : Write AUDIO_VOLUME_CODING = 90
        Verify       : Read back = 90, ECU internal state = 90
        """
        assert ecu.state.security_unlocked is True

        # Write
        extended_client.write_did(DID.AUDIO_VOLUME_CODING, bytes([90]))

        # Verify read-back
        val = extended_client.read_did_byte(DID.AUDIO_VOLUME_CODING)
        assert val == 90

        # Verify ECU internal state
        assert ecu.state.audio_volume_max == 90

    def test_tc02_write_did_boundary_values(self, extended_client: UDSClient, ecu):
        """
        TC_02_F  Write DID boundary value analysis
        -------------------------------------------
        Audio volume: valid range 0-100
          0   → accept
          100 → accept
          101 → NRC 0x31 Request out of range
        """
        for valid_val in (0, 50, 100):
            extended_client.write_did(DID.AUDIO_VOLUME_CODING, bytes([valid_val]))
            assert extended_client.read_did_byte(DID.AUDIO_VOLUME_CODING) == valid_val

        # Out of range → reject
        with pytest.raises(UDSNegativeResponse) as exc_info:
            extended_client.write_did(DID.AUDIO_VOLUME_CODING, bytes([101]))

        assert exc_info.value.nrc_code == NRC.REQUEST_OUT_OF_RANGE

    def test_tc02_write_did_blocked_without_security(self, client: UDSClient):
        """
        TC_02_G  Write DID rejected without security unlock
        ------------------------------------------------------
        Extended session but NO security → NRC 0x33 Security Access Denied
        """
        client.set_session(DiagSession.EXTENDED)
        # Do NOT call unlock_security()

        with pytest.raises(UDSNegativeResponse) as exc_info:
            client.write_did(DID.AUDIO_VOLUME_CODING, bytes([50]))

        assert exc_info.value.nrc_code == NRC.SECURITY_ACCESS_DENIED

    def test_tc02_write_did_blocked_in_default_session(self, client: UDSClient):
        """
        TC_02_H  Write DID rejected in Default session
        ------------------------------------------------
        Default session → NRC 0x22 Conditions not correct (session check before security)
        """
        with pytest.raises(UDSNegativeResponse) as exc_info:
            client.write_did(DID.AUDIO_VOLUME_CODING, bytes([50]))

        assert exc_info.value.nrc_code == NRC.CONDITIONS_NOT_CORRECT

    def test_tc02_multiple_coding_dids(self, extended_client: UDSClient, ecu):
        """
        TC_02_I  Write and read-back multiple coding DIDs
        ---------------------------------------------------
        Verifies the ECU correctly handles writes to different DIDs independently.
        """
        extended_client.write_did(DID.DISPLAY_BRIGHTNESS_CODING, bytes([55]))
        extended_client.write_did(DID.LANGUAGE_CODING,            bytes([0x02]))  # German
        import struct
        extended_client.write_did(DID.SPEED_LIMIT_ADAPTATION, struct.pack("!H", 180))

        assert extended_client.read_did_byte(DID.DISPLAY_BRIGHTNESS_CODING) == 55
        assert extended_client.read_did_byte(DID.LANGUAGE_CODING)           == 0x02
        assert extended_client.read_did_uint16(DID.SPEED_LIMIT_ADAPTATION)  == 180

        assert ecu.state.display_brightness == 55
        assert ecu.state.language_code      == 0x02
        assert ecu.state.speed_limit_kmh    == 180


# ═══════════════════════════════════════════════════════════════════════════════
# TC_03  DTC HANDLING — READ + CLEAR
# ═══════════════════════════════════════════════════════════════════════════════

class TestDTCHandling:
    """
    Verifies ReadDTCInformation (0x19) and ClearDiagnosticInformation (0x14).

    Requirements covered
    --------------------
    REQ-DTC-001: ECU shall report stored DTCs via 0x19 with correct status bytes
    REQ-DTC-002: DTC count shall match number of stored faults
    REQ-DTC-003: Status mask filtering shall return only matching DTCs
    REQ-DTC-004: 0x14 with group 0xFFFFFF shall clear all stored DTCs
    REQ-DTC-005: After clearing, DTC count shall be zero
    REQ-DTC-006: Confirmed DTC shall have status bit 3 (0x08) set
    """

    def test_tc03_no_dtcs_on_clean_ecu(self, client: UDSClient, ecu):
        """
        TC_03_A  Zero DTCs on a freshly reset ECU
        -------------------------------------------
        Precondition : No faults injected (fixture default)
        Verify       : DTC count = 0
        """
        assert len(ecu.state.dtcs) == 0

        count = client.read_dtc_count(status_mask=0xFF)
        assert count == 0, f"Expected 0 DTCs, got {count}"

    def test_tc03_inject_and_read_single_dtc(self, client: UDSClient, ecu):
        """
        TC_03_B  Inject one DTC and verify it appears in fault memory
        ---------------------------------------------------------------
        Precondition : No faults
        Action       : Inject AUDIO_HARDWARE_FAULT (confirmed + failed)
        Verify       : ReadDTC returns exactly 1 DTC with correct code + status
        """
        # Inject
        status = DTCStatus.CONFIRMED_DTC | DTCStatus.TEST_FAILED
        ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT, status)

        # Read count
        count = client.read_dtc_count(status_mask=0xFF)
        assert count == 1

        # Read full list
        dtcs = client.read_dtcs(status_mask=0xFF)
        assert len(dtcs) == 1

        dtc = dtcs[0]
        assert dtc["code"]   == int(DTCCode.AUDIO_HARDWARE_FAULT), \
            f"Wrong DTC code: 0x{dtc['code']:06X}"
        assert dtc["status"] == status, \
            f"Wrong status: 0x{dtc['status']:02X}"

    def test_tc03_multiple_dtcs_all_returned(self, client: UDSClient, ecu):
        """
        TC_03_C  Inject multiple DTCs — all reported
        ----------------------------------------------
        Inject 3 different faults, verify all 3 come back in ReadDTC response.
        """
        ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT,    DTCStatus.CONFIRMED_DTC)
        ecu.inject_dtc(DTCCode.DISPLAY_COMMUNICATION_FAULT, DTCStatus.CONFIRMED_DTC | DTCStatus.WARNING_INDICATOR_REQUESTED)
        ecu.inject_dtc(DTCCode.NAVIGATION_ANTENNA_FAULT, DTCStatus.PENDING_DTC)

        count = client.read_dtc_count(status_mask=0xFF)
        assert count == 3

        dtcs = client.read_dtcs(status_mask=0xFF)
        assert len(dtcs) == 3

        returned_codes = {d["code"] for d in dtcs}
        assert int(DTCCode.AUDIO_HARDWARE_FAULT)         in returned_codes
        assert int(DTCCode.DISPLAY_COMMUNICATION_FAULT)  in returned_codes
        assert int(DTCCode.NAVIGATION_ANTENNA_FAULT)     in returned_codes

    def test_tc03_status_mask_filtering(self, client: UDSClient, ecu):
        """
        TC_03_D  Status mask filters correctly
        ----------------------------------------
        Inject:
          DTC A — status = CONFIRMED (0x08)
          DTC B — status = PENDING   (0x04)

        Query with mask=0x08 (confirmed only) → only DTC A returned
        Query with mask=0x04 (pending only)   → only DTC B returned
        Query with mask=0xFF (all)            → both returned
        """
        ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT,    DTCStatus.CONFIRMED_DTC)
        ecu.inject_dtc(DTCCode.NAVIGATION_ANTENNA_FAULT, DTCStatus.PENDING_DTC)

        # Confirmed only
        confirmed = client.read_dtcs(status_mask=DTCStatus.CONFIRMED_DTC)
        confirmed_codes = {d["code"] for d in confirmed}
        assert int(DTCCode.AUDIO_HARDWARE_FAULT)      in confirmed_codes
        assert int(DTCCode.NAVIGATION_ANTENNA_FAULT) not in confirmed_codes

        # Pending only
        pending = client.read_dtcs(status_mask=DTCStatus.PENDING_DTC)
        pending_codes = {d["code"] for d in pending}
        assert int(DTCCode.NAVIGATION_ANTENNA_FAULT) in pending_codes
        assert int(DTCCode.AUDIO_HARDWARE_FAULT)     not in pending_codes

        # All
        all_dtcs = client.read_dtcs(status_mask=0xFF)
        assert len(all_dtcs) == 2

    def test_tc03_clear_all_dtcs(self, client: UDSClient, ecu):
        """
        TC_03_E  Clear all DTCs with group 0xFFFFFF
        ---------------------------------------------
        Precondition : 2 faults injected
        Action       : 0x14 FF FF FF
        Verify       : DTC count = 0 after clear
        """
        ecu.inject_dtc(DTCCode.AUDIO_HARDWARE_FAULT)
        ecu.inject_dtc(DTCCode.OVERVOLTAGE_FAULT)

        assert client.read_dtc_count(0xFF) == 2

        # Clear all
        client.clear_dtcs(group=0xFFFFFF)

        # Verify
        count_after = client.read_dtc_count(0xFF)
        assert count_after == 0, f"Expected 0 DTCs after clear, got {count_after}"
        assert len(ecu.state.dtcs) == 0

    def test_tc03_dtc_status_bits_correct(self, client: UDSClient, ecu):
        """
        TC_03_F  DTC status byte bits match injected values
        -----------------------------------------------------
        Verify individual status bits:
          bit 0 (0x01) = TEST_FAILED       — currently failing
          bit 3 (0x08) = CONFIRMED_DTC     — debounce passed
          bit 7 (0x80) = WARNING_INDICATOR — MIL / warning lamp on
        """
        full_status = (
            DTCStatus.TEST_FAILED |
            DTCStatus.CONFIRMED_DTC |
            DTCStatus.WARNING_INDICATOR_REQUESTED
        )
        ecu.inject_dtc(DTCCode.DISPLAY_COMMUNICATION_FAULT, full_status)

        dtcs = client.read_dtcs(status_mask=0xFF)
        assert len(dtcs) == 1

        status = dtcs[0]["status"]

        assert status & DTCStatus.TEST_FAILED,              "TEST_FAILED bit not set"
        assert status & DTCStatus.CONFIRMED_DTC,            "CONFIRMED_DTC bit not set"
        assert status & DTCStatus.WARNING_INDICATOR_REQUESTED, "WARNING_INDICATOR bit not set"
        assert not (status & DTCStatus.PENDING_DTC),        "PENDING_DTC should NOT be set"
