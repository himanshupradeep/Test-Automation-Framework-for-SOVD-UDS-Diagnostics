"""
UDS Protocol Constants — ISO 14229
====================================
Covers all Service IDs, Negative Response Codes, Session Types,
and Data Identifiers used across the test suite.

UDS Message Format:
  Request:           [SID] [sub-function/data...]
  Positive response: [SID + 0x40] [data...]
  Negative response: [0x7F] [requested SID] [NRC]
"""

from enum import IntEnum


# ── Service IDs (SID) ─────────────────────────────────────────────────────────
class SID(IntEnum):
    DIAGNOSTIC_SESSION_CONTROL      = 0x10
    ECU_RESET                       = 0x11
    CLEAR_DTC_INFORMATION           = 0x14
    READ_DTC_INFORMATION            = 0x19
    READ_DATA_BY_IDENTIFIER         = 0x22
    READ_MEMORY_BY_ADDRESS          = 0x23
    SECURITY_ACCESS                 = 0x27
    COMMUNICATION_CONTROL           = 0x28
    WRITE_DATA_BY_IDENTIFIER        = 0x2E
    INPUT_OUTPUT_CONTROL            = 0x2F
    ROUTINE_CONTROL                 = 0x31
    REQUEST_DOWNLOAD                = 0x34
    TRANSFER_DATA                   = 0x36
    REQUEST_TRANSFER_EXIT           = 0x37
    TESTER_PRESENT                  = 0x3E
    CONTROL_DTC_SETTING             = 0x85

    # Positive response = SID + 0x40
    @staticmethod
    def positive(sid: int) -> int:
        return sid + 0x40


# ── Negative Response Code ────────────────────────────────────────────────────
NEGATIVE_RESPONSE_SID = 0x7F


class NRC(IntEnum):
    GENERAL_REJECT                          = 0x10
    SERVICE_NOT_SUPPORTED                   = 0x11
    SUB_FUNCTION_NOT_SUPPORTED              = 0x12
    INCORRECT_MESSAGE_LENGTH                = 0x13
    CONDITIONS_NOT_CORRECT                  = 0x22
    REQUEST_SEQUENCE_ERROR                  = 0x24
    REQUEST_OUT_OF_RANGE                    = 0x31
    SECURITY_ACCESS_DENIED                  = 0x33
    INVALID_KEY                             = 0x35
    EXCEED_NUMBER_OF_ATTEMPTS               = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED         = 0x37
    RESPONSE_PENDING                        = 0x78


# ── Diagnostic Session Sub-functions ─────────────────────────────────────────
class DiagSession(IntEnum):
    DEFAULT             = 0x01   # Normal vehicle operation
    PROGRAMMING         = 0x02   # Flash / software download
    EXTENDED            = 0x03   # Advanced diagnostics, coding


# ── Security Access Levels ────────────────────────────────────────────────────
class SecurityLevel(IntEnum):
    REQUEST_SEED_L1     = 0x01   # Request seed for level 1
    SEND_KEY_L1         = 0x02   # Send computed key for level 1
    REQUEST_SEED_L3     = 0x03   # Request seed for level 3 (programming)
    SEND_KEY_L3         = 0x04   # Send computed key for level 3


# ── ECU Reset Sub-functions ────────────────────────────────────────────────────
class ResetType(IntEnum):
    HARD_RESET          = 0x01
    KEY_OFF_ON_RESET    = 0x02
    SOFT_RESET          = 0x03


# ── ReadDTCInformation Sub-functions ──────────────────────────────────────────
class DTCSubFunction(IntEnum):
    REPORT_NUMBER_OF_DTC_BY_STATUS_MASK = 0x01
    REPORT_DTC_BY_STATUS_MASK           = 0x02
    REPORT_DTC_SNAPSHOT_RECORD          = 0x04
    REPORT_DTC_EXTENDED_DATA            = 0x06


# ── DTC Status Bits ───────────────────────────────────────────────────────────
class DTCStatus(IntEnum):
    TEST_FAILED                 = 0x01   # bit 0: currently failed
    TEST_FAILED_THIS_CYCLE      = 0x02   # bit 1: failed this driving cycle
    PENDING_DTC                 = 0x04   # bit 2: pending (not yet confirmed)
    CONFIRMED_DTC               = 0x08   # bit 3: confirmed fault
    TEST_NOT_COMPLETED_SINCE_CLEAR = 0x10
    TEST_FAILED_SINCE_CLEAR     = 0x20
    TEST_NOT_COMPLETED_THIS_CYCLE  = 0x40
    WARNING_INDICATOR_REQUESTED = 0x80   # bit 7: MIL / warning lamp on


# ── Data Identifiers (DID) ────────────────────────────────────────────────────
class DID(IntEnum):
    # Standardised identification DIDs
    BOOT_SOFTWARE_ID            = 0xF180
    APPLICATION_SOFTWARE_ID     = 0xF181
    APPLICATION_DATA_ID         = 0xF182
    ACTIVE_SESSION              = 0xF186
    SOFTWARE_VERSION            = 0xF189
    VIN                         = 0xF190   # Vehicle Identification Number
    ECU_HARDWARE_VERSION        = 0xF191
    ECU_SERIAL_NUMBER           = 0xF18C

    # OEM-specific (project-defined)
    AUDIO_VOLUME_CODING         = 0x0101   # Coding: max allowed volume
    DISPLAY_BRIGHTNESS_CODING   = 0x0102   # Coding: default brightness 0-100
    LANGUAGE_CODING             = 0x0103   # Coding: UI language selection
    SPEED_LIMIT_ADAPTATION      = 0x0201   # Adaptation: speed warning threshold


# ── Routine Identifiers ───────────────────────────────────────────────────────
class RoutineID(IntEnum):
    ERASE_MEMORY                = 0xFF00
    CHECK_PROGRAMMING_DEPENDENCIES = 0xFF01
    RESET_TO_DEFAULT_VALUES     = 0x0202


# ── DTC Codes (project-specific example fault codes) ─────────────────────────
class DTCCode(IntEnum):
    AUDIO_HARDWARE_FAULT        = 0x012300   # Audio amplifier hardware error
    DISPLAY_COMMUNICATION_FAULT = 0x023400   # Display bus communication error
    NAVIGATION_ANTENNA_FAULT    = 0x034500   # GPS antenna signal fault
    OVERVOLTAGE_FAULT           = 0x045600   # Supply voltage too high


# ── Seed-key algorithm (simplified demo) ─────────────────────────────────────
SECURITY_KEY_MASK = 0xA5A5  # XOR mask — in real OEM projects this is secret

def compute_key(seed: int) -> int:
    """
    Simplified seed-to-key algorithm for demo purposes.
    Real OEM algorithms are proprietary and never published.
    """
    return (seed ^ SECURITY_KEY_MASK) & 0xFFFF
