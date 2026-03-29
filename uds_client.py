"""
UDS Client
==========
High-level client that wraps the raw UDS protocol into typed Python methods.
Used by test cases to communicate with the ECU.

Transport: TCP socket (same framing as MockECU)
Real project: replace with udsoncan + python-can + isotp

Example usage:
    with UDSClient() as client:
        client.set_session(DiagSession.EXTENDED)
        client.unlock_security()
        client.write_did(DID.AUDIO_VOLUME_CODING, bytes([90]))
"""

import logging
import socket
import struct
import time

from services.uds_constants import (
    SID, NRC, DID, DiagSession, SecurityLevel, ResetType,
    DTCSubFunction, NEGATIVE_RESPONSE_SID, compute_key,
)

log = logging.getLogger("UDSClient")


class UDSNegativeResponse(Exception):
    """Raised when the ECU returns a 0x7F negative response."""
    def __init__(self, service_id: int, nrc_code: int):
        self.service_id = service_id
        self.nrc_code   = nrc_code
        try:
            nrc_name = NRC(nrc_code).name
        except ValueError:
            nrc_name = f"0x{nrc_code:02X}"
        super().__init__(
            f"NRC for SID 0x{service_id:02X}: {nrc_name} (0x{nrc_code:02X})"
        )


class UDSClient:
    """
    Typed UDS client over TCP.
    Use as a context manager or call connect()/disconnect() manually.
    """

    DEFAULT_TIMEOUT = 3.0

    def __init__(self, host: str = "127.0.0.1", port: int = 13400):
        self.host = host
        self.port = port
        self._sock = None

    # ── Connection ─────────────────────────────────────────────────────────────
    def connect(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.DEFAULT_TIMEOUT)
        self._sock.connect((self.host, self.port))
        log.info("UDSClient connected → %s:%d", self.host, self.port)

    def disconnect(self):
        if self._sock:
            self._sock.close()
            self._sock = None
        log.info("UDSClient disconnected")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── Raw request/response ───────────────────────────────────────────────────
    def _send(self, payload: bytes) -> bytes:
        """Send a UDS request, receive and validate the response."""
        frame = struct.pack("!H", len(payload)) + payload
        self._sock.sendall(frame)
        log.debug("→ %s", payload.hex())

        # Read response frame
        hdr = self._recvall(2)
        length = struct.unpack("!H", hdr)[0]
        resp = self._recvall(length)
        log.debug("← %s", resp.hex())

        if not resp:
            raise ConnectionError("Empty response from ECU")

        # Suppress-positive-response returns empty — that's OK
        if len(resp) == 0:
            return resp

        # Check for negative response
        if resp[0] == NEGATIVE_RESPONSE_SID:
            if len(resp) < 3:
                raise ConnectionError(f"Malformed NRC: {resp.hex()}")
            raise UDSNegativeResponse(resp[1], resp[2])

        return resp

    def _recvall(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed by ECU")
            buf += chunk
        return buf

    # ── 0x10  Diagnostic Session Control ──────────────────────────────────────
    def set_session(self, session: DiagSession) -> bytes:
        """Switch to the specified diagnostic session."""
        resp = self._send(bytes([SID.DIAGNOSTIC_SESSION_CONTROL, int(session)]))
        log.info("Session → %s", session.name)
        return resp

    # ── 0x3E  Tester Present ───────────────────────────────────────────────────
    def tester_present(self, suppress_response: bool = False):
        """Send TesterPresent to keep the current session alive."""
        sub = 0x80 if suppress_response else 0x00
        if not suppress_response:
            self._send(bytes([SID.TESTER_PRESENT, sub]))
        else:
            frame = struct.pack("!H", 2) + bytes([SID.TESTER_PRESENT, sub])
            self._sock.sendall(frame)

    # ── 0x27  Security Access ──────────────────────────────────────────────────
    def unlock_security(self, level: SecurityLevel = SecurityLevel.REQUEST_SEED_L1) -> bool:
        """
        Perform the full seed-key exchange to unlock security access.
        Returns True on success, raises UDSNegativeResponse on failure.
        """
        seed_resp = self._send(bytes([SID.SECURITY_ACCESS, int(level)]))
        seed = (seed_resp[2] << 8) | seed_resp[3]
        log.info("SecurityAccess: received seed=0x%04X", seed)

        key = compute_key(seed)
        log.info("SecurityAccess: sending key=0x%04X", key)

        send_key_level = level + 1
        self._send(bytes([
            SID.SECURITY_ACCESS,
            send_key_level,
            (key >> 8) & 0xFF,
            key & 0xFF,
        ]))
        log.info("SecurityAccess: UNLOCKED")
        return True

    # ── 0x22  Read Data By Identifier ─────────────────────────────────────────
    def read_did(self, did: DID | int) -> bytes:
        """
        Read a DID from the ECU.
        Returns the raw value bytes (DID prefix stripped).
        """
        did_int = int(did)
        resp = self._send(bytes([
            SID.READ_DATA_BY_IDENTIFIER,
            (did_int >> 8) & 0xFF,
            did_int & 0xFF,
        ]))
        # resp: [positive SID] [DID high] [DID low] [value...]
        return resp[3:]

    def read_did_str(self, did: DID | int) -> str:
        """Read a DID that contains an ASCII string."""
        return self.read_did(did).decode("ascii", errors="replace")

    def read_did_byte(self, did: DID | int) -> int:
        """Read a single-byte DID value."""
        return self.read_did(did)[0]

    def read_did_uint16(self, did: DID | int) -> int:
        """Read a 2-byte big-endian DID value."""
        return struct.unpack("!H", self.read_did(did)[:2])[0]

    # ── 0x2E  Write Data By Identifier ────────────────────────────────────────
    def write_did(self, did: DID | int, value: bytes):
        """Write a value to a DID. Requires extended session + security unlock."""
        did_int = int(did)
        self._send(bytes([
            SID.WRITE_DATA_BY_IDENTIFIER,
            (did_int >> 8) & 0xFF,
            did_int & 0xFF,
        ]) + value)
        log.info("Write DID 0x%04X = %s", did_int, value.hex())

    # ── 0x19  Read DTC Information ─────────────────────────────────────────────
    def read_dtc_count(self, status_mask: int = 0xFF) -> int:
        """Return the number of DTCs matching the given status mask."""
        resp = self._send(bytes([
            SID.READ_DTC_INFORMATION,
            DTCSubFunction.REPORT_NUMBER_OF_DTC_BY_STATUS_MASK,
            status_mask,
        ]))
        # resp: [pos SID] [sub] [status_mask] [format] [count_high] [count_low]
        return (resp[4] << 8) | resp[5]

    def read_dtcs(self, status_mask: int = 0xFF) -> list[dict]:
        """
        Return list of DTCs matching status_mask.
        Each entry: {'code': int, 'status': int}
        """
        resp = self._send(bytes([
            SID.READ_DTC_INFORMATION,
            DTCSubFunction.REPORT_DTC_BY_STATUS_MASK,
            status_mask,
        ]))
        # resp: [pos SID] [sub] [status_mask] [DTC0 byte2 byte1 byte0 status] ...
        dtcs = []
        i = 3   # skip positive SID + sub + mask
        while i + 3 < len(resp):
            code   = (resp[i] << 16) | (resp[i+1] << 8) | resp[i+2]
            status = resp[i+3]
            dtcs.append({"code": code, "status": status})
            i += 4
        return dtcs

    # ── 0x14  Clear DTC Information ───────────────────────────────────────────
    def clear_dtcs(self, group: int = 0xFFFFFF):
        """Clear DTCs. Default group 0xFFFFFF clears all."""
        self._send(bytes([
            SID.CLEAR_DTC_INFORMATION,
            (group >> 16) & 0xFF,
            (group >> 8)  & 0xFF,
            group         & 0xFF,
        ]))
        log.info("ClearDTC group=0x%06X", group)

    # ── 0x11  ECU Reset ────────────────────────────────────────────────────────
    def ecu_reset(self, reset_type: ResetType = ResetType.HARD_RESET):
        """Trigger an ECU reset."""
        self._send(bytes([SID.ECU_RESET, int(reset_type)]))
        log.info("ECUReset type=%s", reset_type.name)
        time.sleep(0.05)   # brief pause to let ECU reinitialise
