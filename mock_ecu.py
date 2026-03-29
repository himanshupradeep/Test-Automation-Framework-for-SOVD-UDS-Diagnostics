"""
Mock Infotainment ECU — UDS Service Provider
=============================================
Simulates an automotive Head Unit ECU responding to UDS (ISO 14229) requests.

Transport: TCP socket (simulates DoIP / ISO-TP in software)
           Real project → python-can + isotp + udsoncan on CAN bus

ECU supports:
  Session Control   (0x10) — Default / Extended sessions
  Security Access   (0x27) — Seed-key, level 1
  Read DID          (0x22) — VIN, SW version, coding values
  Write DID         (0x2E) — Coding values (session + security restricted)
  Read DTC          (0x19) — Fault memory with status bytes
  Clear DTC         (0x14) — Erase fault memory
  Tester Present    (0x3E) — Keep session alive
  ECU Reset         (0x11) — Reboot the ECU

Message framing (over TCP):
  [1 byte length_high] [1 byte length_low] [payload...]
"""

import logging
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from services.uds_constants import (
    SID, NRC, DID, DTCCode, DTCStatus, DiagSession,
    SecurityLevel, ResetType, DTCSubFunction,
    NEGATIVE_RESPONSE_SID, compute_key,
)

log = logging.getLogger("MockECU")


# ── ECU Internal State ─────────────────────────────────────────────────────────
@dataclass
class ECUState:
    # Session
    session: DiagSession = DiagSession.DEFAULT
    last_tester_present: float = field(default_factory=time.monotonic)
    session_timeout: float = 5.0   # seconds before falling back to default

    # Security
    security_unlocked: bool = False
    pending_seed: int = 0
    failed_attempts: int = 0
    lockout_until: float = 0.0

    # Identification data
    vin: str = "WBA12345678901234"
    sw_version: str = "SW_V3.2.1"
    hw_version: str = "HW_V1.4"
    serial_number: str = "SN-99887766"

    # Coding values (writable, session + security protected)
    audio_volume_max: int = 80        # 0-100
    display_brightness: int = 70      # 0-100
    language_code: int = 0x01         # 0x01=EN, 0x02=DE, 0x03=FR
    speed_limit_kmh: int = 130        # 60-250

    # Fault memory
    dtcs: dict = field(default_factory=dict)  # {DTCCode: status_byte}


class MockECU:
    """
    TCP server that speaks UDS.
    Start with  ecu = MockECU(); ecu.start()
    Stop  with  ecu.stop()
    """
    HOST = "127.0.0.1"
    PORT = 13400   # DoIP standard port

    def __init__(self):
        self.state = ECUState()
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.HOST, self.PORT))
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        log.info("MockECU listening on %s:%d", self.HOST, self.PORT)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._sock:
            self._sock.close()
        log.info("MockECU stopped")

    # ── Connection handler ─────────────────────────────────────────────────────
    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                self._check_session_timeout()
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def _handle_conn(self, conn: socket.socket, addr):
        with conn:
            conn.settimeout(2.0)
            while not self._stop.is_set():
                try:
                    raw = self._recv_frame(conn)
                except (ConnectionResetError, TimeoutError, OSError):
                    break
                if not raw:
                    break

                self._check_session_timeout()
                response = self._dispatch(raw)
                if response:
                    self._send_frame(conn, response)

    # ── Framing helpers ───────────────────────────────────────────────────────
    def _recv_frame(self, conn) -> bytes | None:
        hdr = self._recvall(conn, 2)
        if not hdr:
            return None
        length = struct.unpack("!H", hdr)[0]
        return self._recvall(conn, length)

    def _recvall(self, conn, n) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send_frame(self, conn, payload: bytes):
        frame = struct.pack("!H", len(payload)) + payload
        conn.sendall(frame)

    # ── Session timeout check ─────────────────────────────────────────────────
    def _check_session_timeout(self):
        if (
            self.state.session != DiagSession.DEFAULT
            and time.monotonic() - self.state.last_tester_present > self.state.session_timeout
        ):
            log.info("Session timeout → returning to DEFAULT session, security locked")
            self.state.session = DiagSession.DEFAULT
            self.state.security_unlocked = False

    # ── Request dispatcher ─────────────────────────────────────────────────────
    def _dispatch(self, data: bytes) -> bytes:
        if not data:
            return self._nrc(0x00, NRC.INCORRECT_MESSAGE_LENGTH)

        sid = data[0]
        log.debug("REQ SID=0x%02X  session=%s  payload=%s",
                  sid, self.state.session.name, data.hex())

        handlers = {
            SID.DIAGNOSTIC_SESSION_CONTROL: self._handle_session_control,
            SID.TESTER_PRESENT:             self._handle_tester_present,
            SID.SECURITY_ACCESS:            self._handle_security_access,
            SID.READ_DATA_BY_IDENTIFIER:    self._handle_read_did,
            SID.WRITE_DATA_BY_IDENTIFIER:   self._handle_write_did,
            SID.READ_DTC_INFORMATION:       self._handle_read_dtc,
            SID.CLEAR_DTC_INFORMATION:      self._handle_clear_dtc,
            SID.ECU_RESET:                  self._handle_ecu_reset,
        }

        handler = handlers.get(sid)
        if handler is None:
            return self._nrc(sid, NRC.SERVICE_NOT_SUPPORTED)

        return handler(data)

    # ── 0x10  Diagnostic Session Control ──────────────────────────────────────
    def _handle_session_control(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.DIAGNOSTIC_SESSION_CONTROL, NRC.INCORRECT_MESSAGE_LENGTH)

        sub = data[1]
        try:
            new_session = DiagSession(sub)
        except ValueError:
            return self._nrc(SID.DIAGNOSTIC_SESSION_CONTROL, NRC.SUB_FUNCTION_NOT_SUPPORTED)

        self.state.session = new_session
        self.state.last_tester_present = time.monotonic()
        if new_session == DiagSession.DEFAULT:
            self.state.security_unlocked = False

        log.info("Session → %s", new_session.name)
        # Response includes P2/P2* timing parameters (4 bytes)
        return bytes([SID.positive(SID.DIAGNOSTIC_SESSION_CONTROL), sub, 0x00, 0x19, 0x01, 0xF4])

    # ── 0x3E  Tester Present ───────────────────────────────────────────────────
    def _handle_tester_present(self, data: bytes) -> bytes:
        sub = data[1] if len(data) > 1 else 0x00
        self.state.last_tester_present = time.monotonic()
        # sub-function 0x80 = suppress positive response
        if sub & 0x80:
            return b""
        return bytes([SID.positive(SID.TESTER_PRESENT), 0x00])

    # ── 0x27  Security Access ──────────────────────────────────────────────────
    def _handle_security_access(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.SECURITY_ACCESS, NRC.INCORRECT_MESSAGE_LENGTH)

        sub = data[1]

        # Lockout check
        if time.monotonic() < self.state.lockout_until:
            return self._nrc(SID.SECURITY_ACCESS, NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED)

        # Request seed (odd sub-function)
        if sub == SecurityLevel.REQUEST_SEED_L1:
            if self.state.session == DiagSession.DEFAULT:
                return self._nrc(SID.SECURITY_ACCESS, NRC.CONDITIONS_NOT_CORRECT)
            self.state.pending_seed = random.randint(0x1000, 0xFFFF)
            log.info("SecurityAccess: seed=0x%04X", self.state.pending_seed)
            return bytes([
                SID.positive(SID.SECURITY_ACCESS),
                sub,
                (self.state.pending_seed >> 8) & 0xFF,
                self.state.pending_seed & 0xFF,
            ])

        # Send key (even sub-function)
        elif sub == SecurityLevel.SEND_KEY_L1:
            if self.state.pending_seed == 0:
                return self._nrc(SID.SECURITY_ACCESS, NRC.REQUEST_SEQUENCE_ERROR)
            if len(data) < 4:
                return self._nrc(SID.SECURITY_ACCESS, NRC.INCORRECT_MESSAGE_LENGTH)

            received_key = (data[2] << 8) | data[3]
            expected_key = compute_key(self.state.pending_seed)

            if received_key != expected_key:
                self.state.failed_attempts += 1
                self.state.pending_seed = 0
                if self.state.failed_attempts >= 3:
                    self.state.lockout_until = time.monotonic() + 10.0
                    log.warning("SecurityAccess: LOCKED OUT after %d failed attempts",
                                self.state.failed_attempts)
                    return self._nrc(SID.SECURITY_ACCESS, NRC.EXCEED_NUMBER_OF_ATTEMPTS)
                log.warning("SecurityAccess: invalid key (attempt %d)", self.state.failed_attempts)
                return self._nrc(SID.SECURITY_ACCESS, NRC.INVALID_KEY)

            self.state.security_unlocked = True
            self.state.failed_attempts = 0
            self.state.pending_seed = 0
            log.info("SecurityAccess: UNLOCKED")
            return bytes([SID.positive(SID.SECURITY_ACCESS), sub])

        return self._nrc(SID.SECURITY_ACCESS, NRC.SUB_FUNCTION_NOT_SUPPORTED)

    # ── 0x22  Read Data By Identifier ─────────────────────────────────────────
    def _handle_read_did(self, data: bytes) -> bytes:
        if len(data) < 3:
            return self._nrc(SID.READ_DATA_BY_IDENTIFIER, NRC.INCORRECT_MESSAGE_LENGTH)

        did = (data[1] << 8) | data[2]

        # Identification DIDs — available in all sessions
        if did == DID.VIN:
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF]) + self.state.vin.encode())
        elif did == DID.SOFTWARE_VERSION:
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF]) + self.state.sw_version.encode())
        elif did == DID.ECU_HARDWARE_VERSION:
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF]) + self.state.hw_version.encode())
        elif did == DID.ECU_SERIAL_NUMBER:
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF]) + self.state.serial_number.encode())
        elif did == DID.ACTIVE_SESSION:
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF, int(self.state.session)]))

        # Coding DIDs — only available in extended session
        coding_map = {
            DID.AUDIO_VOLUME_CODING:     lambda: bytes([self.state.audio_volume_max]),
            DID.DISPLAY_BRIGHTNESS_CODING: lambda: bytes([self.state.display_brightness]),
            DID.LANGUAGE_CODING:         lambda: bytes([self.state.language_code]),
            DID.SPEED_LIMIT_ADAPTATION:  lambda: struct.pack("!H", self.state.speed_limit_kmh),
        }

        if did in coding_map:
            if self.state.session == DiagSession.DEFAULT:
                return self._nrc(SID.READ_DATA_BY_IDENTIFIER, NRC.CONDITIONS_NOT_CORRECT)
            value = coding_map[did]()
            return self._pos(SID.READ_DATA_BY_IDENTIFIER,
                             bytes([did >> 8, did & 0xFF]) + value)

        return self._nrc(SID.READ_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)

    # ── 0x2E  Write Data By Identifier ────────────────────────────────────────
    def _handle_write_did(self, data: bytes) -> bytes:
        if len(data) < 4:
            return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.INCORRECT_MESSAGE_LENGTH)

        did = (data[1] << 8) | data[2]
        value_bytes = data[3:]

        # All writes require extended session
        if self.state.session == DiagSession.DEFAULT:
            return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.CONDITIONS_NOT_CORRECT)

        # All writes require security unlock
        if not self.state.security_unlocked:
            return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.SECURITY_ACCESS_DENIED)

        if did == DID.AUDIO_VOLUME_CODING:
            val = value_bytes[0]
            if not 0 <= val <= 100:
                return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)
            self.state.audio_volume_max = val
            log.info("Write DID 0x%04X: audio_volume_max = %d", did, val)

        elif did == DID.DISPLAY_BRIGHTNESS_CODING:
            val = value_bytes[0]
            if not 0 <= val <= 100:
                return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)
            self.state.display_brightness = val
            log.info("Write DID 0x%04X: display_brightness = %d", did, val)

        elif did == DID.LANGUAGE_CODING:
            val = value_bytes[0]
            if val not in (0x01, 0x02, 0x03):
                return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)
            self.state.language_code = val
            log.info("Write DID 0x%04X: language = 0x%02X", did, val)

        elif did == DID.SPEED_LIMIT_ADAPTATION:
            if len(value_bytes) < 2:
                return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.INCORRECT_MESSAGE_LENGTH)
            val = struct.unpack("!H", value_bytes[:2])[0]
            if not 60 <= val <= 250:
                return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)
            self.state.speed_limit_kmh = val
            log.info("Write DID 0x%04X: speed_limit = %d km/h", did, val)

        else:
            return self._nrc(SID.WRITE_DATA_BY_IDENTIFIER, NRC.REQUEST_OUT_OF_RANGE)

        return self._pos(SID.WRITE_DATA_BY_IDENTIFIER, bytes([did >> 8, did & 0xFF]))

    # ── 0x19  Read DTC Information ─────────────────────────────────────────────
    def _handle_read_dtc(self, data: bytes) -> bytes:
        if len(data) < 3:
            return self._nrc(SID.READ_DTC_INFORMATION, NRC.INCORRECT_MESSAGE_LENGTH)

        sub         = data[1]
        status_mask = data[2]

        # Filter DTCs by status mask
        matching = {
            code: status
            for code, status in self.state.dtcs.items()
            if status & status_mask
        }

        if sub == DTCSubFunction.REPORT_NUMBER_OF_DTC_BY_STATUS_MASK:
            count = len(matching)
            log.info("ReadDTC 0x01: %d DTC(s) matching mask 0x%02X", count, status_mask)
            return self._pos(SID.READ_DTC_INFORMATION,
                             bytes([sub, status_mask, 0x01,   # DTC format = ISO 15031-6
                                    (count >> 8) & 0xFF, count & 0xFF]))

        elif sub == DTCSubFunction.REPORT_DTC_BY_STATUS_MASK:
            log.info("ReadDTC 0x02: returning %d DTC(s)", len(matching))
            payload = bytes([sub, status_mask])
            for dtc_code, status in matching.items():
                # DTC code is 3 bytes (big-endian) + 1 status byte
                payload += struct.pack("!I", int(dtc_code))[1:]  # 3 bytes
                payload += bytes([status])
            return self._pos(SID.READ_DTC_INFORMATION, payload)

        return self._nrc(SID.READ_DTC_INFORMATION, NRC.SUB_FUNCTION_NOT_SUPPORTED)

    # ── 0x14  Clear DTC Information ───────────────────────────────────────────
    def _handle_clear_dtc(self, data: bytes) -> bytes:
        # 3-byte group of DTC: 0xFFFFFF = clear all
        if len(data) < 4:
            return self._nrc(SID.CLEAR_DTC_INFORMATION, NRC.INCORRECT_MESSAGE_LENGTH)

        group = (data[1] << 16) | (data[2] << 8) | data[3]
        if group == 0xFFFFFF:
            count = len(self.state.dtcs)
            self.state.dtcs.clear()
            log.info("ClearDTC: all %d DTC(s) cleared", count)
        else:
            # Clear specific DTC
            self.state.dtcs = {
                k: v for k, v in self.state.dtcs.items()
                if int(k) != group
            }
            log.info("ClearDTC: cleared DTC 0x%06X", group)

        return bytes([SID.positive(SID.CLEAR_DTC_INFORMATION)])

    # ── 0x11  ECU Reset ────────────────────────────────────────────────────────
    def _handle_ecu_reset(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._nrc(SID.ECU_RESET, NRC.INCORRECT_MESSAGE_LENGTH)

        reset_type = data[1]
        log.info("ECUReset type=0x%02X", reset_type)

        # Reset state
        self.state.session = DiagSession.DEFAULT
        self.state.security_unlocked = False
        self.state.pending_seed = 0

        return bytes([SID.positive(SID.ECU_RESET), reset_type])

    # ── Response helpers ───────────────────────────────────────────────────────
    def _pos(self, sid: int, payload: bytes) -> bytes:
        resp = bytes([SID.positive(sid)]) + payload
        log.debug("RESP 0x%02X  %s", SID.positive(sid), resp.hex())
        return resp

    def _nrc(self, sid: int, nrc_code: NRC) -> bytes:
        resp = bytes([NEGATIVE_RESPONSE_SID, sid, int(nrc_code)])
        log.debug("NRC  7F %02X %02X (%s)", sid, int(nrc_code), nrc_code.name)
        return resp

    # ── Test helpers (inject faults from test code) ────────────────────────────
    def inject_dtc(self, dtc: DTCCode, status: int = DTCStatus.CONFIRMED_DTC | DTCStatus.TEST_FAILED):
        """Inject a fault into the ECU's DTC memory (used by test code)."""
        self.state.dtcs[dtc] = status
        log.info("Injected DTC 0x%06X  status=0x%02X", int(dtc), status)

    def clear_all_dtcs(self):
        self.state.dtcs.clear()
