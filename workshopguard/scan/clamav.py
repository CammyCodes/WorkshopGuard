"""ClamAV over clamd's TCP INSTREAM protocol (the clamav/clamav container in docker-compose)."""

from __future__ import annotations

import logging
import socket
import struct
import time

log = logging.getLogger(__name__)
CHUNK = 1 << 20


class ClamAV:
    def __init__(self, host: str, port: int = 3310, max_bytes: int = 95 * 1024 * 1024):
        self.host, self.port, self.max_bytes = host, port, max_bytes

    def _conn(self, timeout: float = 120) -> socket.socket:
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        return s

    def ping(self) -> bool:
        try:
            with self._conn(5) as s:
                s.sendall(b"zPING\0")
                return s.recv(16).startswith(b"PONG")
        except OSError:
            return False

    def version(self) -> str:
        try:
            with self._conn(5) as s:
                s.sendall(b"zVERSION\0")
                return s.recv(256).rstrip(b"\0").decode()
        except OSError as e:
            return f"unavailable ({e})"

    def wait_ready(self, seconds: int = 600) -> bool:
        """clamd takes a minute or two to load signatures on first start."""
        end = time.time() + seconds
        while time.time() < end:
            if self.ping():
                return True
            time.sleep(5)
        return False

    def scan_bytes(self, data: bytes) -> str | None:
        """Return the signature name if infected, None if clean. Raises OSError if clamd is unreachable."""
        data = data[: self.max_bytes]
        with self._conn() as s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(data), CHUNK):
                part = data[i:i + CHUNK]
                s.sendall(struct.pack("!L", len(part)) + part)
            s.sendall(struct.pack("!L", 0))
            reply = b""
            while not reply.endswith(b"\0"):
                chunk = s.recv(4096)
                if not chunk:
                    break
                reply += chunk
        text = reply.rstrip(b"\0").decode("utf-8", "replace")
        # "stream: OK" | "stream: Eicar-Signature FOUND" | "INSTREAM size limit exceeded. ERROR"
        if text.endswith("FOUND"):
            return text.split(":", 1)[1].rsplit(" ", 1)[0].strip()
        if "ERROR" in text:
            raise OSError(f"clamd: {text}")
        return None
