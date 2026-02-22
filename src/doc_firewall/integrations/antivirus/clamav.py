from __future__ import annotations
import subprocess
import socket
import struct
import os
from typing import Dict, Any
from .base import AntivirusEngine


class ClamAVEngine(AntivirusEngine):
    name = "clamav"

    def __init__(
        self,
        clamscan_path: str = "clamscan",
        host: str | None = None,
        port: int = 3310,
        socket_path: str | None = None,
        extra_args: list[str] | None = None,
    ):
        self.clamscan_path = clamscan_path
        self.host = host
        self.port = port
        self.socket_path = socket_path
        self.extra_args = extra_args or ["--no-summary"]

    _SOCKET_TIMEOUT_SECS = 30

    def _get_socket(self) -> socket.socket:
        if self.socket_path and os.path.exists(self.socket_path):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self._SOCKET_TIMEOUT_SECS)
            sock.connect(self.socket_path)
            return sock
        elif self.host:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._SOCKET_TIMEOUT_SECS)
            sock.connect((self.host, self.port))
            return sock
        raise ValueError(
            "No valid ClamAV connection configured (socket_path or host/port)"
        )

    def _scan_stream(self, path: str) -> str:
        """Scan file by streaming content to ClamAV daemon. Returns raw response."""
        sock = self._get_socket()
        try:
            sock.send(b"zINSTREAM\0")

            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    # Send length (4 bytes big-endian) + data
                    length = struct.pack(">I", len(chunk))
                    sock.send(length)
                    sock.send(chunk)

            # End of stream (length 0)
            sock.send(struct.pack(">I", 0))

            # Read response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                # Typically response ends with \0 or newline
                if b"\0" in response:
                    break

            return response.decode("utf-8", errors="ignore").strip()

        finally:
            sock.close()

    def scan_file(self, path: str) -> Dict[str, Any]:
        # Try daemon connection first if configured
        if self.host or (self.socket_path and os.path.exists(self.socket_path)):
            try:
                out = self._scan_stream(path)
                # Parse response like "stream: OK" or
                # "stream: Eicar-Test-Signature FOUND"
                # Some versions might return just "OK" or "FOUND"
                infected = "FOUND" in out and "OK" not in out
                signature = None

                if infected:
                    # simplistic parsing: look for signature name
                    # Expected format: "stream: <Signature> FOUND"
                    parts = out.replace("stream:", "").replace("FOUND", "").strip()
                    if parts:
                        signature = parts

                return {
                    "infected": infected,
                    "signature": signature,
                    "raw": out,
                    "returncode": 0,
                }
            except (ConnectionError, OSError, ValueError):
                # Fallback or report error
                # If specifically configured for network usage, we might want
                # to fail here but for robustness let's try local binary if
                # available
                pass

        # Fallback to CLI
        cmd = [self.clamscan_path, *self.extra_args, path]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)  # noqa: S603
            out = (p.stdout or "") + (p.stderr or "")
            infected = "FOUND" in out
            signature = None
            if infected:
                parts = out.strip().split(":")
                if len(parts) >= 2:
                    signature = parts[1].replace("FOUND", "").strip()
            return {
                "infected": infected,
                "signature": signature,
                "raw": out,
                "returncode": p.returncode,
            }
        except FileNotFoundError:
            return {
                "infected": False,
                "error": "ClamAV binary not found and daemon connection failed",
                "raw": "Error: clamscan not found",
                "returncode": -1,
            }
