"""Minimal HTTP/2 cleartext (prior knowledge) client for SBI, built on the `h2` library.

One TCP connection, one request at a time: enough for reconnaissance, registration
abuse and fuzzing, and easy to reason about in a capture. Header validation can be
switched off so SBI-04 can send malformed requests on purpose.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any

import h2.config
import h2.connection
import h2.events
import h2.exceptions

from prahari_attacks.guard import Guard


@dataclass
class Reply:
    status: int | None  # None: no response (reset, timeout, connection lost)
    body: bytes
    error: str = ""

    def json(self) -> Any:
        return json.loads(self.body) if self.body else None


class H2cClient:
    def __init__(
        self,
        guard: Guard,
        ip: str,
        port: int = 7777,
        *,
        validate: bool = True,
        timeout: float = 3.0,
        source_ip: str = "",
    ) -> None:
        self._guard = guard
        self._ip = ip
        self._port = port
        self._timeout = timeout
        cfg = h2.config.H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            validate_outbound_headers=validate,
            normalize_outbound_headers=validate,
            validate_inbound_headers=False,
        )
        self._sock: socket.socket = guard.tcp_connect(ip, port, timeout, source_ip)
        self._conn = h2.connection.H2Connection(config=cfg)
        self._conn.initiate_connection()
        self._flush()

    def _flush(self) -> None:
        data = self._conn.data_to_send()
        if data:
            self._sock.sendall(data)
            self._guard.count_sent(len(data))

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> Reply:
        sid = self._conn.get_next_available_stream_id()
        headers = [
            (":method", method),
            (":scheme", "http"),
            (":authority", f"{self._ip}:{self._port}"),
            (":path", path),
        ]
        if body is not None:
            headers.append(("content-type", content_type))
        headers += extra_headers or []
        try:
            self._conn.send_headers(sid, headers, end_stream=body is None)
            if body is not None:
                self._send_body(sid, body)
            self._flush()
        except (h2.exceptions.ProtocolError, OSError) as e:
            return Reply(None, b"", f"send: {type(e).__name__}: {e}")
        return self._wait(sid)

    def _send_body(self, sid: int, body: bytes) -> None:
        view = memoryview(body)
        while view:
            window = min(
                self._conn.local_flow_control_window(sid), self._conn.max_outbound_frame_size
            )
            if window <= 0:
                self._flush()
                self._pump_once()
                continue
            chunk, view = view[:window], view[window:]
            self._conn.send_data(sid, bytes(chunk), end_stream=not view)
        self._flush()

    def _pump_once(self) -> list[h2.events.Event]:
        data = self._sock.recv(65536)
        if not data:
            raise ConnectionError("connection closed by peer")
        events: list[h2.events.Event] = self._conn.receive_data(data)
        self._flush()
        return events

    def _wait(self, sid: int) -> Reply:
        status: int | None = None
        body = bytearray()
        try:
            while True:
                for ev in self._pump_once():
                    if isinstance(ev, h2.events.ResponseReceived) and ev.stream_id == sid:
                        for k, v in ev.headers:
                            key = k.decode() if isinstance(k, bytes) else k
                            if key == ":status":
                                status = int(v)
                    elif isinstance(ev, h2.events.DataReceived) and ev.stream_id == sid:
                        body += ev.data
                        self._conn.acknowledge_received_data(ev.flow_controlled_length, sid)
                        self._flush()
                    elif isinstance(ev, h2.events.StreamEnded) and ev.stream_id == sid:
                        return Reply(status, bytes(body))
                    elif isinstance(ev, h2.events.StreamReset) and ev.stream_id == sid:
                        return Reply(status, bytes(body), f"stream reset ({ev.error_code})")
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return Reply(status, bytes(body), f"GOAWAY ({ev.error_code})")
        except (OSError, ConnectionError, h2.exceptions.ProtocolError) as e:
            return Reply(status, bytes(body), f"{type(e).__name__}: {e}")

    def send_raw(self, data: bytes) -> None:
        """Bytes straight onto the TCP stream, bypassing h2 (malformed-frame tests)."""
        self._sock.sendall(data)
        self._guard.count_sent(len(data))

    def close(self) -> None:
        try:
            self._conn.close_connection()
            self._flush()
        except (OSError, h2.exceptions.ProtocolError):
            pass
        self._sock.close()
