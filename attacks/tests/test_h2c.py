"""The h2c client against a local HTTP/2 server built on the same `h2` library.

The server listens on 127.0.0.1, which the guard (rightly) refuses, so these tests
widen the check for loopback only, inside the test.
"""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Iterator

import h2.config
import h2.connection
import h2.events
import pytest

from prahari_attacks import guard as guard_mod
from prahari_attacks.guard import Guard
from prahari_attacks.h2c import H2cClient


def _serve(listener: socket.socket, seen: list[tuple[str, str, bytes]]) -> None:
    conn_sock, _ = listener.accept()
    conn = h2.connection.H2Connection(
        h2.config.H2Configuration(
            client_side=False, header_encoding="utf-8", validate_inbound_headers=False
        )
    )
    conn.initiate_connection()
    conn_sock.sendall(conn.data_to_send())
    reqs: dict[int, dict[str, object]] = {}
    while True:
        data = conn_sock.recv(65536)
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.RequestReceived):
                reqs[ev.stream_id] = {"h": dict(ev.headers), "body": b""}
            elif isinstance(ev, h2.events.DataReceived):
                reqs[ev.stream_id]["body"] += ev.data  # type: ignore[operator]
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                r = reqs.pop(ev.stream_id)
                h = r["h"]
                assert isinstance(h, dict)
                seen.append((h[":method"], h[":path"], r["body"]))  # type: ignore[arg-type]
                status = "404" if "missing" in h[":path"] else "200"
                body = json.dumps({"path": h[":path"]}).encode()
                conn.send_headers(
                    ev.stream_id, [(":status", status), ("content-type", "application/json")]
                )
                conn.send_data(ev.stream_id, body, end_stream=True)
            elif isinstance(ev, h2.events.ConnectionTerminated):
                conn_sock.sendall(conn.data_to_send())
                conn_sock.close()
                return
        conn_sock.sendall(conn.data_to_send())
    conn_sock.close()


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[int, list[tuple[str, str, bytes]]]]:
    monkeypatch.setattr(guard_mod, "check_ip", lambda a: __import__("ipaddress").IPv4Address(a))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    seen: list[tuple[str, str, bytes]] = []
    t = threading.Thread(target=_serve, args=(listener, seen), daemon=True)
    t.start()
    yield listener.getsockname()[1], seen
    listener.close()


def test_requests_and_responses(server: tuple[int, list[tuple[str, str, bytes]]]) -> None:
    port, seen = server
    g = Guard()
    c = H2cClient(g, "127.0.0.1", port)
    r = c.request("GET", "/nnrf-disc/v1/nf-instances?target-nf-type=AUSF")
    assert r.status == 200
    assert r.json() == {"path": "/nnrf-disc/v1/nf-instances?target-nf-type=AUSF"}
    big = json.dumps({"x": "y" * 100_000}).encode()  # beyond one flow-control window
    r2 = c.request("PUT", "/nnrf-nfm/v1/nf-instances/abc", big)
    assert r2.status == 200
    assert c.request("GET", "/missing").status == 404
    c.close()
    assert seen[1] == ("PUT", "/nnrf-nfm/v1/nf-instances/abc", big)
    assert g.sent_bytes > len(big)


def test_unvalidated_mode_sends_odd_methods(
    server: tuple[int, list[tuple[str, str, bytes]]],
) -> None:
    port, seen = server
    c = H2cClient(Guard(), "127.0.0.1", port, validate=False)
    assert c.request("FOO", "/nfoo-bar/v99/" + "A" * 300).status == 200
    c.close()
    assert seen[0][0] == "FOO"
