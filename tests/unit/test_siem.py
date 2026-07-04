"""SIEM export: decisions reach the collector signed, and never block enforcement.

The properties worth pinning are the operational ones: delivery with a verifiable
HMAC, a dead collector counting as failures instead of raising into the request
path, and a full queue dropping (and counting) rather than blocking.
"""

import http.server
import json
import threading
import time

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.siem import SiemForwarder, from_policy, verify_signature


class _Sink(http.server.BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802 — http.server API
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        _Sink.received.append((body, dict(self.headers)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture
def sink():
    _Sink.received = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _wait(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_event_delivered_with_verifiable_hmac(sink):
    fw = SiemForwarder(sink, secret="collector-shared-secret")
    fw.emit({"decision": "deny", "reason": "autonomy_exceeded"})
    assert _wait(lambda: _Sink.received)
    fw.close()
    body, headers = _Sink.received[0]
    event = json.loads(body)
    assert event["event_type"] == "authorization_decision"
    assert event["reason"] == "autonomy_exceeded"
    assert verify_signature("collector-shared-secret", body, headers["X-Signature-256"])
    assert not verify_signature("wrong-secret", body, headers["X-Signature-256"])
    assert fw.stats()["delivered"] == 1


def test_unsigned_when_no_secret(sink):
    fw = SiemForwarder(sink)
    fw.emit({"decision": "allow"})
    assert _wait(lambda: _Sink.received)
    fw.close()
    assert "X-Signature-256" not in _Sink.received[0][1]


def test_dead_collector_counts_failures_and_never_raises():
    fw = SiemForwarder("http://127.0.0.1:1/unreachable", timeout=0.2)
    fw.emit({"decision": "deny"})  # must not raise on the caller's thread
    assert _wait(lambda: fw.stats()["failed"] == 1)
    fw.close()


def test_full_queue_drops_instead_of_blocking():
    release = threading.Event()
    picked_up = threading.Event()

    class _Stalled(SiemForwarder):
        def _deliver(self, event):
            picked_up.set()
            release.wait(5)
            self._count("delivered")

    fw = _Stalled("http://irrelevant.invalid", queue_size=2)
    fw.emit({"n": 0})
    assert picked_up.wait(5)          # worker is now stalled on event 0
    fw.emit({"n": 1})
    fw.emit({"n": 2})                 # queue (size 2) now full
    fw.emit({"n": 3})                 # must drop immediately, not block
    assert fw.stats()["dropped"] == 1
    release.set()
    fw.close()


def test_from_policy_off_and_env_secret(sink, monkeypatch):
    assert from_policy(None, "ANY") is None
    assert from_policy("", None) is None
    monkeypatch.setenv("TEST_SIEM_SECRET", "from-the-env")
    fw = from_policy(sink, "TEST_SIEM_SECRET")
    fw.emit({"decision": "allow"})
    assert _wait(lambda: _Sink.received)
    fw.close()
    body, headers = _Sink.received[0]
    assert verify_signature("from-the-env", body, headers["X-Signature-256"])


def test_gateway_denial_reaches_collector(sink, monkeypatch, tmp_path):
    outcomes = []
    fw = SiemForwarder(sink, secret="s3", on_outcome=outcomes.append)
    monkeypatch.setattr(
        gw, "DECISION_LOG", DecisionLog(str(tmp_path / "d.jsonl"), forwarder=fw)
    )
    monkeypatch.setattr(gw, "AUTH_TOKEN", "test-token")
    client = gw.app.test_client()
    resp = client.post(
        "/v1/chat/completions",
        json={"model": "strategy", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
    assert _wait(lambda: _Sink.received)
    fw.close()
    event = json.loads(_Sink.received[0][0])
    assert event["decision"] == "deny" and event["event_type"] == "authorization_decision"
    assert outcomes == ["delivered"]
