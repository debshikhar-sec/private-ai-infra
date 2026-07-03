"""Tests for the decision-audit tail (/v1/decisions) and the Governance Console shell.

The audit tail is a governed read: only a principal with ``can_read_audit`` may see it.
The console at /console is a static, data-free shell, so it is served without auth but
pinned by a strict CSP.
"""

import json

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.policy import Policy, Principal, hash_token


# -----------------------------
# DecisionLog.tail (pure unit tests — no gateway needed)
# -----------------------------
def _write_events(path, n):
    log = DecisionLog(str(path))
    for i in range(n):
        log.record(
            request_id=f"req-{i}", principal="p", method="GET", path="/x",
            model=None, decision="allow", reason=f"r{i}", status=200,
        )
    return log


def test_tail_returns_newest_first(tmp_path):
    log = _write_events(tmp_path / "d.jsonl", 5)
    events = log.tail(3)
    assert [e["reason"] for e in events] == ["r4", "r3", "r2"]


def test_tail_missing_file_is_empty(tmp_path):
    assert DecisionLog(str(tmp_path / "missing.jsonl")).tail() == []


def test_tail_clamps_limit(tmp_path):
    log = _write_events(tmp_path / "d.jsonl", 3)
    assert len(log.tail(0)) == 1  # clamped up to 1
    assert len(log.tail(10_000)) == 3  # clamped down to 500, only 3 exist


def test_tail_skips_torn_or_malformed_lines(tmp_path):
    path = tmp_path / "d.jsonl"
    log = _write_events(path, 2)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write('{"torn": ')  # simulated torn concurrent append
    events = log.tail(10)
    assert [e["reason"] for e in events] == ["r1", "r0"]


# -----------------------------
# /v1/decisions authorization
# -----------------------------
@pytest.fixture
def audit_env(monkeypatch, tmp_path):
    """Gateway wired to a fresh decision log and a two-principal policy."""
    log = DecisionLog(str(tmp_path / "decisions.jsonl"))
    monkeypatch.setattr(gw, "DECISION_LOG", log)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "owner-token")
    pol = Policy(
        {
            hash_token("auditor-key"): Principal(
                "auditor", frozenset({"strategy"}), can_read_audit=True
            ),
            hash_token("analyst-key"): Principal("analyst", frozenset({"strategy"})),
        }
    )
    monkeypatch.setattr(gw, "POLICY", pol)
    return gw.app.test_client()


def test_decisions_requires_auth(audit_env):
    assert audit_env.get("/v1/decisions").status_code == 401


def test_decisions_denied_without_grant(audit_env):
    r = audit_env.get("/v1/decisions", headers={"Authorization": "Bearer analyst-key"})
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "audit_not_allowed"


def test_decisions_denial_is_itself_audited(audit_env):
    audit_env.get("/v1/decisions", headers={"Authorization": "Bearer analyst-key"})
    r = audit_env.get("/v1/decisions", headers={"Authorization": "Bearer auditor-key"})
    assert r.status_code == 200
    reasons = [e["reason"] for e in r.get_json()["decisions"]]
    assert "audit_not_allowed" in reasons  # watching the watchers is recorded


def test_decisions_allowed_with_grant_newest_first(audit_env):
    # Generate two decisions via whoami-adjacent traffic, then read the tail.
    audit_env.get("/v1/decisions", headers={"Authorization": "Bearer analyst-key"})
    r = audit_env.get("/v1/decisions?limit=5", headers={"Authorization": "Bearer auditor-key"})
    body = r.get_json()
    assert r.status_code == 200
    assert body["count"] == len(body["decisions"]) >= 1
    newest = body["decisions"][0]
    assert {"ts", "principal", "decision", "reason", "status"} <= set(newest)


def test_decisions_owner_has_grant(audit_env):
    r = audit_env.get("/v1/decisions", headers={"Authorization": "Bearer owner-token"})
    assert r.status_code == 200


def test_decisions_bad_limit_falls_back(audit_env):
    r = audit_env.get(
        "/v1/decisions?limit=bogus", headers={"Authorization": "Bearer auditor-key"}
    )
    assert r.status_code == 200


# -----------------------------
# /console shell
# -----------------------------
def test_console_serves_without_auth(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", "t")
    r = gw.app.test_client().get("/console")
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert "Governance Console" in text
    # The shell must not embed any credential or data — it only *asks* for a token.
    assert "Bearer token" in text


def test_console_pins_strict_csp(monkeypatch):
    monkeypatch.setattr(gw, "AUTH_TOKEN", "t")
    r = gw.app.test_client().get("/console")
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "connect-src 'self'" in csp
    assert r.headers["X-Frame-Options"] == "DENY"


def test_console_html_is_packaged():
    import importlib.resources

    data = importlib.resources.files("private_ai_gateway").joinpath("static/console.html")
    assert data.is_file()


def test_eval_suite_includes_audit_case():
    from evals.cases import ALL_CASES

    ids = [c.id for c in ALL_CASES]
    assert "AUDIT-001" in ids


def test_audit_event_shape_is_stable(tmp_path):
    _write_events(tmp_path / "d.jsonl", 1)
    with open(tmp_path / "d.jsonl", encoding="utf-8") as fh:
        event = json.loads(fh.readline())
    assert set(event) == {
        "ts", "request_id", "principal", "method", "path",
        "model", "decision", "reason", "status",
    }
