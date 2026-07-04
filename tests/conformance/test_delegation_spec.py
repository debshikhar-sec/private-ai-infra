"""GAD/1.0 conformance suite — one test per normative MUST in docs/delegation-spec.md.

Runs two ways:

* **In-process (default, CI):** exercises this gateway through its real Flask app with
  the fixture cast from the spec's §5 installed.
* **External:** set ``GAD_BASE_URL`` plus ``GAD_TOKEN_CONDUCTOR`` / ``_WORKER`` /
  ``_CHECKER`` / ``_OUTSIDER`` and the same tests run over HTTP against any
  implementation configured with the fixture cast (max_depth=2).

Test names carry the invariant tag (``gad_i1`` …) so a conformance report is just the
pytest output.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
import urllib.request

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.delegation import DelegationLedger
from private_ai_gateway.policy import Policy, Principal, hash_token
from private_ai_gateway.ratelimit import RateLimiter

BASE_URL = os.environ.get("GAD_BASE_URL", "").rstrip("/")

# The fixture cast from the spec (§5). Ceilings and skills are load-bearing: the suite
# is only valid against a target configured exactly like this, with max_depth=2.
CAST = {
    "conductor": {"skills": {"review"}, "ceiling": 2, "audit": True},
    "worker": {"skills": {"review", "verify"}, "ceiling": 3, "audit": False},
    "checker": {"skills": {"verify"}, "ceiling": 2, "audit": False},
    "outsider": {"skills": set(), "ceiling": 1, "audit": False},
}
MAX_DEPTH = 2


class Target:
    """Uniform HTTP-ish interface over the in-process app or an external base URL."""

    def __init__(self, client, tokens: dict[str, str]):
        self._client = client  # Flask test client, or None for external
        self._tokens = tokens

    def request(self, method: str, path: str, who: str, body: dict | None = None):
        headers = {"Authorization": f"Bearer {self._tokens[who]}"}
        if self._client is not None:
            resp = self._client.open(path, method=method, json=body, headers=headers)
            return resp.status_code, (resp.get_json(silent=True) or {})
        req = urllib.request.Request(
            f"{BASE_URL}{path}",
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={**headers, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read() or b"{}")

    def delegate(self, who: str, *, skill: str, to: str, level: int,
                 parent: str | None = None):
        body = {"skill": skill, "delegatee": to, "autonomy_level": level}
        if parent:
            body["parent_task"] = parent
        return self.request("POST", "/a2a/tasks", who, body)

    def report(self, who: str, task_id: str, status: str, **extra):
        return self.request(
            "POST", f"/a2a/tasks/{task_id}/result", who, {"status": status, **extra}
        )


@pytest.fixture
def target(monkeypatch):
    if BASE_URL:
        tokens = {
            name: os.environ[f"GAD_TOKEN_{name.upper()}"] for name in CAST
        }
        return Target(None, tokens)

    tokens = {name: f"tok-{name}" for name in CAST}
    principals = {
        hash_token(tok): Principal(
            name,
            frozenset(),
            max_autonomy_level=CAST[name]["ceiling"],
            allowed_skills=frozenset(CAST[name]["skills"]),
            can_read_audit=CAST[name]["audit"],
        )
        for name, tok in tokens.items()
    }
    pol = Policy(principals, max_delegation_depth=MAX_DEPTH)
    monkeypatch.setattr(gw, "POLICY", pol)
    monkeypatch.setattr(gw, "AUTH_TOKEN", "")
    monkeypatch.setattr(gw, "RATE_LIMITER", RateLimiter(0))
    monkeypatch.setattr(gw, "DELEGATIONS", DelegationLedger())
    log = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)  # noqa: SIM115
    monkeypatch.setattr(gw, "DECISION_LOG", DecisionLog(log.name))
    return Target(gw.app.test_client(), tokens)


def _err(payload: dict) -> str:
    return (payload.get("error") or {}).get("code", "")


# ------------------------------------------------------------------ creation (I1–I5)
def test_gad_i1_no_self_delegation(target):
    status, body = target.delegate("conductor", skill="review", to="conductor", level=1)
    assert status == 400 and _err(body) == "self_delegation"


def test_gad_i2_delegator_must_hold_skill(target):
    status, body = target.delegate("checker", skill="review", to="worker", level=1)
    assert status == 403 and _err(body) == "skill_not_delegable"


def test_gad_i3_delegatee_must_hold_skill(target):
    status, body = target.delegate("conductor", skill="review", to="checker", level=1)
    assert status == 403 and _err(body) == "skill_not_allowed"


def test_gad_i4_no_amplification_past_delegatee_ceiling(target):
    status, body = target.delegate("conductor", skill="review", to="worker", level=4)
    assert status == 403 and _err(body) == "autonomy_amplification"


def test_gad_i5_delegatee_must_exist(target):
    status, body = target.delegate("conductor", skill="review", to="ghost", level=1)
    assert status == 404 and _err(body) == "unknown_delegatee"


def test_gad_accepted_delegation_is_recorded(target):
    status, body = target.delegate("conductor", skill="review", to="worker", level=2)
    assert status == 202
    assert body["delegator"] == "conductor" and body["delegatee"] == "worker"
    assert body["granted_level"] == 2 and body["depth"] == 1
    assert body["status"] == "submitted"


# --------------------------------------------------------------- chains (I6–I9)
def _root(target, level: int = 2) -> str:
    status, body = target.delegate("conductor", skill="review", to="worker", level=level)
    assert status == 202
    return body["id"]


def test_gad_i6_only_holder_may_subdelegate(target):
    root = _root(target)
    # checker holds 'verify' but is not the holder of the root task.
    status, body = target.delegate(
        "checker", skill="verify", to="worker", level=1, parent=root
    )
    assert status == 403 and _err(body) == "not_task_holder"


def test_gad_i7_only_active_tasks_subdelegate(target):
    root = _root(target)
    assert target.report("worker", root, "completed")[0] == 200
    status, body = target.delegate(
        "worker", skill="verify", to="checker", level=1, parent=root
    )
    assert status == 409 and _err(body) == "parent_not_active"


def test_gad_i8_chains_only_narrow(target):
    root = _root(target, level=1)
    # L2 fits checker's own ceiling (L2) but exceeds the parent grant (L1).
    status, body = target.delegate(
        "worker", skill="verify", to="checker", level=2, parent=root
    )
    assert status == 403 and _err(body) == "delegation_widening"


def test_gad_i9_depth_is_bounded(target):
    root = _root(target)
    status, sub = target.delegate(
        "worker", skill="verify", to="checker", level=1, parent=root
    )
    assert status == 202 and sub["depth"] == 2
    status, body = target.delegate(
        "checker", skill="verify", to="worker", level=1, parent=sub["id"]
    )
    assert status == 403 and _err(body) == "delegation_too_deep"


# ------------------------------------------------------------ outcomes (I10–I11)
def test_gad_i10_only_delegatee_reports(target):
    root = _root(target)
    status, body = target.report("conductor", root, "completed")
    assert status == 403 and _err(body) == "not_task_holder"


def test_gad_i11_report_once_and_terminal_only(target):
    root = _root(target)
    status, body = target.report("worker", root, "in_progress")
    assert status == 400 and _err(body) == "invalid_status"
    assert target.report("worker", root, "failed", result="could not verify")[0] == 200
    status, body = target.report("worker", root, "completed")
    assert status == 409 and _err(body) == "already_reported"


# ------------------------------------------------------- audit + discovery (I12–I13)
def test_gad_i12_denials_are_audited_with_stable_codes(target):
    target.delegate("conductor", skill="review", to="worker", level=4)  # denied I4
    status, body = target.request("GET", "/v1/decisions?limit=20", "conductor")
    assert status == 200
    reasons = [e.get("reason", "") for e in body.get("decisions", body.get("events", []))]
    assert any(r.startswith("autonomy_amplification") for r in reasons)


def test_gad_i13_cards_derive_from_policy_not_claims(target):
    status, body = target.request("GET", "/a2a/agents", "conductor")
    assert status == 200
    assert body.get("max_delegation_depth") == MAX_DEPTH
    cards = {c["name"]: c for c in body["agents"]}
    worker_skills = {s["id"] for s in cards["worker"]["skills"]}
    assert worker_skills == CAST["worker"]["skills"]
    assert cards["outsider"]["skills"] == []  # no grant, no advertised capability
