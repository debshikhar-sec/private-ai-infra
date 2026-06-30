"""Tests for the OpenClaw CLI runner."""

from __future__ import annotations

import json

import pytest
from openclaw import run
from openclaw.client import MetricsClient, MetricsError


class _FakeMetricsClient:
    """Stand-in for MetricsClient: returns canned Prometheus text, no network."""

    def __init__(self, base_url, token, **kw):
        self.base_url = base_url
        self.token = token

    def fetch(self) -> str:
        return "gateway_authz_denials_total 9\n"


def _audit(tmp_path, lines) -> str:
    p = tmp_path / "decisions.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


_CLEAN = (
    '{"ts":"t","request_id":"r1","principal":"analyst","method":"POST",'
    '"path":"/v1/chat/completions","model":"strategy","decision":"allow",'
    '"reason":"ok","status":200}'
)
_AUTONOMY_LEAK = (
    '{"ts":"t","request_id":"r2","principal":"hermes","method":"POST",'
    '"path":"/v1/chat/completions","model":"strategy","decision":"allow",'
    '"reason":"autonomy_exceeded leaked","status":200}'
)


def test_run_clean_audit_exits_zero(tmp_path, capsys):
    code = run.main(["--audit", _audit(tmp_path, [_CLEAN])])
    assert code == 0
    assert "PASS" in capsys.readouterr().out


def test_run_violation_exits_one(tmp_path, capsys):
    code = run.main(["--audit", _audit(tmp_path, [_AUTONOMY_LEAK])])
    assert code == 1
    assert "FAIL" in capsys.readouterr().out


def test_run_json_format_is_parseable(tmp_path, capsys):
    code = run.main(["--audit", _audit(tmp_path, [_CLEAN]), "--format", "json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "PASS"


def test_run_writes_output_file(tmp_path, capsys):
    out = tmp_path / "report.txt"
    code = run.main(["--audit", _audit(tmp_path, [_CLEAN]), "--output", str(out)])
    assert code == 0
    assert "OpenClaw assurance report" in out.read_text(encoding="utf-8")
    # the report goes to the file; stdout stays clean for piping
    assert "report written to" in capsys.readouterr().err


def test_run_metrics_url_uses_injected_client(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PRIVATE_AI_OPENCLAW_TOKEN", "k")
    code = run.main(
        ["--audit", _audit(tmp_path, [_CLEAN]), "--metrics-url", "http://127.0.0.1:8081"],
        metrics_client_factory=_FakeMetricsClient,
    )
    assert code == 0
    # reconcile control should now be exercised (metric 9 >= audit 0 denials)
    assert "AC-METRICS-RECONCILE" in capsys.readouterr().out


def test_run_metrics_url_without_token_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("PRIVATE_AI_OPENCLAW_TOKEN", raising=False)
    monkeypatch.delenv("PRIVATE_AI_AUTH_TOKEN", raising=False)
    code = run.main(
        ["--audit", _audit(tmp_path, [_CLEAN]), "--metrics-url", "http://127.0.0.1:8081"],
        metrics_client_factory=_FakeMetricsClient,
    )
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_run_eval_report_failing_probe_exits_one(tmp_path, capsys):
    er = tmp_path / "evals.json"
    er.write_text(
        '{"verdict":"FAIL","counts":{"pass":11,"fail":1,"skip":0},'
        '"results":[{"id":"AUTONOMY-004","owasp":"LLM06","attack":"hdr+body",'
        '"status":"fail"}]}',
        encoding="utf-8",
    )
    code = run.main(["--audit", _audit(tmp_path, [_CLEAN]), "--eval-report", str(er)])
    assert code == 1
    out = capsys.readouterr().out
    assert "AC-SECURITY-EVALS" in out and "FAIL" in out


def test_run_apply_report_ungated_apply_exits_one(tmp_path, capsys):
    ar = tmp_path / "apply.json"
    ar.write_text(
        '{"status":"applied","approver":null,"committed":true,'
        '"declared_files":["a.py"],"changed_files":["a.py"]}',
        encoding="utf-8",
    )
    code = run.main(["--audit", _audit(tmp_path, [_CLEAN]), "--apply-report", str(ar)])
    assert code == 1
    out = capsys.readouterr().out
    assert "AC-APPLY-INTEGRITY" in out and "FAIL" in out


def test_run_missing_audit_file_is_inconclusive_not_crash(tmp_path, capsys):
    code = run.main(["--audit", str(tmp_path / "nope.jsonl")])
    # no evidence -> no failures -> PASS verdict, exit 0
    assert code == 0
    assert "INCONCLUSIVE" in capsys.readouterr().out


# --------------------------------------------------------------- MetricsClient
def test_metrics_client_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        MetricsClient("file:///etc/passwd", "tok")


def test_metrics_client_fetch_unreachable_raises_metrics_error():
    # An unused loopback port: connection refused -> URLError -> MetricsError.
    client = MetricsClient("http://127.0.0.1:1", "tok", timeout=0.5)
    with pytest.raises(MetricsError):
        client.fetch()
