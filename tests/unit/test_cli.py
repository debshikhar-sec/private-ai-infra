"""Unit tests for the console entry point. The CLI imports the app lazily (only on
`serve`), so parsing and `version` work without MLX and run everywhere."""

from __future__ import annotations

import pytest

from private_ai_gateway import cli


def test_version_command_prints_and_exits_zero(capsys):
    rc = cli.main(["version"])
    assert rc == 0
    assert cli.__version__ in capsys.readouterr().out


def test_version_flag():
    # argparse `action="version"` exits 0
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0


def test_serve_parser_defaults_to_loopback():
    args = cli.build_parser().parse_args(["serve"])
    assert args.host == "127.0.0.1"
    assert args.port == 8080
    assert args.command == "serve"


def test_no_command_prints_help_and_exits_zero(capsys):
    rc = cli.main([])
    assert rc == 0
    assert "private-ai-gateway" in capsys.readouterr().out


def test_scan_demo_manifest_fails_gate(capsys):
    # The packaged demo SBOM is deliberately vulnerable; scanning it must fail the gate.
    rc = cli.main(["scan", "--manifest", "demo"])
    out = capsys.readouterr().out
    assert rc == 1                       # gate failed -> non-zero exit
    assert "CVE-2023-48022" in out       # ShadowRay present
    assert "FAIL" in out


def test_scan_demo_json_format(capsys):
    rc = cli.main(["scan", "--manifest", "demo", "--format", "json"])
    import json

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["gate_passed"] is False
    assert payload["counts"]["critical"] >= 1


def test_scan_clean_manifest_passes(tmp_path, capsys):
    import json

    manifest = tmp_path / "clean.json"
    manifest.write_text(json.dumps({"packages": {"flask": "3.1.3"}}))
    rc = cli.main(["scan", "--manifest", str(manifest)])
    assert rc == 0
    assert "PASS" in capsys.readouterr().out


def test_optimize_reports_savings(capsys):
    rc = cli.main(["optimize"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "saved" in out and "tokens" in out


def test_scan_parser_defaults():
    args = cli.build_parser().parse_args(["scan"])
    assert args.gate == "high" and args.live is False and args.manifest is None
