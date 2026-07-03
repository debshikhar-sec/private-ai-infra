"""Dependency vulnerability intelligence: version ranges, severity gate, OSV client.

The advisory ranges here are pinned to real CVEs (see vulnintel.AI_STACK_ADVISORIES);
these tests assert the *matching logic* around them, and mock the OSV network seam so
the live path is exercised deterministically and offline.
"""

import pytest

from private_ai_gateway import vulnintel as vi


# ------------------------------------------------------------------ version logic
def test_version_ordering_is_numeric_not_lexical():
    assert vi._cmp("0.2.9", "0.2.72") < 0   # lexical would say 9 > 72
    assert vi._cmp("2.10.0", "2.9.0") > 0
    assert vi._cmp("1.0", "1.0") == 0


def test_affected_range_is_half_open():
    r = vi.AffectedRange("0.1.29", "0.2.72")
    assert r.contains("0.2.71")
    assert not r.contains("0.2.72")   # fixed version is not affected
    assert not r.contains("0.1.28")   # below introduced


def test_open_ended_range_has_no_fix():
    r = vi.AffectedRange("0", None)
    assert r.contains("99.99.99")


def test_severity_tiers_track_cvss_bands():
    assert vi.severity_from_cvss(9.8) == "critical"
    assert vi.severity_from_cvss(7.5) == "high"
    assert vi.severity_from_cvss(5.0) == "medium"
    assert vi.severity_from_cvss(2.0) == "low"
    assert vi.severity_from_cvss(None) == "none"


# ------------------------------------------------------------------ snapshot scan
def test_demo_stack_trips_every_advisory():
    packages = {
        "ray": "2.6.0",
        "llama-cpp-python": "0.2.20",
        "mlflow": "2.9.0",
        "vllm": "0.10.5",
    }
    report = vi.scan_packages(packages)
    ids = {f.advisory.id for f in report.findings}
    assert ids == {"CVE-2023-48022", "CVE-2024-34359", "CVE-2024-3573", "CVE-2025-62164"}
    assert not report.gate_passed and report.exit_code() == 1


def test_patched_versions_clear_the_gate():
    packages = {
        "ray": "2.6.0",             # no code fix -> still flagged
        "llama-cpp-python": "0.2.72",
        "mlflow": "2.10.0",
        "vllm": "0.11.1",
    }
    report = vi.scan_packages(packages)
    # Only the (unfixable) Ray advisory remains.
    assert {f.advisory.id for f in report.findings} == {"CVE-2023-48022"}


def test_name_normalization_matches_variants():
    report = vi.scan_packages({"LLaMA_CPP.Python": "0.2.20"})
    assert report.findings and report.findings[0].advisory.id == "CVE-2024-34359"


def test_clean_environment_passes_gate():
    report = vi.scan_packages({"flask": "3.0.3", "numpy": "1.26.4"})
    assert report.findings == [] and report.gate_passed


def test_gate_threshold_is_configurable():
    # A high-only finding passes a 'critical' gate but fails a 'high' gate.
    high_only = {"mlflow": "2.9.0"}
    assert vi.scan_packages(high_only, gate_threshold="critical").gate_passed
    assert not vi.scan_packages(high_only, gate_threshold="high").gate_passed


# ------------------------------------------------------------------ live OSV client
def test_osv_client_builds_batch_and_maps_results():
    captured = {}

    def fake_send(path, body):
        captured["path"] = path
        captured["body"] = body
        # OSV returns results in the same order as the queries.
        return {
            "results": [
                {"vulns": [{"id": "CVE-2024-34359"}]},   # llama-cpp-python
                {},                                        # numpy: clean
            ]
        }

    client = vi.OSVClient(send=fake_send)
    hits = client.query_batch({"llama-cpp-python": "0.2.20", "numpy": "1.26.4"})
    assert captured["path"] == "/v1/querybatch"
    # queries are sorted by name; both are present
    assert {q["package"]["name"] for q in captured["body"]["queries"]} == {
        "llama-cpp-python", "numpy"
    }
    assert hits == {"llama-cpp-python": ["CVE-2024-34359"]}


def test_scan_live_enriches_known_ids_and_flags_unknown():
    def fake_send(path, body):
        return {
            "results": [
                {"vulns": [{"id": "CVE-2024-34359"}]},        # curated -> critical
                {"vulns": [{"id": "CVE-2099-00000"}]},        # unknown -> placeholder
            ]
        }

    report = vi.scan_live(
        {"llama-cpp-python": "0.2.20", "somepkg": "1.0.0"},
        client=vi.OSVClient(send=fake_send),
    )
    assert report.live
    by_pkg = {f.package: f for f in report.findings}
    assert by_pkg["llama-cpp-python"].severity == "critical"
    assert by_pkg["llama-cpp-python"].source == "osv"
    # An id with no curated CVSS is still surfaced (as medium), never dropped.
    assert by_pkg["somepkg"].advisory.id == "CVE-2099-00000"
    assert by_pkg["somepkg"].severity == "medium"


def test_report_json_is_ordered_and_gated():
    report = vi.scan_packages({"vllm": "0.10.5", "mlflow": "2.9.0"})
    d = report.to_dict()
    severities = [f["severity"] for f in d["findings"]]
    # Findings are ordered most-severe first.
    assert severities == sorted(severities, key=lambda s: -vi.severity_rank(s))
    assert d["gate_passed"] is False


def test_report_text_renders_findings_and_refs():
    text = vi.scan_packages({"ray": "2.6.0"}).to_text()
    assert "CVE-2023-48022" in text
    assert "osv.dev" in text
    assert "FAIL" in text


def test_report_text_clean_case():
    text = vi.scan_packages({"flask": "3.1.3"}).to_text()
    assert "No known-vulnerable packages" in text


def test_osv_error_type_exists():
    # The live path raises OSVError on transport failure; the CLI catches it and falls
    # back to the offline snapshot (exercised here at the type level).
    def boom(path, body):
        raise vi.OSVError("network down")

    client = vi.OSVClient(send=boom)
    with pytest.raises(vi.OSVError):
        client.query_batch({"ray": "2.6.0"})


def test_installed_packages_returns_versions():
    pkgs = vi.installed_packages()
    # Flask is a hard dependency, so it must be present and normalized.
    assert "flask" in pkgs and pkgs["flask"]
