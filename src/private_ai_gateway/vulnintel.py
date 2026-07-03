"""Dependency vulnerability intelligence for the AI stack (Snyk/SonarQube-inspired).

A governance plane decides who may use a model; this module answers a different
question the same deployment must own: *is the software under the model safe to run?*
The AI supply chain is where a lot of 2024–2025 damage actually landed — unauthenticated
RCE in Ray's job API (ShadowRay, CVE-2023-48022, exploited in the wild), Jinja2 template
injection in ``llama-cpp-python`` (CVE-2024-34359), path traversal in MLflow
(CVE-2024-3573), and a ``torch.load`` deserialization bug in vLLM's completions endpoint
(CVE-2025-62164). Governing the agent while the runtime under it is trivially exploitable
is theatre.

Two evidence sources, matching the "verify, don't assert" rule elsewhere:

  * **Offline advisory snapshot** — a small, curated set of real, high-severity AI-stack
    CVEs with exact affected ranges and CVSS vectors taken from OSV.dev / GitHub Advisory
    (each entry carries its source URL). Deterministic, works with no network, and is what
    the tests and the demo run against.
  * **Live OSV.dev scan** (opt-in) — the same installed-package set queried against the
    Open Source Vulnerabilities batch API (``POST /v1/querybatch``) for current breadth.
    Network I/O is injectable so it stays testable and off by default.

Severity follows a SonarQube-style tiering with a configurable **quality gate**: a scan
"fails the gate" if any finding at or above a threshold (default: high) is present, which
is the hook a CI pipeline or the OpenClaw assurance pass consumes.

Sources:
  OSV.dev querybatch — https://google.github.io/osv.dev/post-v1-querybatch/
  CVE-2023-48022 (Ray) — https://osv.dev/vulnerability/GHSA-6wgj-66m2-xxp2
  CVE-2024-34359 (llama-cpp-python) — https://osv.dev/vulnerability/GHSA-56xg-wfcc-g829
  CVE-2024-3573 (MLflow) — https://osv.dev/vulnerability/GHSA-hq88-wg7q-gp4g
  CVE-2025-62164 (vLLM) — https://osv.dev/vulnerability/GHSA-mrw7-hf4f-83pf
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# ---------------------------------------------------------------- severity tiers
# SonarQube-style ordered tiers, derived from the CVSS v3 base score bands
# (https://nvd.nist.gov/vuln-metrics/cvss). "gate at high" means high + critical fail.
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def severity_from_cvss(score: float | None) -> str:
    """Map a CVSS v3 base score to a NVD qualitative tier."""
    if score is None:
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


# ---------------------------------------------------------------- version compare
_NUM_RE = re.compile(r"\d+")


def version_key(version: str) -> tuple[int, ...]:
    """A comparable key for a version string.

    PEP 440 handling is delegated to ``packaging`` when available (it ships with pip),
    with a numeric-release-tuple fallback so this module has no hard dependency and never
    crashes on an odd version string.
    """
    try:
        from packaging.version import InvalidVersion, Version

        try:
            return Version(version).release
        except InvalidVersion:
            pass
    except ModuleNotFoundError:
        pass
    parts = _NUM_RE.findall(version or "")
    return tuple(int(p) for p in parts) or (0,)


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


@dataclass(frozen=True)
class AffectedRange:
    """A half-open ``[introduced, fixed)`` range; ``fixed=None`` means no fix yet."""

    introduced: str = "0"
    fixed: str | None = None

    def contains(self, version: str) -> bool:
        if _cmp(version, self.introduced) < 0:
            return False
        if self.fixed is not None and _cmp(version, self.fixed) >= 0:
            return False
        return True


@dataclass(frozen=True)
class Advisory:
    """One known vulnerability against a package."""

    id: str
    package: str
    ecosystem: str
    summary: str
    cvss: float | None
    ranges: tuple[AffectedRange, ...]
    source_url: str
    aliases: tuple[str, ...] = ()
    attack_type: str = ""
    fixed_hint: str = ""
    # Set only when a source reports an advisory id but no CVSS score: the package is
    # still known-vulnerable, so it is surfaced at this tier (never dropped) pending a
    # score. Curated entries leave this None and derive severity from their CVSS.
    severity_override: str | None = None

    @property
    def severity(self) -> str:
        return self.severity_override or severity_from_cvss(self.cvss)

    def affects(self, version: str) -> bool:
        return any(r.contains(version) for r in self.ranges)


# ---------------------------------------------------------------- curated snapshot
# Real, high-severity AI-stack advisories. Ranges + CVSS vectors are taken from OSV.dev
# / GitHub Advisory (see each source_url). This is a high-signal seed, not a full DB —
# the live OSV scan (opt-in) provides breadth.
AI_STACK_ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        id="CVE-2023-48022",
        package="ray",
        ecosystem="PyPI",
        summary="Unauthenticated RCE via the Ray Dashboard job-submission API "
                "(\"ShadowRay\"); exploited in the wild. Mitigate with network isolation "
                "and the token auth added in Ray 2.52.0 — the CVE itself is vendor-disputed "
                "and has no code fix.",
        cvss=9.8,
        ranges=(AffectedRange("0", None),),
        source_url="https://osv.dev/vulnerability/GHSA-6wgj-66m2-xxp2",
        aliases=("GHSA-6wgj-66m2-xxp2",),
        attack_type="unauthenticated-rce",
        fixed_hint="no code fix; isolate the dashboard and enable token auth (>=2.52.0)",
    ),
    Advisory(
        id="CVE-2024-34359",
        package="llama-cpp-python",
        ecosystem="PyPI",
        summary="Server-side template injection: chat templates in .gguf model metadata "
                "are rendered in an unsandboxed Jinja2 environment, giving RCE at model "
                "load from an untrusted model file.",
        cvss=9.7,
        ranges=(AffectedRange("0.1.29", "0.2.72"),),
        source_url="https://osv.dev/vulnerability/GHSA-56xg-wfcc-g829",
        aliases=("GHSA-56xg-wfcc-g829", "PYSEC-2026-392"),
        attack_type="template-injection-rce",
        fixed_hint="upgrade to llama-cpp-python >= 0.2.72",
    ),
    Advisory(
        id="CVE-2024-3573",
        package="mlflow",
        ecosystem="PyPI",
        summary="Local File Inclusion / path traversal: is_local_uri mis-parses empty and "
                "'file' scheme URIs, so a crafted model 'source' reads arbitrary files from "
                "the tracking server.",
        cvss=7.5,
        ranges=(AffectedRange("0", "2.10.0"),),
        source_url="https://osv.dev/vulnerability/GHSA-hq88-wg7q-gp4g",
        aliases=("GHSA-hq88-wg7q-gp4g",),
        attack_type="path-traversal",
        fixed_hint="upgrade to mlflow >= 2.10.0",
    ),
    Advisory(
        id="CVE-2025-62164",
        package="vllm",
        ecosystem="PyPI",
        summary="Deserialization/memory-corruption in the Completions API: a malicious "
                "tensor payload reaches torch.load() with sparse-tensor checks disabled "
                "(PyTorch 2.8.0), yielding DoS and potential RCE.",
        cvss=9.1,
        ranges=(AffectedRange("0.10.2", "0.11.1"),),
        source_url="https://osv.dev/vulnerability/GHSA-mrw7-hf4f-83pf",
        aliases=("GHSA-mrw7-hf4f-83pf",),
        attack_type="deserialization-rce",
        fixed_hint="upgrade to vllm >= 0.11.1",
    ),
)


def _normalize(name: str) -> str:
    """PEP 503 normalization so 'LLaMA_CPP.Python' matches 'llama-cpp-python'."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


# ---------------------------------------------------------------- findings + report
@dataclass(frozen=True)
class Finding:
    package: str
    installed_version: str
    advisory: Advisory
    source: str  # "snapshot" or "osv"

    @property
    def severity(self) -> str:
        return self.advisory.severity

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "installed_version": self.installed_version,
            "vuln_id": self.advisory.id,
            "aliases": list(self.advisory.aliases),
            "severity": self.severity,
            "cvss": self.advisory.cvss,
            "attack_type": self.advisory.attack_type,
            "summary": self.advisory.summary,
            "remediation": self.advisory.fixed_hint,
            "source": self.source,
            "source_url": self.advisory.source_url,
        }


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    scanned: int = 0
    gate_threshold: str = "high"
    live: bool = False

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    @property
    def gate_passed(self) -> bool:
        """The SonarQube-style gate: no finding at/above the threshold tier."""
        floor = severity_rank(self.gate_threshold)
        return not any(severity_rank(f.severity) >= floor for f in self.findings)

    def exit_code(self) -> int:
        return 0 if self.gate_passed else 1

    def to_dict(self) -> dict:
        return {
            "component": "vulnintel",
            "scanned_packages": self.scanned,
            "live_osv": self.live,
            "gate_threshold": self.gate_threshold,
            "gate_passed": self.gate_passed,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda f: -severity_rank(f.severity))],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"

    def to_text(self) -> str:
        c = self.counts()
        lines = [
            "AI-stack dependency vulnerability scan",
            f"scanned: {self.scanned} packages"
            f"{' (+ live OSV.dev)' if self.live else ' (offline snapshot)'}",
            f"gate:    {'PASS' if self.gate_passed else 'FAIL'} "
            f"(threshold: {self.gate_threshold} and above)",
            f"counts:  {c['critical']} critical / {c['high']} high / "
            f"{c['medium']} medium / {c['low']} low",
            "",
        ]
        if not self.findings:
            lines.append("  No known-vulnerable packages found. ")
            return "\n".join(lines) + "\n"
        for f in sorted(self.findings, key=lambda f: -severity_rank(f.severity)):
            lines.append(
                f"  [{f.severity.upper():<8}] {f.package} {f.installed_version}  "
                f"{f.advisory.id}  ({f.advisory.attack_type})"
            )
            lines.append(f"             {f.advisory.summary}")
            lines.append(f"             fix: {f.advisory.fixed_hint}")
            lines.append(f"             ref: {f.advisory.source_url}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- environment scan
def installed_packages() -> dict[str, str]:
    """Map of normalized distribution name -> version for the running environment."""
    import importlib.metadata as im

    out: dict[str, str] = {}
    for dist in im.distributions():
        try:
            name = dist.metadata["Name"]
            if name:
                out[_normalize(name)] = dist.version
        except (KeyError, TypeError):
            continue
    return out


def scan_packages(
    packages: dict[str, str],
    *,
    advisories: tuple[Advisory, ...] = AI_STACK_ADVISORIES,
    gate_threshold: str = "high",
) -> ScanReport:
    """Match installed packages against the offline advisory snapshot."""
    report = ScanReport(scanned=len(packages), gate_threshold=gate_threshold)
    by_pkg: dict[str, list[Advisory]] = {}
    for adv in advisories:
        by_pkg.setdefault(_normalize(adv.package), []).append(adv)

    for raw_name, version in packages.items():
        name = _normalize(raw_name)
        for adv in by_pkg.get(name, ()):
            if adv.affects(version):
                report.findings.append(Finding(name, version, adv, "snapshot"))
    return report


# ---------------------------------------------------------------- live OSV.dev scan
class OSVError(RuntimeError):
    pass


def _osv_http_sender(timeout: float):
    def send(path: str, body: dict) -> dict:
        req = urllib.request.Request(
            f"https://api.osv.dev{path}",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise OSVError(f"OSV.dev request failed: {exc}") from exc

    return send


class OSVClient:
    """Client for the OSV.dev batch API. ``send`` is injectable for offline tests."""

    def __init__(self, *, send=None, timeout: float = 20.0):
        self._send = send or _osv_http_sender(timeout)

    def query_batch(self, packages: dict[str, str], *, ecosystem: str = "PyPI") -> dict:
        """POST /v1/querybatch — returns {normalized_name: [vuln_id, ...]}."""
        names = sorted(packages)
        body = {
            "queries": [
                {"package": {"name": n, "ecosystem": ecosystem}, "version": packages[n]}
                for n in names
            ]
        }
        payload = self._send("/v1/querybatch", body)
        results = payload.get("results", []) if isinstance(payload, dict) else []
        out: dict[str, list[str]] = {}
        for name, result in zip(names, results):
            vulns = (result or {}).get("vulns") or []
            ids = [v.get("id") for v in vulns if v.get("id")]
            if ids:
                out[name] = ids
        return out


def scan_live(
    packages: dict[str, str],
    *,
    client: OSVClient | None = None,
    gate_threshold: str = "high",
    snapshot_by_id: dict[str, Advisory] | None = None,
) -> ScanReport:
    """Scan against live OSV.dev, enriching known ids from the local snapshot.

    OSV batch returns ids only; we surface CVSS/severity for ids we already curate and
    fall back to an unscored 'medium' placeholder for the rest (an id alone still means
    "known-vulnerable", which the gate should see).
    """
    client = client or OSVClient()
    snapshot_by_id = snapshot_by_id or {
        alias: adv for adv in AI_STACK_ADVISORIES
        for alias in (adv.id, *adv.aliases)
    }
    report = ScanReport(scanned=len(packages), gate_threshold=gate_threshold, live=True)
    hits = client.query_batch(packages)
    for name, ids in hits.items():
        version = packages[name]
        curated = next((snapshot_by_id[i] for i in ids if i in snapshot_by_id), None)
        if curated is not None:
            report.findings.append(Finding(name, version, curated, "osv"))
            continue
        primary = ids[0]
        placeholder = Advisory(
            id=primary,
            package=name,
            ecosystem="PyPI",
            summary=f"OSV.dev reports {len(ids)} advisory(ies): {', '.join(ids)}. "
                    "Review upstream for CVSS and remediation.",
            cvss=None,
            ranges=(),
            source_url=f"https://osv.dev/vulnerability/{urllib.parse.quote(primary)}",
            aliases=tuple(ids[1:]),
            attack_type="see-advisory",
            fixed_hint="review the OSV.dev advisory for the fixed version",
            # Known-vulnerable but unscored here: surface at medium so it is visible
            # without tripping a high-gate on an id alone.
            severity_override="medium",
        )
        report.findings.append(Finding(name, version, placeholder, "osv"))
    return report
