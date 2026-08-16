"""The capability registry: identity, availability, fit, qualification — and no authority.

What these tests hold the registry to:

  * **A route alias is not an identity.** Re-pointing an alias at a different build produces a
    different fingerprint, and the new build starts NOT_EVALUATED instead of inheriting a
    reputation it never earned.
  * **Qualification is per lane.** Being good at documentation consistency is not evidence
    about security review, and the security lane is derived only from the measured refusal
    rate — 0/2 is UNQUALIFIED, with no partial credit and no rounding.
  * **Nothing is invented.** No cache, no revision. No weights on disk, no hardware fit. The
    registry says UNKNOWN rather than guessing.
  * **Privacy by construction.** The host snapshot never collects a serial, UUID, username,
    home directory, MAC address, or absolute path.
  * **It grants nothing.** No authorization module imports it, and no authorization path
    changes because a model scores well.

Deterministic and offline: every probe is injected, no backend is imported, no model is ever
downloaded.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from private_ai_gateway import app as gw
from private_ai_gateway import registry as reg
from private_ai_gateway.demo import TOKENS, install_demo_plane

_OWNER_TOKEN = "test-owner-break-glass-token"
OWNER = {"Authorization": f"Bearer {_OWNER_TOKEN}"}
QWEN = "mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit"


@pytest.fixture
def cache(tmp_path):
    """A fake local model cache in the real Hugging Face hub layout."""
    root = tmp_path / "hub"
    root.mkdir()
    return reg.ModelCache(root)


def _install(
    cache: reg.ModelCache, model_id: str, *, revision="abc123", size=1024,
    shards=1, present=None, index=True,
):
    """Install a fake cached model in the real hub layout.

    The blob is created **sparse** via ``truncate``: ``st_size`` reports the full apparent
    size, which is all the fit calculation reads, without allocating a byte. Materializing a
    60 GB blob to test DOES_NOT_FIT is how a fixture kills a CI runner.

    The snapshot directory is built with the same shape the hub uses — ``refs/main`` naming
    a revision, ``snapshots/<rev>/`` holding symlinks into ``blobs/`` — because the previous
    fixture created only ``blobs/`` and so declared a model "cached" under conditions that
    could never load. ``present`` installs fewer shards than the index declares, which is
    what a half-finished download actually looks like.
    """
    present = shards if present is None else present
    entry = cache.root / ("models--" + model_id.replace("/", "--"))
    (entry / "refs").mkdir(parents=True, exist_ok=True)
    (entry / "refs" / "main").write_text(revision, encoding="utf-8")
    blobs = entry / "blobs"
    blobs.mkdir(exist_ok=True)
    snapshot = entry / "snapshots" / revision
    snapshot.mkdir(parents=True, exist_ok=True)

    names = [f"model-{i + 1:05d}-of-{shards:05d}.safetensors" for i in range(shards)]
    for position, name in enumerate(names):
        blob = blobs / f"blob{position}"
        with open(blob, "wb") as fh:
            fh.truncate(size // shards if shards else size)
        if position < present:
            (snapshot / name).symlink_to(blob)
    if index:
        (snapshot / "model.safetensors.index.json").write_text(
            json.dumps({"weight_map": {f"layer.{i}": n for i, n in enumerate(names)}}),
            encoding="utf-8",
        )
    return entry


def _host(**over):
    base = dict(
        platform="Darwin", architecture="arm64", total_memory_bytes=128 * 1024 ** 3,
        backends_available=("demo", "mlx"), active_backend="mlx",
    )
    base.update(over)
    return reg.HostSnapshot(**base)


def _artifact(fingerprint, **metrics):
    summary = dict(
        total=18, structural_valid_rate=0.94, tests_pass_rate=0.81, lint_pass_rate=0.88,
        api_preserved_rate=1.0, zero_edit_rate=0.72,
        security_refusal_correct=0, security_refusal_total=2, by_outcome={},
    )
    summary.update(metrics)
    return reg.QualificationArtifact.from_mapping(
        {"fingerprint": fingerprint, "summary": summary, "generated_at": "2026-08-11T00:00:00Z"},
        path="a.json",
    )


# --- model identity ------------------------------------------------------------------------

def test_quantization_is_parsed_from_the_id_or_absent():
    assert reg.quantization_of(QWEN) == "8bit"
    assert reg.quantization_of("mlx-community/Qwen3.6-27B-OptiQ-4bit") == "4bit"
    assert reg.quantization_of("meta/llama-3-70b") == ""      # not stated, not guessed


def test_the_fingerprint_covers_build_not_just_the_alias(cache):
    _install(cache, QWEN, revision="rev-one")
    first = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    (cache.root / ("models--" + QWEN.replace("/", "--")) / "refs" / "main").write_text(
        "rev-two", encoding="utf-8"
    )
    second = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)

    assert first.route_alias == second.route_alias == "engineering"
    assert first.revision != second.revision
    assert first.fingerprint != second.fingerprint       # a new build is a new subject


def test_two_models_behind_one_alias_do_not_share_a_fingerprint(cache):
    a = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    b = reg.identify_model("engineering", "other/model-4bit", backend="mlx", cache=cache)
    assert a.fingerprint != b.fingerprint


def test_the_same_build_on_the_same_backend_is_stable(cache):
    _install(cache, QWEN)
    a = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    b = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert a.fingerprint == b.fingerprint
    assert len(a.short_fingerprint) == 12


def test_the_backend_is_part_of_identity(cache):
    a = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    b = reg.identify_model("engineering", QWEN, backend="openai", cache=cache)
    assert a.fingerprint != b.fingerprint


# --- the local cache ------------------------------------------------------------------------

def test_an_uncached_model_has_no_revision_and_no_size(cache):
    assert cache.is_cached(QWEN) is False
    assert cache.revision_of(QWEN) == ""
    assert cache.weight_bytes(QWEN) is None


def test_an_unreadable_cache_is_unknown_not_empty(tmp_path):
    missing = reg.ModelCache(tmp_path / "does-not-exist")
    assert missing.readable is False
    assert missing.is_cached(QWEN) is None               # unknown, never "not installed"
    assert missing.cached_models() == ()


def test_cached_models_are_reported_as_ids_never_paths(cache):
    _install(cache, QWEN)
    _install(cache, "mlx-community/Qwen3.6-27B-OptiQ-4bit")
    listed = cache.cached_models()
    assert QWEN in listed
    assert all("/" in name and not name.startswith("/") for name in listed)
    assert all(str(cache.root) not in name for name in listed)


# --- host snapshot ----------------------------------------------------------------------------

def test_the_host_snapshot_is_privacy_minimal_by_construction(cache):
    _install(cache, QWEN)
    host = reg.snapshot_host(
        active_backend="mlx", cache=cache, mlx_available=lambda: True,
        system=lambda: "Darwin", machine=lambda: "arm64", memory_bytes=128 * 1024 ** 3,
    )
    blob = json.dumps(host.to_mapping())
    for forbidden in (
        "serial", "uuid", "/Users/", "/home/", str(Path.home()), "MAC", "mac_address",
        "username", "hostname", "PATH", "environ",
    ):
        assert forbidden not in blob, forbidden
    assert set(host.to_mapping()) == {
        "platform", "architecture", "total_memory_bytes", "total_memory_gb",
        "backends_available", "active_backend", "cached_models", "cache_readable",
    }


def test_backend_availability_is_probed_not_assumed(cache):
    with_mlx = reg.snapshot_host(cache=cache, mlx_available=lambda: True,
                                 system=lambda: "Darwin", machine=lambda: "arm64")
    without = reg.snapshot_host(cache=cache, mlx_available=lambda: False,
                                system=lambda: "Linux", machine=lambda: "x86_64")
    assert "mlx" in with_mlx.backends_available
    assert "mlx" not in without.backends_available
    assert "demo" in without.backends_available


def test_a_failing_backend_probe_means_unavailable_not_a_crash(cache):
    def boom():
        raise RuntimeError("import exploded")

    host = reg.snapshot_host(cache=cache, mlx_available=boom,
                             system=lambda: "Darwin", machine=lambda: "arm64")
    assert "mlx" not in host.backends_available


def test_memory_detection_degrades_to_none_where_unsupported():
    assert reg.detect_total_memory_bytes(names={}) is None
    assert reg.detect_total_memory_bytes(
        sysconf=lambda name: 0, names={"SC_PHYS_PAGES", "SC_PAGE_SIZE"}
    ) is None


def test_the_snapshot_downloads_nothing(cache, monkeypatch):
    import urllib.request

    def forbidden(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("the registry made a network call")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    reg.snapshot_host(cache=cache, mlx_available=lambda: False,
                      system=lambda: "Darwin", machine=lambda: "arm64")


# --- availability --------------------------------------------------------------------------------

def test_a_cached_model_is_installed(cache):
    _install(cache, QWEN)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert reg.availability_of(identity, _host(), cache) == reg.AVAIL_INSTALLED


def test_a_half_downloaded_model_is_not_installed(cache):
    """The bug a live bake-off found: a directory is not a model.

    A hub cache entry exists from the moment a fetch begins. The registry reported
    ``INSTALLED`` for a build with zero of its four weight shards on disk, a run was
    scheduled against it on that basis, and the run started pulling 24 GB — in a train whose
    explicit constraint was that nothing may be downloaded.
    """
    _install(cache, QWEN, shards=4, present=0)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert cache.snapshot_status(QWEN) == reg.SNAPSHOT_INCOMPLETE
    assert reg.availability_of(identity, _host(), cache) == reg.AVAIL_NOT_INSTALLED


def test_a_model_missing_one_shard_of_many_is_not_installed(cache):
    _install(cache, QWEN, shards=8, present=7)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert reg.availability_of(identity, _host(), cache) == reg.AVAIL_NOT_INSTALLED


def test_every_declared_shard_present_is_installed(cache):
    _install(cache, QWEN, shards=8, present=8)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert cache.snapshot_status(QWEN) == reg.SNAPSHOT_COMPLETE
    assert reg.availability_of(identity, _host(), cache) == reg.AVAIL_INSTALLED


def test_a_single_file_model_without_an_index_is_installed(cache):
    """Not every model ships a shard index; absence of one is not evidence of absence."""
    _install(cache, QWEN, shards=1, present=1, index=False)
    assert cache.snapshot_status(QWEN) == reg.SNAPSHOT_COMPLETE


def test_a_refs_pointer_with_no_snapshot_is_incomplete(cache):
    entry = cache.root / ("models--" + QWEN.replace("/", "--"))
    (entry / "refs").mkdir(parents=True)
    (entry / "refs" / "main").write_text("deadbeef", encoding="utf-8")
    assert cache.snapshot_status(QWEN) == reg.SNAPSHOT_INCOMPLETE


def test_snapshot_status_of_an_unreadable_cache_is_unknown(tmp_path):
    missing = reg.ModelCache(tmp_path / "not-here")
    assert missing.snapshot_status(QWEN) == reg.SNAPSHOT_UNKNOWN


def test_an_uncached_model_is_not_installed_and_is_never_fetched(cache):
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    assert reg.availability_of(identity, _host(), cache) == reg.AVAIL_NOT_INSTALLED
    assert not list(cache.root.iterdir())            # nothing was created


def test_a_model_whose_backend_is_absent_is_unavailable(cache):
    _install(cache, QWEN)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    linux = _host(backends_available=("demo",), active_backend="demo")
    assert reg.availability_of(identity, linux, cache) == reg.AVAIL_UNAVAILABLE


def test_an_unreadable_cache_yields_unknown_availability(tmp_path):
    missing = reg.ModelCache(tmp_path / "nope")
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=missing)
    assert reg.availability_of(identity, _host(), missing) == reg.AVAIL_UNKNOWN


# --- hardware fit ------------------------------------------------------------------------------------

def test_a_model_that_comfortably_fits_reports_fits(cache):
    _install(cache, QWEN, size=8 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    fit = reg.hardware_fit(identity, _host(total_memory_bytes=128 * 1024 ** 3), cache)
    assert fit.verdict == reg.FIT_FITS
    assert fit.required_gb == 8.0


def test_a_model_that_barely_fits_reports_marginal(cache):
    _install(cache, QWEN, size=12 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    fit = reg.hardware_fit(identity, _host(total_memory_bytes=16 * 1024 ** 3), cache)
    assert fit.verdict == reg.FIT_MARGINAL


def test_a_model_larger_than_memory_does_not_fit(cache):
    _install(cache, QWEN, size=60 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    fit = reg.hardware_fit(identity, _host(total_memory_bytes=16 * 1024 ** 3), cache)
    assert fit.verdict == reg.FIT_DOES_NOT_FIT


def test_an_uncached_model_has_unknown_fit_rather_than_a_guess(cache):
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    fit = reg.hardware_fit(identity, _host(), cache)
    assert fit.verdict == reg.FIT_UNKNOWN
    assert fit.required_bytes is None
    assert "not cached" in fit.reason


def test_unknown_memory_yields_unknown_fit(cache):
    _install(cache, QWEN, size=8 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    fit = reg.hardware_fit(identity, _host(total_memory_bytes=None), cache)
    assert fit.verdict == reg.FIT_UNKNOWN


# --- qualification ---------------------------------------------------------------------------------------

def test_the_security_lane_is_unqualified_at_zero_of_two():
    """The measured result, carried through without rounding."""
    art = _artifact("sha256:abc")
    lane = reg.qualify_lane(reg.LANE_SECURITY_REVIEW, art)
    assert lane.state == reg.UNQUALIFIED
    assert lane.evidence == {"security_refusal_correct": 0, "security_refusal_total": 2}
    assert "remove a security control" in lane.reason


def test_the_security_lane_gives_no_partial_credit():
    almost = _artifact("sha256:abc", security_refusal_correct=11, security_refusal_total=12)
    assert reg.qualify_lane(reg.LANE_SECURITY_REVIEW, almost).state == reg.UNQUALIFIED


def test_the_security_lane_is_qualified_only_on_a_perfect_measured_score():
    perfect = _artifact("sha256:abc", security_refusal_correct=12,
                        security_refusal_total=12)
    assert reg.qualify_lane(reg.LANE_SECURITY_REVIEW, perfect).state == reg.QUALIFIED


def test_an_unmeasured_security_lane_is_not_evaluated_not_qualified():
    none_run = _artifact("sha256:abc", security_refusal_correct=0, security_refusal_total=0)
    assert reg.qualify_lane(reg.LANE_SECURITY_REVIEW, none_run).state == reg.NOT_EVALUATED


def test_the_engineering_lane_is_qualified_on_the_measured_numbers():
    lane = reg.qualify_lane(reg.LANE_ENGINEERING, _artifact("sha256:abc"))
    assert lane.state == reg.QUALIFIED
    assert "under review" in lane.reason
    assert lane.evidence["zero_edit_rate"] == 0.72


def test_a_weak_engineering_result_is_advisory_only_not_qualified():
    weak = _artifact("sha256:abc", tests_pass_rate=0.30)
    assert reg.qualify_lane(reg.LANE_ENGINEERING, weak).state == reg.ADVISORY_ONLY


def test_a_dropped_public_api_disqualifies_the_engineering_lane():
    regressed = _artifact("sha256:abc", api_preserved_rate=0.5)
    assert reg.qualify_lane(reg.LANE_ENGINEERING, regressed).state == reg.ADVISORY_ONLY


def test_unmeasured_lanes_say_so_rather_than_borrowing_another_lanes_result():
    art = _artifact("sha256:abc")
    for lane in (reg.LANE_STRATEGY, reg.LANE_GENERAL_REVIEW):
        assert reg.qualify_lane(lane, art).state == reg.NOT_EVALUATED


def test_no_artifact_means_not_evaluated():
    lane = reg.qualify_lane(reg.LANE_ENGINEERING, None)
    assert lane.state == reg.NOT_EVALUATED
    assert "this exact model build" in lane.reason


def test_an_unavailable_model_is_unavailable_in_every_lane():
    art = _artifact("sha256:abc")
    for lane in reg.LANES:
        got = reg.qualify_lane(lane, art, availability=reg.AVAIL_UNAVAILABLE)
        assert got.state == reg.UNAVAILABLE


# --- artifacts --------------------------------------------------------------------------------------------

def test_artifacts_are_keyed_by_fingerprint_not_alias(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({
        "fingerprint": "sha256:aaa", "model": {"route_alias": "engineering"},
        "summary": {"total": 1}, "generated_at": "2026-01-01T00:00:00Z",
    }), encoding="utf-8")
    loaded = reg.load_artifacts(tmp_path)
    assert set(loaded) == {"sha256:aaa"}


def test_a_malformed_artifact_is_skipped_rather_than_crashing(tmp_path):
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "nofp.json").write_text(json.dumps({"summary": {}}), encoding="utf-8")
    (tmp_path / "ok.json").write_text(json.dumps({
        "fingerprint": "sha256:ok", "summary": {"total": 1},
        "generated_at": "2026-01-01T00:00:00Z",
    }), encoding="utf-8")
    assert set(reg.load_artifacts(tmp_path)) == {"sha256:ok"}


def test_the_newest_artifact_for_a_fingerprint_wins(tmp_path):
    for name, when, rate in (("old", "2026-01-01T00:00:00Z", 0.1),
                             ("new", "2026-06-01T00:00:00Z", 0.9)):
        (tmp_path / f"{name}.json").write_text(json.dumps({
            "fingerprint": "sha256:x", "generated_at": when,
            "summary": {"total": 1, "zero_edit_rate": rate},
        }), encoding="utf-8")
    assert reg.load_artifacts(tmp_path)["sha256:x"].metrics["zero_edit_rate"] == 0.9


def test_a_missing_artifact_directory_is_empty_not_an_error(tmp_path):
    assert reg.load_artifacts(tmp_path / "nope") == {}


def test_the_qualification_harness_writes_a_complete_artifact(tmp_path):
    """The metrics have exactly one source; nothing is transcribed by hand."""
    from hermes import qualification as q
    from hermes.qualification_corpus import CORPUS_VERSION, corpus_digest

    outcomes = [q.TaskOutcome("t", "c", q.O_ACCEPTED, parse_valid=True, tests_pass=True)]
    path = q.write_report(
        outcomes, tmp_path / "art.json",
        model={"fingerprint": "sha256:zz", "resolved_model": QWEN},
        source_commit="deadbeef", policy_hash="sha256:pol",
        host={"platform": "Darwin", "architecture": "arm64"},
    )
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["fingerprint"] == "sha256:zz"
    assert body["corpus_version"] == CORPUS_VERSION
    assert body["corpus_digest"] == corpus_digest()
    assert body["source_commit"] == "deadbeef"
    assert body["policy_hash"] == "sha256:pol"
    assert body["host"]["platform"] == "Darwin"
    assert body["generated_at"].endswith("Z")
    assert body["summary"]["total"] == 1
    # And it loads straight back into the registry with no hand transcription.
    assert set(reg.load_artifacts(tmp_path)) == {"sha256:zz"}


def test_an_edited_corpus_is_visibly_a_different_corpus():
    from hermes.qualification_corpus import CORPUS, corpus_digest

    assert corpus_digest() == corpus_digest(CORPUS)
    assert corpus_digest(CORPUS[:5]) != corpus_digest(CORPUS)


# --- the assembled registry -------------------------------------------------------------------------------------

def test_the_registry_describes_every_route(cache):
    _install(cache, QWEN, size=8 * 1024 ** 3)
    built = reg.build_registry(
        {"engineering": QWEN, "strategy": "mlx-community/Other-4bit"},
        backend="mlx", host=_host(), cache=cache,
        artifacts={}, default_alias="strategy", policy_hash="sha256:pol",
    )
    assert [m.identity.route_alias for m in built.models] == ["engineering", "strategy"]
    assert built.by_alias("engineering").availability == reg.AVAIL_INSTALLED
    assert built.by_alias("strategy").availability == reg.AVAIL_NOT_INSTALLED
    assert built.default_alias == "strategy"
    assert set(built.by_alias("engineering").lanes) == set(reg.LANES)


def test_qualification_attaches_by_fingerprint_and_not_by_alias(cache):
    _install(cache, QWEN, size=8 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    built = reg.build_registry(
        {"engineering": QWEN}, backend="mlx", host=_host(), cache=cache,
        artifacts={identity.fingerprint: _artifact(identity.fingerprint)},
    )
    model = built.by_alias("engineering")
    assert model.lanes[reg.LANE_ENGINEERING].state == reg.QUALIFIED
    assert model.lanes[reg.LANE_SECURITY_REVIEW].state == reg.UNQUALIFIED


def test_repointing_an_alias_drops_the_inherited_qualification(cache):
    """A new build starts unmeasured; a reputation is not transferable."""
    _install(cache, QWEN, size=8 * 1024 ** 3)
    old = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    artifacts = {old.fingerprint: _artifact(old.fingerprint)}

    _install(cache, "mlx-community/Brand-New-8bit", size=8 * 1024 ** 3)
    built = reg.build_registry(
        {"engineering": "mlx-community/Brand-New-8bit"}, backend="mlx",
        host=_host(), cache=cache, artifacts=artifacts,
    )
    assert built.by_alias("engineering").lanes[reg.LANE_ENGINEERING].state == (
        reg.NOT_EVALUATED
    )


# --- the authority firewall -------------------------------------------------------------------------------------------

def test_no_authorization_module_imports_the_registry():
    """Capability informs routing. Capability never informs authority."""
    repo = Path(__file__).resolve().parents[2]
    guarded = [
        "src/private_ai_gateway/policy.py",
        "src/private_ai_gateway/autonomy.py",
        "src/private_ai_gateway/approvals.py",
        "src/private_ai_gateway/approvals_sqlite.py",
        "src/private_ai_gateway/guardrails.py",
        "src/private_ai_gateway/disposition.py",
        "src/private_ai_gateway/reconciliation.py",
        "src/private_ai_gateway/canonical.py",
    ]
    for rel in guarded:
        source = (repo / rel).read_text(encoding="utf-8")
        for forbidden in ("registry", "qualification", "QUALIFIED", "hardware_fit"):
            assert forbidden not in source, f"{rel} reaches capability data ({forbidden})"


def test_the_registry_module_reaches_no_authorization_primitive():
    source = (
        Path(__file__).resolve().parents[2] / "src/private_ai_gateway/registry.py"
    ).read_text(encoding="utf-8")
    body = source.split('"""', 2)[-1]         # exclude the module docstring's own prose
    for forbidden in (
        "max_autonomy", "allowed_skills", "allowed_tools", "validate_for_execute",
        "decide_approval", "create_pending_approval", "mark_used", "invalidate_run",
    ):
        assert forbidden not in body, forbidden


def test_a_qualified_model_grants_no_extra_authority(tmp_path, monkeypatch):
    """The same principal gets the same ceiling whether or not its model is qualified."""
    install_demo_plane(gw)
    principal = gw.POLICY.identify(TOKENS["shadow-engineer"])
    before = (
        principal.max_autonomy_level,
        frozenset(principal.allowed_skills),
        frozenset(principal.allowed_tools),
    )
    cache = reg.ModelCache(tmp_path / "hub")
    (tmp_path / "hub").mkdir()
    _install(cache, QWEN, size=8 * 1024 ** 3)
    identity = reg.identify_model("engineering", QWEN, backend="mlx", cache=cache)
    reg.build_registry(
        {"engineering": QWEN}, backend="mlx", host=_host(), cache=cache,
        artifacts={identity.fingerprint: _artifact(
            identity.fingerprint, security_refusal_correct=2, security_refusal_total=2
        )},
    )
    after = gw.POLICY.identify(TOKENS["shadow-engineer"])
    assert (after.max_autonomy_level, frozenset(after.allowed_skills),
            frozenset(after.allowed_tools)) == before


# --- the endpoint ----------------------------------------------------------------------------------------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    install_demo_plane(gw)
    monkeypatch.setattr(gw, "AUTH_TOKEN", _OWNER_TOKEN)
    monkeypatch.setattr(gw, "QUALIFICATION_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    return gw.app.test_client()


def test_the_registry_endpoint_is_owner_gated(client):
    denied = client.get("/v1/models/registry",
                        headers={"Authorization": f"Bearer {TOKENS['hermes']}"})
    assert denied.status_code == 403
    assert denied.get_json()["error"]["code"] == "owner_required"


def test_the_registry_endpoint_describes_the_routes(client):
    body = client.get("/v1/models/registry", headers=OWNER).get_json()
    assert {lane["lane"] for lane in body["lanes"]} == set(reg.LANES)
    aliases = {m["identity"]["route_alias"] for m in body["models"]}
    assert {"strategy", "engineering", "offsec"} <= aliases
    for model in body["models"]:
        assert model["identity"]["fingerprint"].startswith("sha256:")
        assert model["availability"] in (
            reg.AVAIL_INSTALLED, reg.AVAIL_NOT_INSTALLED, reg.AVAIL_UNKNOWN,
            reg.AVAIL_UNAVAILABLE,
        )
        assert model["fit"]["verdict"] in (
            reg.FIT_FITS, reg.FIT_MARGINAL, reg.FIT_DOES_NOT_FIT, reg.FIT_UNKNOWN
        )


def test_the_endpoint_leaks_no_host_identifiers(client):
    blob = json.dumps(client.get("/v1/models/registry", headers=OWNER).get_json())
    for forbidden in (str(Path.home()), "/Users/", "/home/", "serial", "uuid"):
        assert forbidden not in blob, forbidden


def test_the_endpoint_grants_nothing_and_downloads_nothing(client, monkeypatch):
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("the registry endpoint made a network call")
    ))
    body = client.get("/v1/models/registry", headers=OWNER).get_json()
    blob = json.dumps(body)
    for forbidden in ("max_autonomy", "allowed_skills", "allowed_tools", "approval"):
        assert forbidden not in blob, forbidden
