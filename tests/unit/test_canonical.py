"""Canonical plan hashing vectors — enforces docs/canonical-plan-hashing.md.

Tests assert the *exact* canonical bytes for the documented Example A, digest
determinism and format, and digest inequality under any authority-bearing change. Per the
spec, placeholder digests (``sha256:<A>``) are never asserted against — only the canonical
byte string is fixed; the digest is checked for shape and stability, then for divergence.
"""

import re

import pytest

from private_ai_gateway import canonical
from private_ai_gateway.canonical import CanonicalizationError, canonicalize

# The exact canonical JSON string documented in docs/canonical-plan-hashing.md §6,
# after the accepted tightenings (incl. resource_root_id, path normalization of
# "./sample_handler.py" -> "sample_handler.py").
EXPECTED_CANONICAL_JSON = (
    '{"canonicalization_version":1,'
    '"constraints":{"no_commit":true,"sandbox_only":true},'
    '"data_sensitivity":null,'
    '"delegation":{"delegation_chain":[{"delegatee":"opencode","delegator":"hermes",'
    '"granted_level":3,"skill":"code.apply"}],"delegation_id":"dg-0973d10825fc",'
    '"depth":1,"parent_task_id":null},'
    '"effective_autonomy":3,'
    '"environment":"demo",'
    '"executor":"opencode",'
    '"objective_normalized":"review sample_handler.py for issues",'
    '"plan_schema_version":1,'
    '"policy_hash":"sha256:PP",'
    '"policy_version":"demo-1",'
    '"principal_id":"hermes",'
    '"requested_autonomy":3,'
    '"resource_root_id":"sandbox/run_20260705_011853",'
    '"skill":"code.apply",'
    '"target_resources":["sample_handler.py"],'
    '"task_class":"code_apply"}'
)

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def base_kwargs() -> dict:
    """Example A from the spec."""
    return dict(
        canonicalization_version=1,
        plan_schema_version=1,
        objective="review sample_handler.py for issues",
        principal_id="hermes",
        executor="opencode",
        skill="code.apply",
        task_class="code_apply",
        requested_autonomy=3,
        effective_autonomy=3,
        policy_version="demo-1",
        policy_hash="sha256:PP",
        resource_root_id="sandbox/run_20260705_011853",
        target_resources=["./sample_handler.py"],
        environment="demo",
        delegation={
            "delegation_id": "dg-0973d10825fc",
            "parent_task_id": None,
            "delegation_chain": [
                {
                    "delegator": "hermes",
                    "delegatee": "opencode",
                    "skill": "code.apply",
                    "granted_level": 3,
                }
            ],
            "depth": 1,
        },
        constraints={"no_commit": True, "sandbox_only": True},
        data_sensitivity=None,
    )


def digest(**overrides) -> str:
    kw = base_kwargs()
    kw.update(overrides)
    return canonicalize(**kw).digest


# 1 — exact canonical bytes
def test_example_a_canonical_bytes_exact():
    plan = canonicalize(**base_kwargs())
    assert plan.canonical_json == EXPECTED_CANONICAL_JSON
    assert plan.canonical_bytes == EXPECTED_CANONICAL_JSON.encode("utf-8")


# 2 — stable digest across repeated calls
def test_digest_is_stable():
    assert canonicalize(**base_kwargs()).digest == canonicalize(**base_kwargs()).digest


# 3 — digest format
def test_digest_format():
    assert DIGEST_RE.match(canonicalize(**base_kwargs()).digest)


# 4 — executor
def test_executor_change_changes_digest():
    assert digest(executor="opencode-2") != digest()


# 5 — skill
def test_skill_change_changes_digest():
    assert digest(skill="code.review") != digest()


# 6 — autonomy fields
def test_requested_autonomy_change_changes_digest():
    assert digest(requested_autonomy=2) != digest()


def test_effective_autonomy_change_changes_digest():
    assert digest(effective_autonomy=4) != digest()


# 7 — resource_root_id (same relative path, different root)
def test_resource_root_id_change_changes_digest():
    assert digest(resource_root_id="sandbox/other_root") != digest()


# 8 — target_resources
def test_target_resources_change_changes_digest():
    assert digest(target_resources=["./other_handler.py"]) != digest()


# 9 — policy_hash
def test_policy_hash_change_changes_digest():
    assert digest(policy_hash="sha256:QQ") != digest()


# 10 — delegation fields
def test_delegation_id_change_changes_digest():
    d = base_kwargs()["delegation"]
    d = {**d, "delegation_id": "dg-different"}
    assert digest(delegation=d) != digest()


def test_delegation_granted_level_change_changes_digest():
    d = base_kwargs()["delegation"]
    chain = [{**d["delegation_chain"][0], "granted_level": 5}]
    assert digest(delegation={**d, "delegation_chain": chain}) != digest()


def test_delegation_delegatee_change_changes_digest():
    d = base_kwargs()["delegation"]
    chain = [{**d["delegation_chain"][0], "delegatee": "someone_else"}]
    assert digest(delegation={**d, "delegation_chain": chain}) != digest()


def test_delegation_chain_extra_hop_changes_digest():
    d = base_kwargs()["delegation"]
    chain = d["delegation_chain"] + [
        {"delegator": "opencode", "delegatee": "openclaw",
         "skill": "assurance.verify", "granted_level": 2}
    ]
    assert digest(delegation={**d, "delegation_chain": chain, "depth": 2}) != digest()


# 11 — volatile fields are not part of CanonicalPlan
def test_volatile_fields_not_accepted_and_digest_unaffected():
    # request_id / timestamp / detail are structurally excluded: passing them errors.
    with pytest.raises(TypeError):
        canonicalize(**base_kwargs(), request_id="req-123")
    with pytest.raises(TypeError):
        canonicalize(**base_kwargs(), created_at="2026-07-05T00:00:00Z")
    with pytest.raises(TypeError):
        canonicalize(**base_kwargs(), detail="some narration")
    # And a caller who merely *has* such context still gets the same digest.
    assert digest() == digest()


# 12 — canonicalization_version
def test_unsupported_canonicalization_version_fails_closed():
    with pytest.raises(CanonicalizationError):
        digest(canonicalization_version=2)


# 13 — plan_schema_version
def test_unsupported_plan_schema_version_fails_closed():
    with pytest.raises(CanonicalizationError):
        digest(plan_schema_version=2)


# 14 — non-allowlisted constraint key
def test_non_allowlisted_constraint_fails_closed():
    with pytest.raises(CanonicalizationError):
        digest(constraints={"exfiltrate": True})


# 15 — wrong constraint types
def test_wrong_constraint_type_fails_closed():
    with pytest.raises(CanonicalizationError):
        digest(constraints={"no_commit": "yes"})
    # bool must not satisfy an int-typed constraint
    with pytest.raises(CanonicalizationError):
        digest(constraints={"max_files": True})


# 16 — secrets/tokens cannot enter via unsupported fields, and are absent from the bytes
def test_secret_cannot_enter_canonical_bytes():
    with pytest.raises(TypeError):
        canonicalize(**base_kwargs(), secret_token="AKIAIOSFODNN7EXAMPLE")
    plan = canonicalize(**base_kwargs())
    assert "AKIA" not in plan.canonical_json
    assert b"AKIA" not in plan.canonical_bytes


# Extra: path normalization is lossless-relative and de-duplicates as a set
def test_target_resources_are_set_normalized_and_order_independent():
    a = digest(target_resources=["./a.py", "b.py"])
    b = digest(target_resources=["b.py", "a.py", "./a.py"])
    assert a == b


# Extra: a path escaping the declared root fails closed
def test_path_escaping_root_fails_closed():
    with pytest.raises(CanonicalizationError):
        digest(target_resources=["../escape.py"])


# Extra: the module-level version constants are the pinned baseline
def test_version_constants_pinned():
    assert canonical.CANONICALIZATION_VERSION == 1
    assert 1 in canonical.SUPPORTED_SCHEMA_VERSIONS
