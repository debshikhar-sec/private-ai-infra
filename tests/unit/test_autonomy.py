"""Unit tests for the autonomy ladder parsing and policy loading (pure logic)."""

from private_ai_gateway import autonomy
from private_ai_gateway.policy import Policy, hash_token


def test_parse_level_accepts_forms():
    assert autonomy.parse_level("L3") == 3
    assert autonomy.parse_level("3") == 3
    assert autonomy.parse_level(3) == 3
    assert autonomy.parse_level("l0") == 0


def test_parse_level_rejects_out_of_range_and_garbage():
    assert autonomy.parse_level("L9") is None
    assert autonomy.parse_level("-1") is None
    assert autonomy.parse_level("nonsense") is None
    assert autonomy.parse_level(None) is None
    assert autonomy.parse_level(None, default=1) == 1


def test_level_name():
    assert autonomy.level_name(0) == "observe"
    assert autonomy.level_name(6) == "unbounded"
    assert autonomy.level_name(None) == "unset"


def test_policy_loads_principal_and_default_autonomy(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(
        "[[principals]]\n"
        'name = "analyst"\n'
        f'key_sha256 = "{hash_token("k1")}"\n'
        'allowed_models = ["strategy"]\n'
        'max_autonomy_level = "L1"\n'
        "\n"
        "[autonomy]\n"
        'default_max_level = "L2"\n'
    )
    pol = Policy.load(str(p))
    assert pol.default_max_autonomy_level == 2
    who = pol.identify("k1")
    assert who is not None and who.max_autonomy_level == 1


def test_policy_without_autonomy_section_is_unset(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(
        "[[principals]]\n"
        'name = "a"\n'
        f'key_sha256 = "{hash_token("k")}"\n'
        'allowed_models = ["strategy"]\n'
    )
    pol = Policy.load(str(p))
    assert pol.default_max_autonomy_level is None
    assert pol.identify("k").max_autonomy_level is None
