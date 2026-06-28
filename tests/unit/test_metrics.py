"""Unit tests for the hand-rolled Prometheus metrics registry."""

from private_ai_gateway.metrics import Metrics


def test_registered_counter_renders_at_zero():
    m = Metrics()
    m.register("gateway_requests_total", "help text")
    out = m.render()
    assert "# HELP gateway_requests_total help text" in out
    assert "# TYPE gateway_requests_total counter" in out
    assert "gateway_requests_total 0" in out


def test_labeled_increments_accumulate_independently():
    m = Metrics()
    m.inc("reqs", {"decision": "allow"})
    m.inc("reqs", {"decision": "allow"})
    m.inc("reqs", {"decision": "deny"})
    out = m.render()
    assert 'reqs{decision="allow"} 2' in out
    assert 'reqs{decision="deny"} 1' in out


def test_label_values_are_escaped():
    m = Metrics()
    m.inc("c", {"k": 'a"b'})
    assert 'c{k="a\\"b"} 1' in m.render()


def test_multiple_labels_sorted_deterministically():
    m = Metrics()
    m.inc("c", {"principal": "analyst", "decision": "allow"})
    # Labels render in sorted key order, so output is stable.
    assert 'c{decision="allow",principal="analyst"} 1' in m.render()
