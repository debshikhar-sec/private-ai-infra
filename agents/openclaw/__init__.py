"""OpenClaw — the assurance component of the control plane.

OpenClaw verifies; it does not act. It reads the evidence the governance plane
already produces — the decision audit, the metrics, OpenCode's isolation manifests,
and the policy — and emits a structured assurance report: one PASS / FAIL /
INCONCLUSIVE finding per control. It runs **observe-only (autonomy L0)** and holds no
authority to change anything; its output is evidence, not action.

The design principle (from the project's own roadmap) is that the *verifier should be
defined before the implementer's authority is widened* — assurance before execution.
"""

__version__ = "0.12.0"
