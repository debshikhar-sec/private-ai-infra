"""OpenCode — the implementer component of the control plane.

OpenCode reviews and *proposes* changes; it does not hold authority to apply them.
Two halves:

  - the **review** harness (`run_review.sh`) runs OpenCode capability-denied and
    read-only against a copy of a target, and proves via manifests it changed nothing;
  - the **act** step (`opencode_sandbox.apply` / `opencode_sandbox.act`) takes a
    *proposed* change set, refuses to apply it without an explicit, separately-sourced
    approval (fail closed), applies it only inside a confined sandbox copy, and verifies
    that exactly the declared files changed — capability to propose is not authority to
    apply, and here that is mechanical.
"""

__version__ = "0.11.0"
