"""Hermes — the planning component of the control plane.

Hermes plans; it does not execute. It reads persistent memory, delegates one planning
call to the gateway as the ``hermes`` principal (capped at autonomy L1 / suggest), and
records the resulting plan back to memory. It also runs the verification step
(``hermes.verify``) that folds OpenClaw's assurance verdict back into memory, so the
next planning cycle plans from verified state.
"""

__version__ = "0.8.0"
