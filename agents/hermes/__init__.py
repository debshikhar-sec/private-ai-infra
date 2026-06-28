"""Hermes — the planning component of the control plane.

Hermes plans; it does not execute. It reads persistent memory, delegates one planning
call to the gateway as the ``hermes`` principal (capped at autonomy L1 / suggest), and
records the resulting plan back to memory.
"""

__version__ = "0.6.0"
