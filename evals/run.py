"""Security eval runner.

Drives the whole attack catalogue against the gateway's enforced controls and emits a
pass/fail report. Two layers run:

  - **egress probes** use only the gateway's `Guardrails` (pure Python), so they run
    anywhere — including Linux CI;
  - **request-level probes** drive the real gateway via a Flask test client, which imports
    MLX; where MLX is unavailable those probes are reported SKIP rather than passed.

The runner configures the gateway's policy with the harness's own test identities first,
so every attack is judged against the real enforcement path. Exits non-zero on FAIL.

Usage:
    PYTHONPATH=src python -m evals.run                 # text report
    PYTHONPATH=src python -m evals.run --format json --output evals.json
    PYTHONPATH=src python -m evals.run --require-gateway   # fail if gateway probes can't run
"""

from __future__ import annotations

import argparse
import sys

from evals.cases import ALL_CASES, IDENTITIES
from evals.harness import SKIP, Context, Observation, run_suite
from evals.report import build_report


def make_flask_transport(client):
    """Adapt a Flask test client to the harness Transport signature."""

    def transport(method, path, *, headers=None, json=None) -> Observation:
        fn = getattr(client, method.lower())
        resp = fn(path, headers=headers or {}, json=json)
        code = ""
        data = resp.get_json(silent=True)
        if isinstance(data, dict):
            code = (data.get("error") or {}).get("code", "") or ""
        return Observation(status=resp.status_code, code=code, body=resp.get_data(as_text=True))

    return transport


def build_gateway_transport():
    """Configure the gateway policy with test identities and return a transport.

    Returns ``None`` if the gateway cannot be imported (e.g. MLX absent), so the
    request-level probes report SKIP instead of failing the run.
    """
    try:
        from private_ai_gateway import app as gw
        from private_ai_gateway.policy import Policy, Principal, hash_token
        from private_ai_gateway.ratelimit import RateLimiter
    except Exception:
        return None

    principals = {
        hash_token(idt.token): Principal(
            idt.name,
            frozenset(idt.allowed_models),
            None,
            idt.requests_per_minute,
            idt.max_autonomy_level,
            allowed_skills=frozenset(idt.allowed_skills),
            allowed_tools=frozenset(idt.allowed_tools),
        )
        for idt in IDENTITIES
    }
    gw.POLICY = Policy(principals)
    gw.AUTH_TOKEN = ""  # nosec B105 — empties the owner break-glass fallback during evals
    gw.RATE_LIMITER = RateLimiter(0)  # default unlimited; per-principal rpm still enforced
    return make_flask_transport(gw.app.test_client())


def _build_guardrails():
    from private_ai_gateway.guardrails import Guardrails

    return Guardrails("redact")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evals.run", description="Adversarial security evals")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--output", help="Write the report to this file instead of stdout")
    p.add_argument(
        "--require-gateway",
        action="store_true",
        help="Fail (exit 2) if the gateway transport is unavailable instead of skipping",
    )
    return p


def main(argv: list[str] | None = None, *, transport_factory=build_gateway_transport) -> int:
    args = build_parser().parse_args(argv)

    transport = transport_factory()
    if transport is None and args.require_gateway:
        print(
            "error: gateway transport unavailable (MLX not importable) and --require-gateway set",
            file=sys.stderr,
        )
        return 2

    ctx = Context(transport=transport, guardrails=_build_guardrails())
    report = build_report(run_suite(ALL_CASES, ctx))

    rendered = {
        "json": report.to_json,
        "markdown": report.to_markdown,
        "text": report.to_text,
    }[args.format]()

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"[evals] {report.verdict} — report written to {args.output}", file=sys.stderr)
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    skipped = report.counts().get(SKIP, 0)
    if skipped:
        print(
            f"[evals] note: {skipped} request-level probe(s) SKIPPED "
            "(gateway/MLX unavailable here — run on Apple Silicon for full coverage).",
            file=sys.stderr,
        )
    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
