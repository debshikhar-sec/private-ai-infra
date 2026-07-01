"""Console entry point for the gateway: ``private-ai-gateway <command>``.

Installed as a script via ``pyproject.toml`` so a user can ``pip install`` the package
and run it directly, without the Makefile or the nginx wrapper:

    pip install private-ai-gateway      # (Apple Silicon / MLX)
    export PRIVATE_AI_AUTH_TOKEN=...     # fail-closed: required to serve
    private-ai-gateway serve             # Flask on 127.0.0.1:8080 (loopback)

``serve`` runs the Flask app directly (loopback only). For the hardened loopback boundary
with the nginx reverse proxy, use ``make start`` as before — this entry point is the
zero-dependency path for local use.
"""

from __future__ import annotations

import argparse

__version__ = "0.14.0"


def _serve(args: argparse.Namespace) -> int:
    # Imported lazily so `version`/`--help` work without importing MLX.
    from private_ai_gateway import app as gw

    if not gw.AUTH_TOKEN:
        raise SystemExit(
            "PRIVATE_AI_AUTH_TOKEN is not set. Refusing to start the gateway without an "
            "auth token. Set it in your environment or .env (see .env.example)."
        )
    if gw.AUTH_TOKEN == gw._DEV_DEFAULT_TOKEN:
        gw.logger.warning(
            "AUTH_TOKEN_IS_DEV_DEFAULT | Using the documented development token; "
            "set a unique PRIVATE_AI_AUTH_TOKEN before any real use."
        )
    # Single process/thread avoids multiple MLX model copies.
    gw.app.run(host=args.host, port=args.port, threaded=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="private-ai-gateway",
        description="Local-first AI governance plane — OpenAI-compatible gateway with "
        "policy-as-code identity, an enforced autonomy ceiling, A2A/MCP governance, and a "
        "decision audit.",
    )
    p.add_argument("--version", action="version", version=f"private-ai-gateway {__version__}")
    sub = p.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Run the gateway on loopback (Flask).")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    serve.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080).")
    serve.set_defaults(func=_serve)

    ver = sub.add_parser("version", help="Print the version and exit.")
    ver.set_defaults(func=lambda _a: (print(__version__) or 0))

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0
    return func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
