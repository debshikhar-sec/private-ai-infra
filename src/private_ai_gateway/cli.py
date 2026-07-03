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

from private_ai_gateway import __version__


def _serve(args: argparse.Namespace) -> int:
    import os

    # Backend selection happens at app import, so flags must land in the
    # environment first. Imported lazily so `version`/`--help` stay instant.
    if args.backend:
        os.environ["PRIVATE_AI_BACKEND"] = args.backend
    if args.upstream_base_url:
        os.environ["PRIVATE_AI_UPSTREAM_BASE_URL"] = args.upstream_base_url

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
    serve.add_argument(
        "--backend",
        choices=["auto", "mlx", "openai", "demo"],
        default=None,
        help="Inference backend (default: auto — upstream URL, then MLX, then demo).",
    )
    serve.add_argument(
        "--upstream-base-url",
        default=None,
        help="OpenAI-compatible upstream, e.g. https://llm.internal/v1 or "
        "http://127.0.0.1:11434/v1 (Ollama). Pass the upstream API key via "
        "PRIVATE_AI_UPSTREAM_API_KEY, never on the command line.",
    )
    serve.set_defaults(func=_serve)

    demo = sub.add_parser(
        "demo",
        help="One-command starter kit: demo policy + offline backend + scripted "
        "governed traffic, then serve the Governance Console.",
    )
    demo.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1).")
    demo.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080).")
    demo.add_argument(
        "--no-serve", action="store_true",
        help="Run the scripted traffic and exit (CI / smoke-test mode).",
    )
    demo.set_defaults(
        func=lambda a: __import__(
            "private_ai_gateway.demo", fromlist=["main"]
        ).main(a.host, a.port, serve=not a.no_serve)
    )

    scan = sub.add_parser(
        "scan",
        help="Scan installed (or manifest-listed) dependencies for known AI-stack CVEs, "
        "with a SonarQube-style severity gate.",
    )
    scan.add_argument(
        "--manifest",
        default=None,
        help="JSON manifest {\"packages\": {name: version}} to scan instead of the live "
        "environment (use 'demo' for the packaged deliberately-vulnerable AI stack).",
    )
    scan.add_argument(
        "--gate",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Fail (exit 1) if any finding is at this severity or above (default: high).",
    )
    scan.add_argument(
        "--live", action="store_true",
        help="Also query OSV.dev over the network for current breadth (opt-in).",
    )
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.set_defaults(func=_scan)

    ver = sub.add_parser("version", help="Print the version and exit.")
    ver.set_defaults(func=lambda _a: (print(__version__) or 0))

    return p


def _scan(args: argparse.Namespace) -> int:
    import importlib.resources
    import json

    from private_ai_gateway import vulnintel

    if args.manifest == "demo":
        raw = importlib.resources.files("private_ai_gateway").joinpath(
            "demo_sbom.json"
        ).read_text(encoding="utf-8")
        packages = json.loads(raw).get("packages", {})
    elif args.manifest:
        with open(args.manifest, encoding="utf-8") as fh:
            packages = json.load(fh).get("packages", {})
    else:
        packages = vulnintel.installed_packages()

    normalized = {vulnintel._normalize(n): v for n, v in packages.items()}
    if args.live:
        try:
            report = vulnintel.scan_live(normalized, gate_threshold=args.gate)
        except vulnintel.OSVError as exc:
            print(f"live OSV scan failed ({exc}); falling back to offline snapshot.")
            report = vulnintel.scan_packages(normalized, gate_threshold=args.gate)
    else:
        report = vulnintel.scan_packages(normalized, gate_threshold=args.gate)

    print(report.to_json() if args.format == "json" else report.to_text(), end="")
    return report.exit_code()


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
