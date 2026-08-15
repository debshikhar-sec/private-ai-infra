#!/usr/bin/env python3
"""
OpenAI-compatible AI governance gateway
Client -> (nginx) -> Flask enforcement plane -> inference backend

The enforcement plane (identity, policy, autonomy ceilings, guardrails, audit) is
model-plane-agnostic: the backend may be in-process MLX, any OpenAI-compatible
upstream (an enterprise LLM-as-a-Service platform, vLLM, Ollama, …), or an offline
demo simulator. See backends.py.
"""

import atexit
import hashlib
import hmac
import importlib.resources
import json
import logging
import os
import re
import sys
import time
import uuid

from flask import Flask, Response, g, jsonify, request

from private_ai_gateway import a2a, autonomy, backends, contextopt, delegation, siem, state, tools
from private_ai_gateway.approvals import ApprovalError
from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.guardrails import Guardrails
from private_ai_gateway.ingress import IngressFirewall
from private_ai_gateway.logutil import log_safe
from private_ai_gateway.metrics import Metrics
from private_ai_gateway.policy import Policy, Principal
from private_ai_gateway.ratelimit import RateLimiter

app = Flask(__name__)

# Bound the request body to prevent unbounded-memory input DoS (default 8 MiB).
app.config["MAX_CONTENT_LENGTH"] = int(
    os.environ.get("PRIVATE_AI_MAX_CONTENT_LENGTH", str(8 * 1024 * 1024))
)

# -----------------------------
# Config
# -----------------------------
# Fail-closed: the gateway refuses to start without an auth token (enforced in
# __main__). The documented development default lives in the launcher / .env,
# never baked into the server itself.
_DEV_DEFAULT_TOKEN = "private-portfolio-token"  # documented dev default, not a secret  # nosec B105
AUTH_TOKEN = os.environ.get("PRIVATE_AI_AUTH_TOKEN", "").strip()

# Project root is three levels up: src/private_ai_gateway/app.py -> <root>
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.environ.get("PRIVATE_AI_LOG_DIR", os.path.join(_PROJECT_ROOT, "logs"))
AUDIT_LOG_PATH = os.path.join(LOG_DIR, "audit.log")
os.makedirs(LOG_DIR, exist_ok=True)

# -----------------------------
# Governance: policy-as-code identity + authorization
# -----------------------------
POLICY_PATH = os.environ.get(
    "PRIVATE_AI_POLICY_PATH", os.path.join(_PROJECT_ROOT, "config", "policy.toml")
)
POLICY = Policy.load(POLICY_PATH)

# Cross-cutting controls, all driven by the same policy file:
#   * RATE_LIMITER bounds request volume per principal (token bucket).
#   * GUARDRAILS filters secret-like content out of model responses (egress).
RATE_LIMITER = RateLimiter(POLICY.default_requests_per_minute)
GUARDRAILS = Guardrails(POLICY.guardrail_action)
#   * INGRESS is the inbound AI-firewall (prompt-injection / jailbreak / PII), the
#     mirror of GUARDRAILS on the way in. Off by default; opt in via [ingress] policy.
INGRESS = IngressFirewall(POLICY.ingress_action, block_threshold=POLICY.ingress_block_threshold)

# Observability: in-process Prometheus counters exposed at /metrics.
METRICS = Metrics()
METRICS.register("gateway_requests_total", "Terminal request decisions by principal.")
METRICS.register("gateway_authz_denials_total", "Authorization denials by reason.")
METRICS.register("gateway_rate_limited_total", "Requests rejected by the rate limiter.")
METRICS.register("gateway_guardrail_events_total", "Responses that tripped an egress guardrail.")
METRICS.register("gateway_ingress_events_total", "Inbound prompts flagged by the ingress firewall, by category.")
METRICS.register("gateway_a2a_tasks_total", "A2A delegation decisions by decision.")
METRICS.register("gateway_tool_calls_total", "MCP tool-call decisions by decision.")
METRICS.register("gateway_orchestrate_total", "Governed Chat Console orchestration phases run.")
METRICS.register(
    "gateway_context_tokens_saved_total",
    "Prompt tokens saved by deterministic context compression (measured or applied).",
)
METRICS.register(
    "gateway_siem_events_total",
    "SIEM webhook export outcomes (delivered / failed / dropped).",
)

# SIEM push export (off unless [siem] webhook_url is set in policy): every decision
# event is forwarded to the collector off the hot path, HMAC-signed when a secret is
# configured. The decision log itself stays the local source of truth either way.
SIEM = siem.from_policy(
    POLICY.siem_webhook_url,
    POLICY.siem_secret_env,
    on_outcome=lambda outcome: METRICS.inc(
        "gateway_siem_events_total", {"outcome": outcome}
    ),
)
DECISION_LOG = DecisionLog(os.path.join(LOG_DIR, "decisions.jsonl"), forwarder=SIEM)

# Authority store for the governed chat loop. The backend is selected by
# PRIVATE_AI_STATE_BACKEND (default "memory"): "memory" is the in-process, restart-forgetting
# ApprovalStore (byte-identical to before); "sqlite" opens a durable single-node store under
# PRIVATE_AI_STATE_DIR (Step 7A). Store selection changes *durability only* — the governed
# lifecycle, ordering, and authorization semantics are unchanged.
_STATE_CONFIG = state.StateConfig.from_env(os.environ)
_OPENED_BACKEND = state.open_backend(_STATE_CONFIG, environ=os.environ)
APPROVAL_STORE = _OPENED_BACKEND.authority_store

# Gateway authorization evidence (Steps 5/5b emit points; Step 7B.0 live durable wiring).
# The gateway emits signed authorization records into a verifier-owned EvidenceSink at two
# points: `execute_validated` when execution authority is granted (orchestration._run_execute)
# and `approval_decided` when an approval decision is recorded (v1_approvals).
#
# Default (PRIVATE_AI_EVIDENCE_MODE=off): no sink — behavior is byte-identical to before, and
# no key material is loaded. Tests may still inject a sink/key onto this module directly.
#
# Durable mode (PRIVATE_AI_EVIDENCE_MODE=durable, Step 7B.0): open_backend returned a LIVE
# durable sink constructed by assurance-owned code (openclaw.assurance — the gateway never
# builds or holds the verification registry). The gateway loads only its OWN emitter signing
# key; REQUIRE_AUTHORIZATION_EVIDENCE is forced True (durable mode IS the hardened
# configuration — a configured-but-failing emit fails closed *before* the outcome it guards),
# and EVIDENCE_RUNTIME_WIRED threads the sink through the execution session so OpenCode's
# signed apply_result lands in the same durable chain and OpenClaw verifies from it.
EVIDENCE_SINK = _OPENED_BACKEND.evidence_sink
if EVIDENCE_SINK is not None:
    from openclaw import assurance as _assurance  # importable: open_backend already used it
    from openclaw.sink import EMITTER_GATEWAY as _EMITTER_GATEWAY

    EVIDENCE_KEY, EVIDENCE_KEY_ID = _assurance.emitter_signing_key(
        os.environ, _EMITTER_GATEWAY
    )
    REQUIRE_AUTHORIZATION_EVIDENCE = True
    EVIDENCE_RUNTIME_WIRED = True
else:
    EVIDENCE_KEY = None
    EVIDENCE_KEY_ID = ""
    REQUIRE_AUTHORIZATION_EVIDENCE = False
    EVIDENCE_RUNTIME_WIRED = False

# Step 7C.3B — the one directory a governed rollback may read a pre-image from. A rollback
# request names a workspace *relative to* this root and nothing else, so no caller can point
# a restore at a tree outside the sandbox runtime. Unset means rollback is unavailable, which
# is the correct default: a runtime with no sandbox root has nothing it may safely restore.
SANDBOX_RUNTIME_ROOT = os.environ.get("PRIVATE_AI_SANDBOX_RUNTIME_DIR", "")

# Where recorded qualification artifacts are read from. Read-only and descriptive: these are
# measurements of what a model can do, never evidence and never authority. No authorization
# path may consult them (see ``registry`` and its structural test).
QUALIFICATION_ARTIFACT_DIR = os.environ.get(
    "PRIVATE_AI_QUALIFICATION_DIR", "runtime/qualification"
)

# Managed route revisions. This directory is written by the gateway; ``config/policy.toml``
# never is. The effective configuration is base policy + active revision, and the effective
# policy hash is derived over both — see ``route_revision``.
ROUTE_REVISION_DIR = os.environ.get(
    "PRIVATE_AI_ROUTE_REVISION_DIR", os.path.join(_PROJECT_ROOT, "runtime", "route-revisions")
)

# Release both stores' connections and ownership locks on interpreter shutdown. (Process
# death releases the flocks anyway; this makes a *clean* shutdown explicit.)
atexit.register(_OPENED_BACKEND.close)

# Delegation ledger: the lifecycle state for governed agent-to-agent hand-offs.
# Enforcement outcomes (allow/deny + reason) go to DECISION_LOG like everything else.
DELEGATIONS = delegation.DelegationLedger()

# The owner token (PRIVATE_AI_AUTH_TOKEN) maps to this break-glass admin identity:
# every model, no token/rate cap, and the top of the autonomy ladder (L6). Finer-grained
# restrictions come from POLICY principals.
OWNER_PRINCIPAL = Principal(
    "owner",
    frozenset({"*"}),
    max_output_tokens=None,
    requests_per_minute=None,
    max_autonomy_level=autonomy.MAX_LEVEL,
    allowed_skills=frozenset({"*"}),
    allowed_tools=frozenset({"*"}),
    can_read_audit=True,
)


def autonomy_ceiling_for(principal: Principal) -> int | None:
    """The principal's effective autonomy ceiling: its own, else the policy default."""
    ceiling = principal.max_autonomy_level
    return POLICY.default_max_autonomy_level if ceiling is None else ceiling

# Model routing: alias -> backend model id. The defaults are the MLX line-up; a
# ``[models.routes]`` table in policy.toml overrides/extends them, which is how the
# same aliases point at an upstream platform's model ids in openai-backend mode.
DEFAULT_ROUTE_MAP = {
    "strategy": "mlx-community/Qwen3.6-27B-OptiQ-4bit",
    "engineering": "mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit",
    "offsec": "mlx-community/Llama-3-70B-Instruct-Gradient-1048k-4bit",
}
ROUTE_MAP = {**DEFAULT_ROUTE_MAP, **POLICY.model_routes}

DEFAULT_MODEL_ALIAS = POLICY.default_model_alias or "strategy"

# -----------------------------
# Inference backend (model-plane-agnostic)
# -----------------------------
BACKEND = backends.select_backend(
    os.environ.get("PRIVATE_AI_BACKEND", "auto"),
    base_url=os.environ.get("PRIVATE_AI_UPSTREAM_BASE_URL"),
    api_key=os.environ.get("PRIVATE_AI_UPSTREAM_API_KEY"),
)

# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger("AuditTrail")
logger.setLevel(logging.INFO)

if not logger.handlers:
    fh = logging.FileHandler(AUDIT_LOG_PATH)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(fh)

def resolve_model(requested_model: str) -> str:
    if not requested_model:
        requested_model = DEFAULT_MODEL_ALIAS
    return ROUTE_MAP.get(requested_model, requested_model)


def normalize_content(content):
    """
    OpenAI message content may be:
    - string
    - list of content parts
    Clients/tooling may send richer shapes.
    Convert to plain text for MLX chat templates.
    """
    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
                elif "text" in item:
                    parts.append(str(item.get("text", "")))
                elif "content" in item:
                    parts.append(str(item.get("content", "")))
        return "\n".join([p for p in parts if p])

    return str(content)


def normalize_messages(messages):
    clean = []

    if not isinstance(messages, list):
        return [{"role": "user", "content": str(messages)}]

    for msg in messages:
        if not isinstance(msg, dict):
            continue

        role = msg.get("role", "user")
        content = normalize_content(msg.get("content", ""))

        # Ignore assistant tool call metadata for now.
        # Keep only role/content, which MLX chat templates understand.
        if role not in ("system", "user", "assistant", "tool"):
            role = "user"

        if role == "tool":
            role = "user"
            content = f"Tool result:\n{content}"

        clean.append({"role": role, "content": content})

    if not clean:
        clean = [{"role": "user", "content": ""}]

    return clean


def sanitize_model_output(text):
    """Remove visible model control/tool/thinking tags before returning API content."""
    if text is None:
        return ""

    original_text = str(text)
    text = original_text

    tool_marker_patterns = [
        r"<tool_call>",
        r"</tool_call>",
        r"<tool_call\|>",
        r"<\|tool_call\|>",
        r"<function_calls>",
        r"</function_calls>",
        r"<function_call>",
        r"</function_call>",
    ]

    tool_marker_seen = any(
        re.search(pattern, original_text, flags=re.IGNORECASE) for pattern in tool_marker_patterns
    )

    # Remove Qwen/QwQ visible thinking wrappers, including empty streamed wrappers.
    text = re.sub(
        r"<think>\s*.*?</think>\s*",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove visible thought/control blocks like:
    # <|channel>thought ... <channel|>OK
    text = re.sub(
        r"<\|channel\>thought\s*.*?<channel\|>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove plain Qwen-style fake tool-call lines/blocks.
    text = re.sub(
        r"<tool_call>.*?(?=\n|$)",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(
        r"<function_calls>.*?</function_calls>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )
    text = re.sub(
        r"<function_call>.*?</function_call>",
        "",
        text,
        flags=re.DOTALL | re.IGNORECASE,
    )

    # Remove remaining channel/control markers.
    text = re.sub(r"<\|channel\>[a-zA-Z_ -]*", "", text)
    text = text.replace("<channel|>", "")

    # Remove common accidental special tokens.
    for tok in [
        "<|start|>",
        "<|end|>",
        "<|message|>",
        "<|assistant|>",
        "<|user|>",
        "<|system|>",
        "<|final|>",
        "<|tool_call|>",
        "<tool_call|>",
        "<tool_call>",
        "</tool_call>",
        "<function_calls>",
        "</function_calls>",
        "<function_call>",
        "</function_call>",
        "<think>",
        "</think>",
    ]:
        text = text.replace(tok, "")

    text = text.strip()

    # If the model attempted a tool call, do not let the client interpret or display it.
    # Return a safe text-only fallback instead of pretending the tool call happened.
    if tool_marker_seen:
        logger.warning(
            "SANITIZER_BLOCKED_TOOL_CALL | Replaced fake tool-call output with safe text fallback"
        )
        if not text:
            return (
                "I cannot call tools through this local gateway. "
                "Paste the relevant file content or terminal output, and I will continue in text-only mode."
            )
        return (
            "I cannot call tools through this local gateway. "
            "Paste the relevant file content or terminal output. "
            "Continuing in text-only mode: " + text
        )

    return text


def estimate_tokens_rough(text: str) -> int:
    if not text:
        return 0
    return max(1, len(text) // 4)


def _identify_principal(token: str) -> Principal | None:
    """Resolve a bearer token to a principal: policy first, then owner fallback."""
    principal = POLICY.identify(token)
    if principal is not None:
        return principal
    # Owner / break-glass token. Constant-time compare; an empty configured token
    # or an empty presented token never matches.
    if (
        AUTH_TOKEN
        and token
        and hmac.compare_digest(token.encode("utf-8"), AUTH_TOKEN.encode("utf-8"))
    ):
        return OWNER_PRINCIPAL
    return None


@app.before_request
def authenticate_request():
    g.request_id = uuid.uuid4().hex
    # Correlation id for a governed run, if the caller carries one. Orchestration
    # sub-requests set it (see orchestration._build_peers); plain requests leave it empty,
    # and only the explicitly tagged orchestration-path audit records emit it.
    g.run_id = request.headers.get("X-Run-Id", "")
    g.principal = None

    # Allow health and the console *shell* without auth. The console HTML carries no
    # data — every API call it makes presents a bearer token the operator pastes in,
    # so serving the static page is no more sensitive than serving /health.
    if request.path in ("/health", "/v1/health", "/console", "/chat"):
        return None

    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    principal = _identify_principal(token)

    # The Authorization header is never logged (it carries the bearer credential).
    if principal is None:
        logger.warning(
            f"AUTH_FAILURE | IP={log_safe(request.remote_addr)} | Path={log_safe(request.path)}"
        )
        METRICS.inc("gateway_requests_total", {"principal": "anonymous", "decision": "deny"})
        DECISION_LOG.record(
            request_id=g.request_id,
            principal=None,
            method=request.method,
            path=request.path,
            model=None,
            decision="deny",
            reason="invalid_or_unknown_token",
            status=401,
        )
        return jsonify(
            {
                "error": {
                    "message": "Unauthorized",
                    "type": "authentication_error",
                    "code": "unauthorized",
                }
            }
        ), 401

    g.principal = principal

    # Rate limit per principal (token bucket). Applied before any work is done so a
    # runaway key is rejected cheaply, ahead of model loading or inference.
    allowed, retry_after = RATE_LIMITER.allow(principal.name, principal.requests_per_minute)
    if not allowed:
        logger.warning(
            f"RATE_LIMITED | principal={log_safe(principal.name)} | path={log_safe(request.path)}"
        )
        METRICS.inc("gateway_rate_limited_total", {"principal": principal.name})
        METRICS.inc("gateway_requests_total", {"principal": principal.name, "decision": "deny"})
        DECISION_LOG.record(
            request_id=g.request_id,
            principal=principal.name,
            method=request.method,
            path=request.path,
            model=None,
            decision="deny",
            reason="rate_limited",
            status=429,
        )
        response = jsonify(
            {
                "error": {
                    "message": "Rate limit exceeded",
                    "type": "rate_limit_error",
                    "code": "rate_limited",
                }
            }
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(int(retry_after) + 1)
        return response

    logger.info(
        f"AUTH_SUCCESS | principal={log_safe(principal.name)} | "
        f"IP={log_safe(request.remote_addr)} | Path={log_safe(request.path)}"
    )
    return None


@app.after_request
def apply_response_hardening(response):
    """Attach a correlation id and conservative security headers to every response.

    The gateway already mints a per-request id in ``before_request`` and threads it
    through the decision audit; surfacing it as ``X-Request-Id`` lets an operator tie a
    client-visible response back to the exact audit line. The headers are deliberately
    strict for an API that only ever returns JSON / Prometheus text to a loopback caller:
    no sniffing, no framing, no referrer leakage, and never cache a governed response.
    """
    request_id = getattr(g, "request_id", "")
    if request_id:
        response.headers["X-Request-Id"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.errorhandler(413)
def request_entity_too_large(_e):
    return jsonify(
        {
            "error": {
                "message": "Request body too large",
                "type": "invalid_request_error",
                "code": "payload_too_large",
            }
        }
    ), 413


@app.route("/health", methods=["GET"])
@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "backend": BACKEND.info(),
            "current_model": BACKEND.info().get("current_model"),
            "models": list(ROUTE_MAP.keys()),
        }
    )


@app.route("/v1/whoami", methods=["GET"])
def whoami():
    """Introspection: report the calling principal's effective permissions.

    Useful for debugging policy and for a caller to confirm what it is authorized
    to do without trial-and-error against /v1/chat/completions.
    """
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    effective_rpm = principal.requests_per_minute
    if effective_rpm is None:
        effective_rpm = POLICY.default_requests_per_minute or None
    max_autonomy = principal.max_autonomy_level
    if max_autonomy is None:
        max_autonomy = POLICY.default_max_autonomy_level
    return jsonify(
        {
            "principal": principal.name,
            "allowed_models": sorted(principal.allowed_models),
            "max_output_tokens": principal.max_output_tokens,
            "requests_per_minute": effective_rpm,
            "max_autonomy_level": max_autonomy,
            "max_autonomy_name": autonomy.level_name(max_autonomy),
        }
    )


@app.route("/metrics", methods=["GET"])
def metrics():
    """Prometheus text-format metrics (requires auth; safe to scrape with a token)."""
    return Response(METRICS.render(), mimetype="text/plain; version=0.0.4")


@app.route("/v1/decisions", methods=["GET"])
def decisions():
    """Tail the decision audit (who was allowed/denied what, and why).

    The audit reveals every principal's allow/deny history, so reading it is its own
    policy grant (``can_read_audit``) rather than something any authenticated caller
    gets for free. Denials are themselves recorded — watching the watchers is also a
    governed action.
    """
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    if not principal.can_read_audit:
        METRICS.inc("gateway_authz_denials_total", {"reason": "audit_not_allowed"})
        METRICS.inc("gateway_requests_total", {"principal": principal.name, "decision": "deny"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny", reason="audit_not_allowed", status=403,
        )
        return jsonify(
            {"error": {"message": (
                f"Principal '{principal.name}' is not granted access to the decision audit"),
                "type": "permission_error", "code": "audit_not_allowed"}}
        ), 403

    try:
        limit = int(request.args.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    events = DECISION_LOG.tail(limit)
    return jsonify({"decisions": events, "count": len(events)})


@app.route("/console", methods=["GET"])
def console():
    """Serve the Governance Console — a single-file, zero-dependency web UI.

    The shell is static and holds no data: the operator pastes a bearer token into the
    page, and everything it shows (whoami, decisions, metrics, tools, chat probes) is
    fetched from the governed API with that token. A strict CSP pins the page to
    same-origin API calls and inline assets only — no external scripts, no images,
    no frames.
    """
    html = importlib.resources.files("private_ai_gateway").joinpath(
        "static/console.html"
    ).read_text(encoding="utf-8")
    response = Response(html, mimetype="text/html")
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'"
    )
    return response


@app.route("/chat", methods=["GET"])
def chat_console():
    """Serve the Governed Chat Console — a conversational front-end to the real loop.

    Like ``/console`` the shell is static and data-free: the operator pastes a bearer
    token, types a goal, and watches Hermes plan → delegate → verify through the same
    enforced plane. The apply step is human-gated; the page cannot approve on its own.
    """
    html = importlib.resources.files("private_ai_gateway").joinpath(
        "static/chat.html"
    ).read_text(encoding="utf-8")
    response = Response(html, mimetype="text/html")
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'"
    )
    return response


@app.route("/v1/orchestrate", methods=["POST"])
def v1_orchestrate():
    """Run one governed-orchestration phase for the Governed Chat Console.

    Body: ``{"objective": str, "phase": "plan"|"execute"|"probe", "run_id": str,
    "approval_id": str}``. The caller is authenticated and rate-limited like any request;
    the orchestration itself drives the demo principals back through this same app, so
    every plan/delegate/apply/verify hop is enforced and audited. The ``execute`` phase
    applies only under a durable, owner-issued approval (see ``/v1/approvals``): it needs
    ``run_id`` + ``approval_id`` and a server-recomputed canonical hash. A request-body
    ``approver`` grants nothing — an old inline-approver body is refused (governed 200)
    with ``approval_missing``. Authority to change anything stays with the human.
    """
    from private_ai_gateway import orchestration

    body = request.get_json(silent=True) or {}
    objective = body.get("objective") or body.get("goal") or ""
    phase = (body.get("phase") or "plan").strip()
    run_id = body.get("run_id") or ""
    approval_id = body.get("approval_id") or ""

    try:
        result = orchestration.run_phase(
            sys.modules[__name__], objective, phase,
            run_id=run_id, approval_id=approval_id,
        )
    except orchestration.OrchestrationUnavailable as exc:
        # Keep internal detail server-side; return a static, client-safe message (CWE-209).
        logger.warning(f"ORCHESTRATE_UNAVAILABLE | detail={log_safe(str(exc))}")
        return jsonify({"error": {"message": "Orchestration is temporarily unavailable",
                                  "type": "unavailable",
                                  "code": "orchestration_unavailable"}}), 503
    except ValueError as exc:
        logger.warning(f"ORCHESTRATE_INVALID_REQUEST | detail={log_safe(str(exc))}")
        return jsonify({"error": {"message": "Invalid orchestration request",
                                  "type": "invalid_request_error",
                                  "code": "invalid_request"}}), 400

    METRICS.inc("gateway_orchestrate_total",
                {"phase": phase, "principal": g.principal.name})
    # An approval-gate refusal happens before any sub-request, so it would otherwise leave
    # no audit trace. Record it (deny, with run_id) through the existing DecisionLog.
    if phase == "execute" and result.get("refused"):
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=g.principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny",
            reason=f"execute_refused:{result.get('refusal_reason', '')}",
            status=200, run_id=result.get("run_id", ""),
        )
    logger.info(
        f"ORCHESTRATE | principal={log_safe(g.principal.name)} | phase={log_safe(phase)} "
        f"| run_id={log_safe(result.get('run_id', ''))} | objective={log_safe(objective)[:80]}"
    )
    return jsonify(result)


@app.route("/v1/approvals", methods=["POST"])
def v1_approvals():
    """Owner-gated approval decision for a governed run (durable, hash-bound).

    The approver is the authenticated **owner** identity — never a body field, never model
    text. The decision binds to a run registered on ``plan`` and to that run's exact
    ``canonical_plan_hash``; a mismatch is refused. Rejection is a governed *success*
    (HTTP 200), not an error. This endpoint decides an approval; it does not execute
    anything — execute-time validation arrives with D2b.
    """
    principal = getattr(g, "principal", None)
    if principal is not OWNER_PRINCIPAL:
        # Counted as an authz denial so the audit and the metrics stream stay
        # reconcilable — OpenClaw's AC-METRICS-RECONCILE treats a 403 deny in the audit
        # without a matching counter increment as evidence of a dropped metric.
        METRICS.inc("gateway_authz_denials_total", {"reason": "owner_required"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""),
            principal=(principal.name if principal else None),
            method=request.method, path=request.path, model=None,
            decision="deny", reason="owner_required", status=403,
        )
        return jsonify(
            {"error": {"message": "Approval requires the owner identity",
                       "type": "permission_error", "code": "owner_required"}}
        ), 403

    body = request.get_json(silent=True) or {}
    run_id = str(body.get("run_id", "")).strip()
    supplied_hash = str(body.get("canonical_plan_hash", "")).strip()
    decision = str(body.get("decision", "")).strip()
    reason = str(body.get("reason", ""))

    if decision not in ("approve", "reject"):
        return jsonify(
            {"error": {"message": "decision must be 'approve' or 'reject'",
                       "type": "invalid_request_error", "code": "invalid_decision"}}
        ), 400

    run = APPROVAL_STORE.get_run(run_id)
    if run is None:
        return jsonify(
            {"error": {"message": f"Unknown run '{run_id}'",
                       "type": "invalid_request_error", "code": "run_not_found"}}
        ), 404
    if supplied_hash != run.canonical_plan_hash:
        return jsonify(
            {"error": {"message": "canonical_plan_hash does not match the registered run",
                       "type": "invalid_request_error", "code": "hash_mismatch"}}
        ), 409

    try:
        pending = APPROVAL_STORE.create_pending_approval(run_id)
        record = APPROVAL_STORE.decide_approval(
            pending.approval_id, decision=decision,
            approver=principal.name, reason=reason,
        )
    except ApprovalError as exc:
        # Static, client-safe message; the specific reason stays in the server log (CWE-209).
        logger.warning(f"APPROVAL_ERROR | run_id={log_safe(run_id)} | detail={log_safe(str(exc))}")
        return jsonify(
            {"error": {"message": "Approval could not be recorded",
                       "type": "invalid_request_error",
                       "code": "approval_error"}}
        ), 409

    # Step 5b — gateway authorization evidence emit. With a verifier-owned EvidenceSink
    # injected, emit ONE signed `approval_decided` record (approve or reject) before returning
    # the decision. Default (no sink) is byte-identical to before. Under
    # REQUIRE_AUTHORIZATION_EVIDENCE the record MUST land: if it cannot, fail closed —
    # invalidate the run (so the just-recorded approval can never be used at execute) and
    # return a static, client-safe refusal rather than a normal approval body.
    from private_ai_gateway import orchestration

    if not orchestration._emit_approval_decided(
        sys.modules[__name__],
        run_id=run_id,
        approval_id=record.approval_id,
        decision=decision,
        approver=principal.name,
        canonical_plan_hash=record.canonical_plan_hash,
    ):
        APPROVAL_STORE.invalidate_run(run_id)
        # Audit the governed refusal (a decision that required evidence but could not record
        # it must not be a silent gap); the internal emit detail stays in the server log only.
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny",
            reason=f"authorization_evidence_unavailable:{run_id}",
            status=503, run_id=run_id,
        )
        return jsonify(
            {"error": {"message": "The approval evidence record could not be recorded — "
                                  "approval denied",
                       "type": "server_error",
                       "code": "authorization_evidence_unavailable"}}
        ), 503

    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow" if decision == "approve" else "deny",
        reason=f"approval_{record.approval_status.value}:{run_id}",
        status=200, run_id=run_id,
    )

    resp = {
        "approval_id": record.approval_id,
        "run_id": record.run_id,
        "approval_status": record.approval_status.value,
        "canonical_plan_hash": record.canonical_plan_hash,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "single_use": record.single_use,
    }
    if record.approval_status.value == "rejected":
        resp["rejection_reason"] = record.rejection_reason
    return jsonify(resp), 200


def _owner_only(code_path: str):
    """403 unless the caller is the owner; ``None`` when the request may proceed.

    Same shape as the ``/v1/approvals`` gate, including the ``gateway_authz_denials_total``
    increment — OpenClaw's AC-METRICS-RECONCILE reads a 403 deny in the audit with no
    matching counter as a dropped metric, and would fail the *next* legitimate run.
    """
    principal = getattr(g, "principal", None)
    if principal is OWNER_PRINCIPAL:
        return None
    METRICS.inc("gateway_authz_denials_total", {"reason": "owner_required"})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""),
        principal=(principal.name if principal else None),
        method=request.method, path=request.path, model=None,
        decision="deny", reason="owner_required", status=403,
    )
    return jsonify(
        {"error": {"message": f"{code_path} requires the owner identity",
                   "type": "permission_error", "code": "owner_required"}}
    ), 403


@app.route("/v1/models/registry", methods=["GET"])
def v1_models_registry():
    """The capability picture: what can run here, and what has actually been measured.

    Owner-gated and **read-only**. It describes capability and grants nothing — no autonomy,
    no skill, no tool, no approval right. Nothing here is downloaded: the host snapshot reads
    the local model cache and never fetches a model, so opening this page cannot trigger a
    30 GB pull.
    """
    from private_ai_gateway import registry as reg

    denied = _owner_only("The model registry")
    if denied is not None:
        return denied

    cache = reg.ModelCache()
    host = reg.snapshot_host(
        active_backend=getattr(BACKEND, "name", ""),
        cache=cache,
        upstream_configured=bool(os.environ.get("PRIVATE_AI_UPSTREAM_BASE_URL")),
    )
    # Deliberately no per-model output cap: the cap is a property of the *principal*, not of
    # the model, so attaching one here would be inventing metadata the config does not hold.
    built = reg.build_registry(
        ROUTE_MAP,
        backend=getattr(BACKEND, "name", ""),
        host=host,
        cache=cache,
        artifacts=reg.load_artifacts(QUALIFICATION_ARTIFACT_DIR),
        default_alias=DEFAULT_MODEL_ALIAS,
        policy_hash=_policy_file_hash(),
    )
    return jsonify(built.to_mapping()), 200


@app.route("/v1/models/routing", methods=["GET"])
def v1_models_routing():
    """Everything the Models & Routing view needs, kept as four separate answers.

    Deliberately *not* collapsed into one badge. "What is available", "what is qualified for
    this task", "what is currently routed", and "what authority does the routed principal
    hold" are four different questions, and a UI that merges them is how a capability number
    turns into a permission in someone's head.

    The authority block is included precisely so it can be shown **separately** and shown to
    be unchanged by anything on this page.
    """
    from private_ai_gateway import registry as reg

    denied = _owner_only("Model routing")
    if denied is not None:
        return denied

    built = _capability_registry()
    lanes = []
    for lane in reg.LANES:
        eligible = None
        if lane == reg.LANE_ENGINEERING:
            # Engineering candidates are authored by the shadow principal, so its own model
            # allowlist bounds what may serve the lane at all.
            shadow = _principal_named("shadow-engineer")
            if shadow is not None and "*" not in shadow.allowed_models:
                eligible = set(shadow.allowed_models)
        lanes.append({
            "lane": lane,
            "label": reg.LANE_LABELS[lane],
            "recommendations": [
                r.to_mapping() for r in reg.recommend(built, lane, policy_eligible=eligible)
            ],
        })

    return jsonify({
        "registry": built.to_mapping(),
        "lanes": lanes,
        "deterministic_controls": [
            {"name": name, "why": why} for name, why in reg.DETERMINISTIC_CONTROLS
        ],
        "authority": _routed_authority(),
        "activation": _ROUTE_ACTIVATION,
    }), 200


@app.route("/v1/trust-history", methods=["GET"])
def v1_trust_history():
    """Derived trust history, owner-gated and read-only. It grants nothing.

    Two blocks that are never combined: **QUALIFICATION** (how a model did on a corpus we
    built) and **RUNTIME HISTORY** (what the governed loop actually did). Presenting corpus
    results as production history would be the most flattering possible lie.

    An unverifiable evidence chain yields **no ledger** rather than an empty one — an empty
    ledger reads as "no bad history", which is the opposite of what "could not be read" means.
    """
    from private_ai_gateway import trust_ledger as tl

    denied = _owner_only("Trust history")
    if denied is not None:
        return denied

    ledger = None
    error = ""
    try:
        ledger = tl.derive_ledger(APPROVAL_STORE, EVIDENCE_SINK)
    except tl.TrustLedgerError as exc:
        error = str(exc)
        logger.warning(f"TRUST_LEDGER_UNAVAILABLE | detail={log_safe(error)}")
    except Exception as exc:  # noqa: BLE001 — an unreadable ledger is "no ledger", not a 500
        # This path is why the endpoint used to return 500 in a real process: a same-named
        # installed package shadowed the verifier and raised ImportError, which the narrow
        # except above did not cover. "No ledger" is the honest answer and the safe one —
        # an absent history must never render as a clean one.
        error = f"the trust history could not be derived: {exc}"
        logger.warning(f"TRUST_LEDGER_UNAVAILABLE | detail={log_safe(str(exc))}")

    view = tl.build_view(_capability_registry(), ledger)
    return jsonify({
        **view.to_mapping(),
        "ledger": ledger.to_mapping() if ledger is not None else None,
        "ledger_error": error,
        "grants": "nothing",
    }), 200


@app.route("/v1/autonomy-readiness", methods=["POST"])
def v1_autonomy_readiness():
    """Advisory earned-autonomy readiness. Shadow only — it grants nothing and nothing reads it.

    Assembles the facts other modules established (lane qualification, deterministic task
    risk, attributed runtime history, evidence integrity) and reports whether a candidate
    *could* ever run unattended. Every condition is a veto; there is no score. No
    authorization path consumes this result, and a structural test keeps it that way.
    """
    from private_ai_gateway import eligibility as elig
    from private_ai_gateway import registry as reg
    from private_ai_gateway import task_risk as risk
    from private_ai_gateway import trust_ledger as tl

    denied = _owner_only("Autonomy readiness")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    lane = str(body.get("lane", elig.LANE_ENGINEERING_CANDIDATE)).strip()
    route_alias = str(body.get("route_alias", "")).strip() or DEFAULT_MODEL_ALIAS

    registry = _capability_registry()
    model = registry.by_alias(route_alias)
    identity = model.identity if model is not None else None
    lane_state = ""
    security_state = ""
    if model is not None:
        standing = model.lanes.get(lane)
        lane_state = standing.state if standing else reg.NOT_EVALUATED
        sec = model.lanes.get(reg.LANE_SECURITY_REVIEW)
        security_state = sec.state if sec else reg.NOT_EVALUATED

    assessment = risk.classify(
        declared_files=body.get("declared_files") or (),
        content=str(body.get("content", "")),
        objective=str(body.get("objective", "")),
        claimed_class=str(body.get("risk_class", "")),
    )

    # History is read from the derived ledger, which fails closed on an unverifiable chain.
    facts = None
    history_fingerprint = ""
    evidence_verified = False
    try:
        ledger = tl.derive_ledger(APPROVAL_STORE, EVIDENCE_SINK)
        evidence_verified = True
        fingerprint = identity.fingerprint if identity is not None else ""
        for entry in ledger.entries:
            if entry.key.model_fingerprint == fingerprint != tl.NOT_RECORDED:
                facts, history_fingerprint = entry.facts, entry.key.model_fingerprint
                break
    except Exception:  # noqa: BLE001 — any unreadable history is unverified history
        # Fails closed on purpose, and the direction matters: an unreadable chain must read as
        # "no usable history", never as "a clean record".
        evidence_verified = False
        facts, history_fingerprint = None, ""

    result = elig.evaluate(
        lane=lane,
        security_lane_state=security_state,
        lane_state=lane_state,
        risk_class=assessment.risk_class,
        trust_facts=facts,
        model_fingerprint=identity.fingerprint if identity is not None else "",
        history_fingerprint=history_fingerprint,
        policy_hash=effective_routes().effective_policy_hash,
        evidence_verified=evidence_verified,
    )
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"autonomy_readiness:{result.outcome}", status=200,
    )
    return jsonify({**result.to_mapping(), "task_risk": assessment.to_mapping()}), 200


@app.route("/v1/models/route-activate", methods=["POST"])
def v1_models_route_activate():
    """Activate a route change as a managed revision. Owner only, and narrow by construction.

    Writes a numbered, atomic revision to the gateway-owned store — never to
    ``config/policy.toml``, which stays hand-authored. The new effective policy hash is
    computed over base policy + the revision and returned, so the caller sees exactly what
    authority will bind to. Runs already in flight are untouched.

    Refused for the security lane unless the model is qualified for it. That is not a warning
    here as it is on the proposal path: activation is the point where a warning would stop
    being read.
    """
    from private_ai_gateway import registry as reg
    from private_ai_gateway import route_revision as rev

    denied = _owner_only("Route activation")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    lane = str(body.get("lane", "")).strip()
    route_alias = str(body.get("route_alias", "")).strip()
    if lane not in reg.LANES:
        return jsonify({"error": {"message": "Unknown task lane",
                                  "type": "invalid_request_error",
                                  "code": "unknown_lane"}}), 400

    registry = _capability_registry()
    target = registry.by_alias(route_alias)
    if target is None:
        return jsonify({"error": {"message": "Unknown route alias",
                                  "type": "invalid_request_error",
                                  "code": "unknown_route_alias"}}), 400

    standing = target.lanes.get(lane)
    state = standing.state if standing else reg.NOT_EVALUATED
    if lane == reg.LANE_SECURITY_REVIEW and state != reg.QUALIFIED:
        logger.warning(
            f"ROUTE_ACTIVATION_REFUSED | lane={log_safe(lane)} "
            f"| alias={log_safe(route_alias)} | qualification={log_safe(state)}"
        )
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=g.principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny", reason="security_lane_not_qualified", status=403,
        )
        return jsonify({"error": {
            "message": (
                "This model is not qualified for security review, so it cannot be activated "
                "for that lane. Only a new qualification measurement can change that."
            ),
            "type": "permission_error",
            "code": "security_lane_not_qualified",
            "qualification": state,
        }}), 403

    try:
        revision = rev.build_revision(
            _route_revision_store(),
            base_routes=ROUTE_MAP,
            policy_path=POLICY_PATH,
            lane=lane,
            route_alias=route_alias,
            resolved_model=target.identity.resolved_model,
            activated_by=g.principal.name,
        )
        _route_revision_store().append(revision)
    except rev.RouteRevisionError as exc:
        logger.warning(f"ROUTE_ACTIVATION_FAILED | detail={log_safe(str(exc))}")
        return jsonify({"error": {"message": "The route revision could not be written",
                                  "type": "server_error",
                                  "code": "route_revision_unavailable"}}), 503

    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"route_activated:{lane}:{route_alias}", status=200,
    )
    logger.info(
        f"ROUTE_ACTIVATED | revision={revision.revision} | lane={log_safe(lane)} "
        f"| alias={log_safe(route_alias)}"
    )
    return jsonify({
        "activated": True,
        "revision": revision.revision,
        "lane": lane,
        "route_alias": route_alias,
        "resolved_model": revision.routes.get(route_alias, ""),
        "base_policy_hash": revision.base_policy_hash,
        "effective_policy_hash": revision.effective_policy_hash,
        "policy_file_written": False,
        "authority_unchanged": True,
        "applies_to": "runs planned after this revision; runs in flight keep their own",
        "note": revision.note,
    }), 200


@app.route("/v1/task-risk", methods=["POST"])
def v1_task_risk():
    """Classify a proposed change against the protected-surface taxonomy.

    Read-only and advisory: it reports what a change *is*, and grants nothing. The local model
    scored 0/14 on refusing control-weakening changes, so this classification is made out here
    in deterministic code rather than asked of a model — and a caller's own ``risk_class`` can
    only make the answer stricter, never laxer.
    """
    from private_ai_gateway import task_risk as risk

    denied = _owner_only("Task risk")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    assessment = risk.classify(
        declared_files=body.get("declared_files") or (),
        content=str(body.get("content", "")),
        objective=str(body.get("objective", "")),
        claimed_class=str(body.get("risk_class", "")),
    )
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"task_risk:{assessment.risk_class}", status=200,
    )
    return jsonify({
        **assessment.to_mapping(),
        "note": (
            "advisory classification only; nothing in this system consumes it as authority, "
            "and no autonomous execution is granted anywhere"
        ),
    }), 200


@app.route("/v1/models/route-proposal", methods=["POST"])
def v1_models_route_proposal():
    """Compute a route-change **proposal**. Nothing is applied, ever, on this path.

    Body: ``{lane, route_alias}``. Returns the before/after picture, the qualification and fit
    of the proposed model, the current policy hash, and every warning that applies. A browser
    dropdown must never mutate the policy file, so this endpoint deliberately cannot: see
    ``_ROUTE_ACTIVATION`` for the exact gap that has to close before activation exists.
    """
    from private_ai_gateway import registry as reg

    denied = _owner_only("Model routing")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    lane = str(body.get("lane", "")).strip()
    route_alias = str(body.get("route_alias", "")).strip()
    if lane not in reg.LANES:
        return jsonify(
            {"error": {"message": "Unknown task lane", "type": "invalid_request_error",
                       "code": "unknown_lane"}}
        ), 400

    proposal = reg.propose_route(
        _capability_registry(), lane=lane, route_alias=route_alias,
        activation=_ROUTE_ACTIVATION["state"],
    )
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"route_proposed:{lane}:{route_alias}", status=200,
    )
    logger.info(
        f"ROUTE_PROPOSED | lane={log_safe(lane)} | alias={log_safe(route_alias)} "
        f"| applied=false"
    )
    return jsonify({
        **proposal.to_mapping(),
        "applied": False,
        "authority_unchanged": True,
        "note": "a proposal only; no policy file was written and no authority changed",
    }), 200


# Activation exists now, and deliberately does not work the way the earlier gap description
# imagined. Rewriting the hand-authored ``config/policy.toml`` from an HTTP handler was the
# obvious plan and the wrong one: it would put a web request in charge of a file a human owns,
# with no way to distinguish an operator's edit from a machine's. Instead the policy file stays
# hand-authored and never written here, and activation appends a numbered, atomic revision to a
# gateway-owned store. The effective configuration is base policy + active revision, and the
# effective policy hash is derived over both — so the hash still covers everything in force.
# See ``private_ai_gateway.route_revision``.
_ROUTE_ACTIVATION = {
    "state": "owner_gated_revision",
    "reason": "activation appends a managed, hash-covered revision; the policy file is never written",
    "effect": (
        "a revision takes effect for runs planned after it; runs already in flight keep the "
        "revision they were planned under, so a route change can never retroactively "
        "reinterpret a run someone already approved"
    ),
    "limits": (
        "route table only — a revision has no field for autonomy, skills, tools, principals or "
        "approval rights, so there is nothing to set rather than merely a check that refuses; "
        "a model whose security lane is not qualified cannot be activated for security work"
    ),
}


def _route_revision_store():
    from private_ai_gateway import route_revision as rev

    return rev.RouteRevisionStore(ROUTE_REVISION_DIR)


def effective_routes():
    """The route table actually in force: base policy merged with the active revision.

    Falls back to the base map — loudly, via the returned ``state`` — if the revision store is
    unreadable or the policy file changed underneath a revision. A route override is never
    applied against a policy file it was not reviewed against.
    """
    from private_ai_gateway import route_revision as rev

    try:
        return rev.resolve_effective_routes(
            _route_revision_store(), base_routes=ROUTE_MAP, policy_path=POLICY_PATH
        )
    except rev.RouteRevisionError as exc:
        logger.warning(f"ROUTE_REVISION_UNREADABLE | detail={log_safe(str(exc))}")
        return rev.EffectiveRoutes(
            routes=dict(ROUTE_MAP),
            state=rev.ACTIVATION_NONE,
            detail=f"revision store unreadable; the policy file is in force ({exc})",
        )


def _principal_named(name: str):
    """A configured principal by name, or ``None`` — policy-derived, never key material."""
    for principal in POLICY.principals():
        if principal.name == name:
            return principal
    return None


def _capability_registry():
    """One assembled capability picture, shared by the routing views."""
    from private_ai_gateway import registry as reg

    cache = reg.ModelCache()
    host = reg.snapshot_host(
        active_backend=getattr(BACKEND, "name", ""),
        cache=cache,
        upstream_configured=bool(os.environ.get("PRIVATE_AI_UPSTREAM_BASE_URL")),
    )
    return reg.build_registry(
        ROUTE_MAP,
        backend=getattr(BACKEND, "name", ""),
        host=host,
        cache=cache,
        artifacts=reg.load_artifacts(QUALIFICATION_ARTIFACT_DIR),
        default_alias=DEFAULT_MODEL_ALIAS,
        policy_hash=_policy_file_hash(),
    )


def _routed_authority() -> list[dict]:
    """The authority each agent principal actually holds — shown *beside* routing, never merged.

    Sourced from policy, not from the registry, so the page cannot imply that changing a model
    changes a ceiling. It is here to be visibly independent.
    """
    out = []
    for name in ("hermes", "opencode", "openclaw", "shadow-engineer"):
        principal = _principal_named(name)
        if principal is None:
            continue
        out.append({
            "principal": principal.name,
            "max_autonomy_level": autonomy_ceiling_for(principal),
            "allowed_models": sorted(principal.allowed_models),
            "allowed_skills": sorted(principal.allowed_skills),
            "allowed_tools": sorted(principal.allowed_tools),
        })
    return out


def _policy_file_hash() -> str:
    """The active policy file's hash, or ``""`` when it cannot be read.

    Unlike the authority-bearing ``canonical_plan_hash`` path, this is descriptive: the
    registry showing an empty hash is a display gap, not a governed decision, so an
    unreadable file degrades rather than failing closed.
    """
    try:
        with open(POLICY_PATH, "rb") as fh:
            return "sha256:" + hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


@app.route("/v1/runs/<run_id>/disposition-basis", methods=["GET"])
def v1_disposition_basis(run_id: str):
    """The bases a human may cite when disposing this run (Step 7C.2), owner-gated.

    Read-only. Lists the run's signed ``execute_validated`` reservation and every
    ``verification_result`` OpenClaw recorded for it, each with the typed ``EvidenceRef`` that
    ``POST /v1/dispositions`` expects. It deliberately does **not** recommend one: when a run
    carries several verdicts the human picks, and naming a specific record is the whole point.
    """
    from private_ai_gateway import disposition as disp

    denied = _owner_only("Disposition")
    if denied is not None:
        return denied
    if EVIDENCE_SINK is None:
        return jsonify(
            {"error": {"message": "No evidence sink is configured",
                       "type": "server_error", "code": disp.CODE_EVIDENCE_UNAVAILABLE}}
        ), 503
    if APPROVAL_STORE.get_run(run_id) is None:
        return jsonify(
            {"error": {"message": f"Unknown run '{run_id}'",
                       "type": "invalid_request_error", "code": disp.CODE_RUN_NOT_FOUND}}
        ), 404

    from openclaw.evidence import SinkGraphReader

    reader = SinkGraphReader(EVIDENCE_SINK)
    if reader.chain_error:
        logger.warning(f"DISPOSITION_BASIS_CHAIN | detail={log_safe(reader.chain_error)}")
        return jsonify(
            {"error": {"message": "The evidence chain did not verify",
                       "type": "server_error", "code": disp.CODE_EVIDENCE_UNAVAILABLE}}
        ), 503

    bases = []
    for rec in reader.records:
        env = rec.envelope
        if (env.run_id or "") != run_id or env.record_type not in disp.BASIS_TYPES:
            continue
        entry = {
            "basis_type": env.record_type,
            "approval_id": env.approval_id or "",
            "basis_ref": rec.evidence_ref().to_mapping(),
        }
        if env.record_type == disp.BASIS_VERIFICATION_RESULT and isinstance(rec.payload, dict):
            entry["verdict"] = rec.payload.get("verdict", "")
        bases.append(entry)

    try:
        existing = disp.disposition_for_run(
            reader.records, sink_id=reader.sink_id, run_id=run_id
        )
    except disp.DispositionError as exc:
        logger.warning(f"DISPOSITION_INVALID | run_id={log_safe(run_id)} "
                       f"| detail={log_safe(exc.detail)}")
        return jsonify(
            {"error": {"message": "The recorded disposition for this run did not validate",
                       "type": "server_error", "code": exc.code}}
        ), 409

    return jsonify({
        "run_id": run_id,
        "run_status": APPROVAL_STORE.get_run(run_id).status.value,
        "bases": bases,
        "disposition": existing.disposition if existing else None,
    }), 200


@app.route("/v1/dispositions", methods=["POST"])
def v1_dispositions():
    """Owner-gated terminal disposition of an invalidated run (Step 7C.2).

    Body: ``{run_id, approval_id, disposition, basis_type, basis_ref}``. The caller names a
    *basis* — one specific ``verification_result`` it read, or the ``execute_validated``
    reservation for a dirty run where no verdict can legitimately exist — and the server
    re-resolves that reference against the verified chain before constructing and signing the
    record itself. A client never supplies an evidence envelope, and there is no "latest
    verdict" fallback.

    This closes a run; it never reopens one. The run must already be invalidated, no authority
    state is touched, and a run that is already disposed is refused with ``already_disposed``
    rather than being superseded.
    """
    from private_ai_gateway import disposition as disp

    denied = _owner_only("Disposition")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    run_id = str(body.get("run_id", "")).strip()
    approval_id = str(body.get("approval_id", "")).strip()

    try:
        recorded = disp.dispose_run(
            APPROVAL_STORE,
            EVIDENCE_SINK,
            run_id=run_id,
            approval_id=approval_id,
            disposition=str(body.get("disposition", "")).strip(),
            basis_type=str(body.get("basis_type", "")).strip(),
            basis_ref=body.get("basis_ref"),
            human_actor=g.principal.name,
            signing_key=EVIDENCE_KEY,
            key_id=EVIDENCE_KEY_ID,
        )
    except disp.DispositionError as exc:
        # The specific reason stays server-side (CWE-209); the client gets the governed code.
        logger.warning(
            f"DISPOSITION_REFUSED | run_id={log_safe(run_id)} | code={log_safe(exc.code)} "
            f"| detail={log_safe(exc.detail)}"
        )
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=g.principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny", reason=f"disposition_refused:{exc.code}",
            status=_DISPOSITION_STATUS.get(exc.code, 400), run_id=run_id,
        )
        return jsonify(
            {"error": {"message": "The disposition was refused",
                       "type": "invalid_request_error", "code": exc.code}}
        ), _DISPOSITION_STATUS.get(exc.code, 400)

    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"run_disposed:{recorded.disposition}",
        status=200, run_id=run_id,
    )
    logger.info(
        f"RUN_DISPOSED | run_id={log_safe(run_id)} "
        f"| disposition={log_safe(recorded.disposition)} "
        f"| basis={log_safe(recorded.basis_type)} | by={log_safe(recorded.human_actor)}"
    )
    return jsonify({
        "run_id": recorded.run_id,
        "approval_id": recorded.approval_id,
        "disposition": recorded.disposition,
        "basis_type": recorded.basis_type,
        "human_actor": recorded.human_actor,
        "evidence_id": recorded.evidence_id,
        "terminal": True,
    }), 200


@app.route("/v1/rollbacks", methods=["POST"])
def v1_rollbacks_plan():
    """Plan one specific sandbox rollback, owner-gated (Step 7C.3B).

    Body: ``{run_id, approval_id, workspace}``. Reads only: it resolves the signed
    ``apply_result`` for that run, re-derives the pre-image the apply recorded, and registers
    a **new governed run** whose canonical plan hash commits to the original run, the exact
    apply record, and the snapshot's identity and digest. The owner then approves that hash
    through the ordinary ``/v1/approvals`` path — a rollback gets no second approval system —
    and only then may ``/v1/rollbacks/execute`` run.

    An apply that recorded no pre-image is refused ``run_not_reversible``. Nothing is
    fabricated for a historical run.
    """
    from private_ai_gateway import rollback as rb

    denied = _owner_only("Rollback")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    try:
        plan = rb.plan_rollback(
            APPROVAL_STORE,
            EVIDENCE_SINK,
            origin_run_id=str(body.get("run_id", "")).strip(),
            origin_approval_id=str(body.get("approval_id", "")).strip(),
            workspace=str(body.get("workspace", "")).strip(),
            runtime_root=SANDBOX_RUNTIME_ROOT,
            principal_id=g.principal.name,
            policy_ceiling=autonomy_ceiling_for(g.principal) or autonomy.MAX_LEVEL,
        )
    except rb.RollbackError as exc:
        return _rollback_refusal(exc, str(body.get("run_id", "")).strip())

    logger.info(
        f"ROLLBACK_PLANNED | origin_run_id={log_safe(plan.origin_run_id)} "
        f"| rollback_run_id={log_safe(plan.rollback_run_id)} "
        f"| snapshot={log_safe(plan.snapshot_id)}"
    )
    return jsonify({
        **plan.to_mapping(),
        "next": "approve this canonical_plan_hash for rollback_run_id via POST /v1/approvals, "
                "then POST /v1/rollbacks/execute",
        "scope": "the supported sandbox state only; no external effect is undone",
    }), 200


@app.route("/v1/rollbacks/execute", methods=["POST"])
def v1_rollbacks_execute():
    """Execute an approved sandbox rollback, owner-gated (Step 7C.3B).

    Body: ``{rollback_run_id, approval_id, run_id, approval_id_origin, workspace}``. The
    ordering is Step 7B.1's: validate, append the ``rollback_validated`` reservation, consume
    the single-use approval, and only then restore. A failure is never a success — the
    workspace is contained, the rollback run is invalidated, and the signed outcome says
    ``failed``.
    """
    from private_ai_gateway import rollback as rb

    denied = _owner_only("Rollback")
    if denied is not None:
        return denied

    body = request.get_json(silent=True) or {}
    rollback_run_id = str(body.get("rollback_run_id", "")).strip()
    try:
        result = rb.execute_rollback(
            sys.modules[__name__],
            rollback_run_id=rollback_run_id,
            approval_id=str(body.get("approval_id", "")).strip(),
            origin_run_id=str(body.get("run_id", "")).strip(),
            origin_approval_id=str(body.get("approval_id_origin", "")).strip(),
            workspace=str(body.get("workspace", "")).strip(),
        )
    except rb.RollbackError as exc:
        return _rollback_refusal(exc, rollback_run_id)

    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow" if result["restored"] else "deny",
        reason=f"rollback_{result['status']}:{result['origin_run_id']}",
        status=200, run_id=rollback_run_id,
    )
    logger.info(
        f"ROLLBACK_{result['status'].upper()} | rollback_run_id={log_safe(rollback_run_id)} "
        f"| contained={result['contained']}"
    )
    return jsonify(result), 200


def _rollback_refusal(exc, run_id: str):
    """One governed refusal shape for both rollback endpoints (detail stays server-side)."""
    logger.warning(
        f"ROLLBACK_REFUSED | run_id={log_safe(run_id)} | code={log_safe(exc.code)} "
        f"| detail={log_safe(exc.detail)}"
    )
    status = _ROLLBACK_STATUS.get(exc.code, 400)
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=g.principal.name,
        method=request.method, path=request.path, model=None,
        decision="deny", reason=f"rollback_refused:{exc.code}", status=status, run_id=run_id,
    )
    return jsonify(
        {"error": {"message": "The rollback was refused",
                   "type": "invalid_request_error", "code": exc.code}}
    ), status


_ROLLBACK_STATUS = {
    "apply_not_found": 404,
    "workspace_missing": 404,
    "run_not_reversible": 409,
    "run_already_disposed": 409,
    "already_rolled_back": 409,
    "rollback_not_authorized": 409,
    "rollback_evidence_unavailable": 503,
    "rollback_reservation_failed": 503,
}


# HTTP status per governed disposition refusal. Everything else falls back to 400.
_DISPOSITION_STATUS = {
    "run_not_found": 404,
    "approval_not_found": 404,
    "run_not_terminal": 409,
    "already_disposed": 409,
    "ambiguous_disposition": 409,
    "disposition_evidence_unavailable": 503,
}


# -----------------------------
# A2A (Agent2Agent) — agent card discovery + governed delegation
# -----------------------------
@app.route("/.well-known/agent-card.json", methods=["GET"])
def agent_card():
    """Serve the calling principal's A2A Agent Card, scoped to its granted skills.

    Unlike a self-asserted card, this is rendered from policy: it advertises only the
    skills the principal is actually granted and surfaces its enforced autonomy ceiling,
    so a peer's delegation decision is made against authority, not a claim.
    """
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    base_url = request.host_url.rstrip("/")
    return jsonify(a2a.agent_card(principal, base_url=base_url, ceiling=autonomy_ceiling_for(principal)))


@app.route("/a2a/tasks", methods=["POST"])
def a2a_tasks():
    """Governed A2A delegation: accept a task only if the principal is authorized for it.

    A delegation names a ``skill`` and (optionally) the autonomy level it intends to
    operate at. The gateway enforces the same plane as inference — the skill must be in
    the principal's ``allowed_skills`` and the declared level must not exceed its ceiling —
    before the task is accepted. Accepted tasks are recorded; nothing executes on the
    strength of the request alone.
    """
    req_data = request.get_json(force=True, silent=True) or {}
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    skill = str(req_data.get("skill", "")).strip()

    if not skill:
        return jsonify(
            {"error": {"message": "Missing 'skill'", "type": "invalid_request_error",
                       "code": "invalid_request"}}
        ), 400

    # Naming a delegatee turns this from a self-task acknowledgement into a governed
    # hand-off between two principals, with attenuation and lifecycle (see delegation.py).
    if str(req_data.get("delegatee", "")).strip():
        return _delegate_task(principal, skill, req_data)

    # --- AUTHORIZATION: is this principal granted the delegated skill? ---
    if not principal.may_use_skill(skill):
        METRICS.inc("gateway_a2a_tasks_total", {"decision": "deny"})
        METRICS.inc("gateway_authz_denials_total", {"reason": "skill_not_allowed"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny", reason=f"skill_not_allowed:{skill}", status=403,
        )
        return jsonify(
            {"error": {"message": f"Principal '{principal.name}' is not granted skill '{skill}'",
                       "type": "permission_error", "code": "skill_not_allowed"}}
        ), 403

    # --- AUTONOMY: does the delegation exceed the principal's ceiling? ---
    declared = autonomy.declared_level(
        request.headers.get("X-Autonomy-Level"), req_data.get("autonomy_level")
    )
    ceiling = autonomy_ceiling_for(principal)
    if ceiling is not None and declared is not None and declared > ceiling:
        METRICS.inc("gateway_a2a_tasks_total", {"decision": "deny"})
        METRICS.inc("gateway_authz_denials_total", {"reason": "autonomy_exceeded"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny",
            reason=f"autonomy_exceeded:requested=L{declared},ceiling=L{ceiling}", status=403,
        )
        return jsonify(
            {"error": {"message": (
                f"Principal '{principal.name}' is capped at autonomy L{ceiling} "
                f"({autonomy.level_name(ceiling)}); delegation declared L{declared}"),
                "type": "permission_error", "code": "autonomy_exceeded"}}
        ), 403

    METRICS.inc("gateway_a2a_tasks_total", {"decision": "allow"})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"a2a_task:{skill}", status=202,
    )
    return jsonify(
        {
            "id": f"task-{getattr(g, 'request_id', '')[:12]}",
            "status": "submitted",
            "skill": skill,
            "principal": principal.name,
            "accepted_autonomy_level": declared,
            "accepted_autonomy_name": autonomy.level_name(declared),
        }
    ), 202


def _delegation_error(principal: Principal, exc: delegation.DelegationError, detail: str):
    """Audit and answer a refused delegation operation."""
    METRICS.inc("gateway_a2a_tasks_total", {"decision": "deny"})
    if exc.status == 403:
        METRICS.inc("gateway_authz_denials_total", {"reason": exc.code})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="deny", reason=f"{exc.code}:{detail}", status=exc.status,
        run_id=getattr(g, "run_id", ""),
    )
    return jsonify(
        {"error": {"message": exc.message, "type": "permission_error", "code": exc.code}}
    ), exc.status


def _delegation_view(record: delegation.Delegation) -> dict:
    view = record.to_dict()
    view["granted_autonomy_name"] = autonomy.level_name(record.granted_level)
    return view


def _delegate_task(principal: Principal, skill: str, req_data: dict):
    """Governed agent-to-agent hand-off: create a delegation if policy allows it.

    The two-axis rule: both principals must *hold* the skill (the right to route that
    task type), and the requested level must fit inside the delegatee's own policy
    ceiling and — for sub-delegation — inside the parent grant. A delegation therefore
    never manufactures authority: the delegatee only ever works under levels its own
    policy grants, and chains can only narrow.
    """
    delegatee_name = str(req_data.get("delegatee", "")).strip()
    delegatee = POLICY.find_principal(delegatee_name)
    detail = f"{skill}->{delegatee_name}"
    if delegatee is None:
        exc = delegation.DelegationError(
            "unknown_delegatee", f"No principal named '{delegatee_name}' in policy.", 404
        )
        return _delegation_error(principal, exc, detail)

    requested = autonomy.parse_level(
        req_data.get("autonomy_level"), autonomy.DEFAULT_REQUEST_LEVEL
    )
    try:
        record = DELEGATIONS.create(
            delegator=principal,
            delegatee=delegatee,
            skill=skill,
            requested_level=requested,
            delegatee_ceiling=autonomy_ceiling_for(delegatee),
            parent_id=str(req_data.get("parent_task", "")).strip() or None,
            max_depth=POLICY.max_delegation_depth,
            task=str(req_data.get("task", ""))[:500],
            ttl_seconds=POLICY.delegation_ttl_seconds,
        )
    except delegation.DelegationError as exc:
        return _delegation_error(principal, exc, detail)

    METRICS.inc("gateway_a2a_tasks_total", {"decision": "allow"})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow",
        reason=f"delegate:{skill}->{delegatee_name}@L{record.granted_level}"
               f",depth={record.depth}",
        status=202, run_id=getattr(g, "run_id", ""),
    )
    return jsonify(_delegation_view(record)), 202


@app.route("/a2a/agents", methods=["GET"])
def a2a_agents():
    """Agent directory: every policy principal's card, for peer discovery.

    This is how agents *understand each other* without hardcoding: each card is
    rendered from enforced policy (granted skills + autonomy ceiling), so a planner
    can match a task to a peer against authority facts, not self-descriptions.
    """
    base_url = request.host_url.rstrip("/")
    principals = POLICY.principals() or [getattr(g, "principal", None) or OWNER_PRINCIPAL]
    return jsonify(
        {
            "agents": [
                a2a.agent_card(p, base_url=base_url, ceiling=autonomy_ceiling_for(p))
                for p in principals
            ],
            "max_delegation_depth": POLICY.max_delegation_depth,
        }
    )


@app.route("/a2a/tasks", methods=["GET"])
def a2a_task_list():
    """A principal's task inbox (or outbox with ``role=delegator``).

    ``all=true`` widens to every delegation, but only for principals holding the
    ``can_read_audit`` grant — task history is governance telemetry like the audit.
    """
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    status = str(request.args.get("status", "")).strip() or None
    if str(request.args.get("all", "")).lower() in ("1", "true", "yes"):
        if not principal.can_read_audit:
            exc = delegation.DelegationError(
                "audit_not_allowed",
                f"Principal '{principal.name}' lacks can_read_audit; it may only "
                "list its own tasks.",
            )
            return _delegation_error(principal, exc, "list_all")
        records = DELEGATIONS.all()
        if status:
            records = [r for r in records if r.status == status]
    else:
        role = "delegator" if request.args.get("role") == "delegator" else "delegatee"
        records = DELEGATIONS.for_principal(principal.name, role=role, status=status)
    return jsonify({"tasks": [_delegation_view(r) for r in records]})


@app.route("/a2a/tasks/<task_id>", methods=["GET"])
def a2a_task_get(task_id: str):
    """One delegation plus its full custody chain (participants or auditors only)."""
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    record = DELEGATIONS.get(task_id)
    if record is None:
        return jsonify(
            {"error": {"message": f"No delegation '{task_id}'",
                       "type": "invalid_request_error", "code": "unknown_task"}}
        ), 404
    chain = DELEGATIONS.chain(task_id)
    involved = {d.delegator for d in chain} | {d.delegatee for d in chain}
    if principal.name not in involved and not principal.can_read_audit:
        exc = delegation.DelegationError(
            "not_task_participant",
            f"Principal '{principal.name}' is not part of delegation '{task_id}' "
            "and lacks can_read_audit.",
        )
        return _delegation_error(principal, exc, task_id)
    return jsonify(
        {"task": _delegation_view(record), "chain": [_delegation_view(d) for d in chain]}
    )


@app.route("/a2a/tasks/<task_id>/result", methods=["POST"])
def a2a_task_result(task_id: str):
    """The delegatee reports its outcome; nobody else may speak for the task."""
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    req_data = request.get_json(force=True, silent=True) or {}
    try:
        record = DELEGATIONS.report(
            task_id,
            reporter=principal.name,
            status=str(req_data.get("status", "")).strip(),
            result=str(req_data.get("result", ""))[:2000],
            verdict=str(req_data.get("verdict", ""))[:100],
        )
    except delegation.DelegationError as exc:
        return _delegation_error(principal, exc, task_id)
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"task_result:{task_id}:{record.status}", status=200,
    )
    return jsonify(_delegation_view(record))


# -----------------------------
# MCP — governed tool access
# -----------------------------
@app.route("/mcp/tools", methods=["GET"])
def mcp_tools():
    """List the governed tools this principal is permitted to call."""
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    allowed = [t for t in tools.list_tools() if principal.may_use_tool(t["name"])]
    return jsonify({"tools": allowed})


@app.route("/mcp/call", methods=["POST"])
def mcp_call():
    """Governed MCP tool invocation: a tool call is not authority unless granted.

    Enforcement runs before the tool handler: the tool must exist, be in the principal's
    ``allowed_tools``, and sit at or below the principal's autonomy ceiling (each tool
    declares the autonomy level it requires). Only then does the (pure, side-effect-free)
    handler run, and the outcome is recorded.
    """
    req_data = request.get_json(force=True, silent=True) or {}
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    name = str(req_data.get("tool", "")).strip()
    tool = tools.get_tool(name)

    if tool is None:
        return jsonify(
            {"error": {"message": f"Unknown tool '{name}'", "type": "invalid_request_error",
                       "code": "tool_not_found"}}
        ), 404

    if not principal.may_use_tool(name):
        METRICS.inc("gateway_tool_calls_total", {"decision": "deny"})
        METRICS.inc("gateway_authz_denials_total", {"reason": "tool_not_allowed"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny", reason=f"tool_not_allowed:{name}", status=403,
        )
        return jsonify(
            {"error": {"message": f"Principal '{principal.name}' is not granted tool '{name}'",
                       "type": "permission_error", "code": "tool_not_allowed"}}
        ), 403

    ceiling = autonomy_ceiling_for(principal)
    if ceiling is not None and tool.min_level > ceiling:
        METRICS.inc("gateway_tool_calls_total", {"decision": "deny"})
        METRICS.inc("gateway_authz_denials_total", {"reason": "autonomy_exceeded"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""), principal=principal.name,
            method=request.method, path=request.path, model=None,
            decision="deny",
            reason=f"autonomy_exceeded:tool={name},needs=L{tool.min_level},ceiling=L{ceiling}",
            status=403,
        )
        return jsonify(
            {"error": {"message": (
                f"Tool '{name}' requires autonomy L{tool.min_level} "
                f"({autonomy.level_name(tool.min_level)}); principal '{principal.name}' is "
                f"capped at L{ceiling}"),
                "type": "permission_error", "code": "autonomy_exceeded"}}
        ), 403

    try:
        result = tool.handler(dict(req_data.get("arguments", {}) or {}))
    except Exception as exc:  # a tool that errors is a failed call, never a silent pass
        logger.exception(f"TOOL_FAILED | tool={log_safe(name)} | {log_safe(exc)}")
        return jsonify(
            {"error": {"message": "Tool execution failed", "type": "server_error",
                       "code": "tool_failed"}}
        ), 500

    METRICS.inc("gateway_tool_calls_total", {"decision": "allow"})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""), principal=principal.name,
        method=request.method, path=request.path, model=None,
        decision="allow", reason=f"tool_call:{name}", status=200,
    )
    return jsonify({"tool": name, "autonomy_level": tool.min_level, "result": result})


@app.route("/models", methods=["GET"])
@app.route("/v1/models", methods=["GET"])
@app.route("/v1/models/models", methods=["GET"])
def list_models():
    data = []

    for alias, actual in ROUTE_MAP.items():
        data.append(
            {
                "id": alias,
                "object": "model",
                "created": 0,
                "owned_by": "private-infra",
            }
        )

    for alias, actual in ROUTE_MAP.items():
        data.append(
            {
                "id": actual,
                "object": "model",
                "created": 0,
                "owned_by": "private-infra",
            }
        )

    return jsonify(
        {
            "object": "list",
            "data": data,
        }
    )


@app.route("/v1/chat/completions", methods=["POST"])
def chat_completions():
    req_data = request.get_json(force=True, silent=True) or {}

    requested_model = req_data.get("model", DEFAULT_MODEL_ALIAS)
    messages = req_data.get("messages", [])

    # --- AUTHORIZATION: may this principal use the requested model? ---
    principal = getattr(g, "principal", None) or OWNER_PRINCIPAL
    if not principal.may_use(requested_model):
        logger.warning(
            f"AUTHZ_DENY | principal={log_safe(principal.name)} | model={log_safe(requested_model)}"
        )
        METRICS.inc("gateway_authz_denials_total", {"reason": "model_not_allowed"})
        METRICS.inc("gateway_requests_total", {"principal": principal.name, "decision": "deny"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""),
            principal=principal.name,
            method=request.method,
            path=request.path,
            model=requested_model,
            decision="deny",
            reason="model_not_allowed",
            status=403,
        )
        return jsonify(
            {
                "error": {
                    "message": (
                        f"Principal '{principal.name}' is not permitted to use "
                        f"model '{requested_model}'"
                    ),
                    "type": "permission_error",
                    "code": "model_not_allowed",
                }
            }
        ), 403

    # --- AUTONOMY: does this request exceed the principal's autonomy ceiling? ---
    # The request declares an intended level (header or body); the principal carries a
    # ceiling (its own, else the policy default). When no ceiling is configured anywhere,
    # gating is off. This turns the L0-L6 ladder from a prompt rule into an enforced one.
    # The effective declared level is the most-privileged across header and body, so a
    # caller cannot under-declare in one channel to bypass the ceiling via the other.
    declared_level = autonomy.declared_level(
        request.headers.get("X-Autonomy-Level"),
        req_data.get("autonomy_level"),
    )
    autonomy_ceiling = principal.max_autonomy_level
    if autonomy_ceiling is None:
        autonomy_ceiling = POLICY.default_max_autonomy_level
    if (
        autonomy_ceiling is not None
        and declared_level is not None
        and declared_level > autonomy_ceiling
    ):
        logger.warning(
            f"AUTONOMY_DENY | principal={log_safe(principal.name)} | "
            f"requested=L{log_safe(declared_level)} | ceiling=L{autonomy_ceiling}"
        )
        METRICS.inc("gateway_authz_denials_total", {"reason": "autonomy_exceeded"})
        METRICS.inc("gateway_requests_total", {"principal": principal.name, "decision": "deny"})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""),
            principal=principal.name,
            method=request.method,
            path=request.path,
            model=requested_model,
            decision="deny",
            reason=(
                f"autonomy_exceeded:requested=L{declared_level}"
                f"({autonomy.level_name(declared_level)}),ceiling=L{autonomy_ceiling}"
            ),
            status=403,
        )
        return jsonify(
            {
                "error": {
                    "message": (
                        f"Principal '{principal.name}' is capped at autonomy "
                        f"L{autonomy_ceiling} ({autonomy.level_name(autonomy_ceiling)}); "
                        f"request declared L{declared_level} "
                        f"({autonomy.level_name(declared_level)})"
                    ),
                    "type": "permission_error",
                    "code": "autonomy_exceeded",
                }
            }
        ), 403

    # --- TOOL SAFETY PREAMBLE INJECTED HERE ---
    if req_data.get("tools") or req_data.get("tool_choice"):
        messages = [
            {
                "role": "system",
                "content": (
                    "Tool calling is not available through this local gateway. "
                    "Do not emit tool calls, XML tags, JSON tool requests, hidden thoughts, "
                    "or <|tool_call> blocks. Respond only with plain text instructions or summaries. "
                    "Do not claim you read or wrote files unless the user provided the contents directly."
                ),
            }
        ] + messages

    stream = bool(req_data.get("stream", False))
    temperature = req_data.get("temperature")
    requested_max_tokens = int(req_data.get("max_tokens") or 2048)

    # Model-specific output caps.
    DEFAULT_OUTPUT_TOKENS = int(os.environ.get("PRIVATE_AI_MAX_OUTPUT_TOKENS", "4096"))

    MODEL_OUTPUT_TOKEN_CAPS = {
        "strategy": int(os.environ.get("PRIVATE_AI_MAX_OUTPUT_TOKENS_STRATEGY", "4096")),
        "strategy_v2": int(os.environ.get("PRIVATE_AI_MAX_OUTPUT_TOKENS_STRATEGY_V2", "4096")),
        "engineering": int(os.environ.get("PRIVATE_AI_MAX_OUTPUT_TOKENS_ENGINEERING", "4096")),
        "offsec": int(os.environ.get("PRIVATE_AI_MAX_OUTPUT_TOKENS_OFFSEC", "4096")),
    }

    requested_model_for_cap = str(req_data.get("model") or "strategy")
    model_cap = MODEL_OUTPUT_TOKEN_CAPS.get(requested_model_for_cap, DEFAULT_OUTPUT_TOKENS)

    # Effective cap is the tightest of: the request, the per-model cap, and the
    # principal's policy cap (governance can only tighten, never loosen).
    caps = [requested_max_tokens, model_cap]
    if principal.max_output_tokens is not None:
        caps.append(principal.max_output_tokens)
    max_tokens = min(caps)

    if requested_max_tokens != max_tokens:
        logger.info(
            f"MAX_TOKENS_CLAMPED | model={log_safe(requested_model_for_cap)} | requested={log_safe(requested_max_tokens)} | effective={max_tokens} | cap={model_cap}"
        )
    logger.info(
        "REQUEST_BODY_KEYS | "
        f"keys={log_safe(list(req_data.keys()))} | "
        f"model={log_safe(requested_model)} | "
        f"stream={stream} | "
        f"max_tokens={max_tokens} | "
        f"temperature={log_safe(temperature)} | "
        f"has_tools={'tools' in req_data} | "
        f"has_tool_choice={'tool_choice' in req_data} | "
        f"has_response_format={'response_format' in req_data}"
    )

    # Accept but ignore unsupported OpenAI client extras for now.
    _ = req_data.get("tools")
    _ = req_data.get("tool_choice")
    _ = req_data.get("parallel_tool_calls")
    _ = req_data.get("response_format")
    _ = req_data.get("stream_options")
    _ = req_data.get("metadata")
    _ = req_data.get("user")

    clean_messages = normalize_messages(messages)

    # Ingress AI-firewall: inspect inbound prompt text for prompt-injection / jailbreak
    # / PII before it reaches the model. 'flag' audits and continues; 'block' refuses at
    # or above the configured severity. The scan is evasion-aware (Unicode-normalizing).
    if INGRESS.action != "off":
        user_text = "\n".join(
            str(m.get("content", "")) for m in clean_messages
            if m.get("role") in ("user", "tool")
        )
        scan = INGRESS.scan(user_text)
        if scan.triggered:
            for category in scan.categories:
                METRICS.inc("gateway_ingress_events_total", {"category": category})
            evasion_note = f",evasion={'+'.join(scan.evasions)}" if scan.evasions else ""
            if INGRESS.should_block(scan):
                METRICS.inc("gateway_authz_denials_total", {"reason": "prompt_injection"})
                METRICS.inc(
                    "gateway_requests_total",
                    {"principal": principal.name, "decision": "deny"},
                )
                DECISION_LOG.record(
                    request_id=getattr(g, "request_id", ""), principal=principal.name,
                    method=request.method, path=request.path, model=requested_model,
                    decision="deny",
                    reason=f"prompt_injection:{scan.max_severity}:"
                           f"{'+'.join(scan.categories)}{evasion_note}",
                    status=403,
                )
                logger.warning(
                    f"INGRESS_BLOCK | principal={log_safe(principal.name)} | "
                    f"severity={log_safe(scan.max_severity)} | categories={log_safe(scan.categories)} | "
                    f"evasions={log_safe(scan.evasions)}"
                )
                return jsonify(
                    {"error": {"message": (
                        "Prompt blocked by the ingress firewall: it matched a "
                        f"{scan.max_severity}-severity {', '.join(scan.categories)} "
                        "pattern."),
                        "type": "permission_error", "code": "prompt_injection_blocked"}}
                ), 403
            # flag (or below threshold): record and continue.
            DECISION_LOG.record(
                request_id=getattr(g, "request_id", ""), principal=principal.name,
                method=request.method, path=request.path, model=requested_model,
                decision="flag",
                reason=f"ingress_flag:{scan.max_severity}:"
                       f"{'+'.join(scan.categories)}{evasion_note}",
                status=200,
            )
            logger.info(
                f"INGRESS_FLAG | principal={log_safe(principal.name)} | "
                f"severity={log_safe(scan.max_severity)} | categories={log_safe(scan.categories)}"
            )

    # Context optimization: always measure the achievable prompt-token savings; only
    # rewrite the prompt when policy opts in (context_compress). Silently mutating a
    # caller's prompt is a trust boundary, so the safe default is measure-only.
    ctx = contextopt.compress_messages(
        clean_messages,
        budget=POLICY.context_budget,
        apply=POLICY.context_compress,
    )
    if ctx.saved_tokens:
        METRICS.inc("gateway_context_tokens_saved_total", value=ctx.saved_tokens)
        logger.info(
            f"CONTEXT_OPT | applied={ctx.applied} | saved_tokens={ctx.saved_tokens} "
            f"| saved_pct={ctx.saved_pct} | ratio={ctx.ratio} | steps={log_safe(','.join(ctx.steps))}"
        )
    if ctx.applied:
        clean_messages = ctx.messages

    resolved_model = resolve_model(requested_model)
    prompt_tokens_rough = estimate_tokens_rough(
        "\n".join(str(m.get("content", "")) for m in clean_messages)
    )

    logger.info(
        f"INFERENCE_START | RequestedModel={log_safe(requested_model)} | "
        f"ResolvedModel={log_safe(resolved_model)} | Backend={BACKEND.name} | "
        f"MaxTokens={max_tokens} | PromptTokensRough={prompt_tokens_rough}"
    )

    try:
        result = BACKEND.complete(
            resolved_model,
            clean_messages,
            max_tokens=max_tokens,
            temperature=temperature if isinstance(temperature, (int, float)) else None,
        )
        response_text = sanitize_model_output(result.text)
        served_model = result.model
    except backends.ModelLoadError:
        return jsonify(
            {
                "error": {
                    "message": "Failed to load requested model",
                    "type": "server_error",
                    "code": "model_load_failed",
                }
            }
        ), 500
    except backends.BackendError as e:
        logger.error(f"UPSTREAM_FAILED | {log_safe(e)}")
        # Detail is logged server-side only; never surface backend/exception text to the
        # caller (CWE-209, stack-trace / internal-error exposure).
        return jsonify(
            {
                "error": {
                    "message": "Inference backend failed",
                    "type": "server_error",
                    "code": "upstream_error",
                }
            }
        ), 502
    except Exception as e:
        logger.exception(f"INFERENCE_FAILED | {log_safe(e)}")
        return jsonify(
            {
                "error": {
                    "message": "Inference failed",
                    "type": "server_error",
                    "code": "inference_failed",
                }
            }
        ), 500

    logger.info("INFERENCE_COMPLETE | Payload generated")

    # Egress guardrail: scan (and redact/block) secret-like content before the
    # response leaves the gateway, regardless of how authorized the caller is.
    guard = GUARDRAILS.scan(response_text)
    if guard.fired:
        logger.warning(
            f"GUARDRAIL_FIRED | action={GUARDRAILS.action} | matched={','.join(guard.triggered)}"
        )
        METRICS.inc("gateway_guardrail_events_total", {"action": GUARDRAILS.action})
        DECISION_LOG.record(
            request_id=getattr(g, "request_id", ""),
            principal=principal.name,
            method=request.method,
            path=request.path,
            model=requested_model,
            decision="filter",
            reason=f"egress_{GUARDRAILS.action}:{','.join(guard.triggered)}",
            status=200,
            run_id=getattr(g, "run_id", ""),
        )
        response_text = guard.text

    METRICS.inc("gateway_requests_total", {"principal": principal.name, "decision": "allow"})
    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""),
        principal=principal.name,
        method=request.method,
        path=request.path,
        model=requested_model,
        decision="allow",
        reason="completed",
        status=200,
        run_id=getattr(g, "run_id", ""),
    )

    completion_tokens_rough = estimate_tokens_rough(response_text)

    if stream:

        def stream_generator():
            first_chunk = {
                "id": "chatcmpl-local",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": served_model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"role": "assistant", "content": response_text},
                        "finish_reason": None,
                    }
                ],
            }

            final_chunk = {
                "id": "chatcmpl-local",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": served_model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }

            yield f"data: {json.dumps(first_chunk)}\n\n"
            yield f"data: {json.dumps(final_chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return Response(
            stream_generator(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return jsonify(
        {
            "id": "chatcmpl-local",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": served_model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": response_text,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens_rough,
                "completion_tokens": completion_tokens_rough,
                "total_tokens": prompt_tokens_rough + completion_tokens_rough,
            },
        }
    )


@app.route("/v1/completions", methods=["POST"])
def completions():
    """
    Compatibility fallback for clients that accidentally call legacy completions.
    """
    req_data = request.get_json(force=True, silent=True) or {}
    prompt = req_data.get("prompt", "")
    model = req_data.get("model", DEFAULT_MODEL_ALIAS)
    max_tokens = int(req_data.get("max_tokens") or 512)

    fake_chat_req = {
        "model": model,
        "messages": [{"role": "user", "content": str(prompt)}],
        "max_tokens": max_tokens,
        "stream": False,
    }

    with app.test_request_context(
        "/v1/chat/completions",
        method="POST",
        json=fake_chat_req,
        headers={"Authorization": f"Bearer {AUTH_TOKEN}"},
    ):
        return chat_completions()


if __name__ == "__main__":
    # Fail-closed: refuse to start without an auth token.
    if not AUTH_TOKEN:
        raise SystemExit(
            "PRIVATE_AI_AUTH_TOKEN is not set. Refusing to start the gateway without "
            "an auth token. Set it in your environment or .env (see .env.example)."
        )
    if AUTH_TOKEN == _DEV_DEFAULT_TOKEN:
        logger.warning(
            "AUTH_TOKEN_IS_DEV_DEFAULT | Using the documented development token; "
            "set a unique PRIVATE_AI_AUTH_TOKEN before any real use."
        )
    # Single process/thread avoids multiple MLX model copies.
    app.run(host="127.0.0.1", port=8080, threaded=False)
