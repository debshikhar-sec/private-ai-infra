#!/usr/bin/env python3
"""
OpenAI-compatible AI governance gateway
Client -> (nginx) -> Flask enforcement plane -> inference backend

The enforcement plane (identity, policy, autonomy ceilings, guardrails, audit) is
model-plane-agnostic: the backend may be in-process MLX, any OpenAI-compatible
upstream (an enterprise LLM-as-a-Service platform, vLLM, Ollama, …), or an offline
demo simulator. See backends.py.
"""

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
# lifecycle, ordering, and authorization semantics are unchanged. The durable evidence
# database is initialized/validated alongside it but left unwired (no keys loaded here), so
# EVIDENCE_SINK stays None below.
_STATE_CONFIG = state.StateConfig.from_env(os.environ)
_OPENED_BACKEND = state.open_backend(_STATE_CONFIG)
APPROVAL_STORE = _OPENED_BACKEND.authority_store

# Step 5 / 5b — gateway authorization evidence emit: injection points ONLY (additive).
# The gateway can emit signed authorization records into a verifier-owned EvidenceSink at two
# points: `execute_validated` when execution authority is granted (orchestration._run_execute)
# and `approval_decided` when an approval decision is recorded (v1_approvals). Production
# defaults to no sink, so behavior is byte-identical to before. No key material is ever loaded
# from disk or env here — a caller (a test, or a later, separately-authorized wiring step) sets
# these. With REQUIRE_AUTHORIZATION_EVIDENCE True a configured-but-failing emit fails closed
# *before* the outcome it guards (execution refused / approval denied + run invalidated); with
# it False (default) emit is best-effort and never changes the governed outcome.
EVIDENCE_SINK = None
EVIDENCE_KEY = None
EVIDENCE_KEY_ID = ""
REQUIRE_AUTHORIZATION_EVIDENCE = False

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
