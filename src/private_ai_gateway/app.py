#!/usr/bin/env python3
"""
Local OpenAI-compatible MLX Gateway
Client -> Nginx -> Flask -> MLX
"""

import gc
import hmac
import json
import logging
import os
import re
import time
import uuid

import mlx.core as mx
from flask import Flask, Response, g, jsonify, request
from mlx_lm import generate, load

from private_ai_gateway.audit import DecisionLog
from private_ai_gateway.policy import Policy, Principal

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
DECISION_LOG = DecisionLog(os.path.join(LOG_DIR, "decisions.jsonl"))

# The owner token (PRIVATE_AI_AUTH_TOKEN) maps to this break-glass admin identity,
# permitted every model. Finer-grained restrictions come from POLICY principals.
OWNER_PRINCIPAL = Principal("owner", frozenset({"*"}), None)

ROUTE_MAP = {
    "strategy": "mlx-community/Qwen3.6-27B-OptiQ-4bit",
    "engineering": "mlx-community/Qwen3-Coder-30B-A3B-Instruct-8bit",
    "offsec": "mlx-community/Llama-3-70B-Instruct-Gradient-1048k-4bit",
}

DEFAULT_MODEL_ALIAS = "strategy"

# -----------------------------
# Logging
# -----------------------------
logger = logging.getLogger("AuditTrail")
logger.setLevel(logging.INFO)

if not logger.handlers:
    fh = logging.FileHandler(AUDIT_LOG_PATH)
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(fh)

# -----------------------------
# Global MLX state
# -----------------------------
CURRENT_MODEL_NAME = None
MODEL_REF = None
TOKENIZER_REF = None


def clear_mlx_cache():
    gc.collect()
    try:
        mx.clear_cache()
    except AttributeError:
        mx.metal.clear_cache()


def resolve_model(requested_model: str) -> str:
    if not requested_model:
        requested_model = DEFAULT_MODEL_ALIAS
    return ROUTE_MAP.get(requested_model, requested_model)


def swap_model_if_needed(requested_model: str) -> bool:
    global CURRENT_MODEL_NAME, MODEL_REF, TOKENIZER_REF

    target_model = resolve_model(requested_model)

    if target_model == CURRENT_MODEL_NAME and MODEL_REF is not None and TOKENIZER_REF is not None:
        logger.info(f"MODEL_REUSE | {target_model}")
        return True

    logger.info(f"MODEL_SWAP_START | {CURRENT_MODEL_NAME} -> {target_model}")

    try:
        MODEL_REF = None
        TOKENIZER_REF = None
        clear_mlx_cache()

        logger.info(f"MODEL_LOAD_START | {target_model}")
        MODEL_REF, TOKENIZER_REF = load(target_model)
        CURRENT_MODEL_NAME = target_model
        logger.info(f"MODEL_LOAD_SUCCESS | {target_model}")
        return True

    except Exception as e:
        logger.exception(f"MODEL_LOAD_FAILED | {target_model} | {str(e)}")
        CURRENT_MODEL_NAME = None
        MODEL_REF = None
        TOKENIZER_REF = None
        clear_mlx_cache()
        return False


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


def build_prompt(messages):
    clean_messages = normalize_messages(messages)

    # Qwen chat templates require system content to appear only at the beginning.
    # Tool-safety preambles can create multiple system messages.
    # Merge all system messages into one leading system message before rendering.
    current_model_name = str(CURRENT_MODEL_NAME or "").lower()
    if "qwen" in current_model_name:
        system_parts = []
        non_system_messages = []
        for msg in clean_messages:
            if msg.get("role") == "system":
                content = str(msg.get("content", "")).strip()
                if content:
                    system_parts.append(content)
            else:
                non_system_messages.append(msg)

        if system_parts:
            clean_messages = [
                {
                    "role": "system",
                    "content": "\n\n".join(system_parts),
                }
            ] + non_system_messages

    try:
        if hasattr(TOKENIZER_REF, "apply_chat_template"):
            chat_template_kwargs = {
                "tokenize": False,
                "add_generation_prompt": True,
            }

            # Qwen3/Qwen3.6 thinking models must use the hard template switch.
            # Prompt-only /no_think was tested and is not reliable enough for this gateway.
            current_model_name = str(CURRENT_MODEL_NAME or "").lower()
            if "qwen" in current_model_name:
                chat_template_kwargs["enable_thinking"] = False

            return TOKENIZER_REF.apply_chat_template(
                clean_messages,
                **chat_template_kwargs,
            )
    except Exception as e:
        logger.exception(f"CHAT_TEMPLATE_FAILED | {str(e)}")

    # Fallback prompt format
    lines = []
    for m in clean_messages:
        lines.append(f"{m['role']}: {m['content']}")
    lines.append("assistant:")
    return "\n".join(lines)


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
    g.principal = None

    # Allow health only without auth.
    if request.path in ("/health", "/v1/health"):
        return None

    header = request.headers.get("Authorization", "")
    token = header[7:] if header.startswith("Bearer ") else ""
    principal = _identify_principal(token)

    # The Authorization header is never logged (it carries the bearer credential).
    if principal is None:
        logger.warning(f"AUTH_FAILURE | IP={request.remote_addr} | Path={request.path}")
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
    logger.info(
        f"AUTH_SUCCESS | principal={principal.name} | "
        f"IP={request.remote_addr} | Path={request.path}"
    )
    return None


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
            "current_model": CURRENT_MODEL_NAME,
            "models": list(ROUTE_MAP.keys()),
        }
    )


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
            f"AUTHZ_DENY | principal={principal.name} | model={requested_model}"
        )
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
            f"MAX_TOKENS_CLAMPED | model={requested_model_for_cap} | requested={requested_max_tokens} | effective={max_tokens} | cap={model_cap}"
        )
    logger.info(
        "REQUEST_BODY_KEYS | "
        f"keys={list(req_data.keys())} | "
        f"model={requested_model} | "
        f"stream={stream} | "
        f"max_tokens={max_tokens} | "
        f"temperature={temperature} | "
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

    if not swap_model_if_needed(requested_model):
        return jsonify(
            {
                "error": {
                    "message": "Failed to load requested model",
                    "type": "server_error",
                    "code": "model_load_failed",
                }
            }
        ), 500

    try:
        prompt = build_prompt(messages)
    except Exception as e:
        logger.exception(f"CONTEXT_FORMAT_ERROR | {str(e)}")
        return jsonify(
            {
                "error": {
                    "message": "Context formatting failed",
                    "type": "invalid_request_error",
                    "code": "context_format_error",
                }
            }
        ), 400

    prompt_tokens_rough = estimate_tokens_rough(prompt)

    logger.info(
        f"INFERENCE_START | RequestedModel={requested_model} | "
        f"ResolvedModel={CURRENT_MODEL_NAME} | MaxTokens={max_tokens} | "
        f"PromptChars={len(prompt)} | PromptTokensRough={prompt_tokens_rough}"
    )

    try:
        response_text = generate(
            MODEL_REF,
            TOKENIZER_REF,
            prompt=prompt,
            max_tokens=max_tokens,
            verbose=False,
        )
        response_text = sanitize_model_output(response_text)
    except Exception as e:
        logger.exception(f"INFERENCE_FAILED | {str(e)}")
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

    DECISION_LOG.record(
        request_id=getattr(g, "request_id", ""),
        principal=principal.name,
        method=request.method,
        path=request.path,
        model=requested_model,
        decision="allow",
        reason="completed",
        status=200,
    )

    completion_tokens_rough = estimate_tokens_rough(response_text)

    if stream:

        def stream_generator():
            first_chunk = {
                "id": "chatcmpl-local",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": CURRENT_MODEL_NAME,
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
                "model": CURRENT_MODEL_NAME,
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
            "model": CURRENT_MODEL_NAME,
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
