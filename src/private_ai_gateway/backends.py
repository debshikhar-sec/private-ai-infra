"""Pluggable inference backends — the governance plane is model-plane-agnostic.

The gateway's value is the *authority layer* (identity, policy, autonomy ceilings,
audit); where tokens actually get generated is an implementation detail. This module
isolates that detail behind one small interface so the same enforcement code runs:

  * ``mlx``    — in-process Apple Silicon inference (the original local-first path);
  * ``openai`` — any OpenAI-compatible upstream: an enterprise LLM-as-a-Service
                 platform, vLLM, TGI, Ollama, LM Studio, llama.cpp server, …;
  * ``demo``   — a deterministic offline simulator so the plane (and its console) can
                 be demonstrated on any machine with no model and no network.

Selection is by ``PRIVATE_AI_BACKEND`` (``auto`` | ``mlx`` | ``openai`` | ``demo``).
``auto`` prefers an explicitly configured upstream, then MLX where it is importable,
and falls back to the demo simulator — so ``pip install && serve`` works everywhere.

Every backend returns *raw* text; output sanitization and the egress guardrails stay
in the gateway, applied uniformly regardless of where the text came from.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger("AuditTrail")


class BackendError(Exception):
    """The backend could not produce a completion (upstream/network/runtime failure)."""


class ModelLoadError(BackendError):
    """The requested model could not be loaded (MLX path)."""


@dataclass(frozen=True)
class CompletionResult:
    """What a backend produced: the text and the model that actually served it."""

    text: str
    model: str


class MLXBackend:
    """In-process MLX inference (Apple Silicon). Imports MLX lazily.

    ``loader``/``generator`` default to ``mlx_lm.load``/``mlx_lm.generate`` and exist
    as injection points so the swap/reuse/failure logic is testable without MLX.
    """

    name = "mlx"

    def __init__(self, loader=None, generator=None):
        self._loader = loader
        self._generator = generator
        self.current_model: str | None = None
        self._model_ref = None
        self._tokenizer_ref = None

    def _runtime(self):
        if self._loader is None or self._generator is None:
            from mlx_lm import generate, load  # deferred: only the MLX path pays for MLX

            self._loader = self._loader or load
            self._generator = self._generator or generate
        return self._loader, self._generator

    def _clear_cache(self):
        import gc

        gc.collect()
        try:
            import mlx.core as mx

            try:
                mx.clear_cache()
            except AttributeError:
                mx.metal.clear_cache()
        except ImportError:
            pass  # fake loader injected in tests — nothing to clear

    def _swap_if_needed(self, target_model: str) -> None:
        if target_model == self.current_model and self._model_ref is not None:
            logger.info(f"MODEL_REUSE | {target_model}")
            return
        loader, _ = self._runtime()
        logger.info(f"MODEL_SWAP_START | {self.current_model} -> {target_model}")
        try:
            self._model_ref = None
            self._tokenizer_ref = None
            self._clear_cache()
            self._model_ref, self._tokenizer_ref = loader(target_model)
            self.current_model = target_model
            logger.info(f"MODEL_LOAD_SUCCESS | {target_model}")
        except Exception as exc:
            logger.exception(f"MODEL_LOAD_FAILED | {target_model} | {exc}")
            self.current_model = None
            self._model_ref = None
            self._tokenizer_ref = None
            self._clear_cache()
            raise ModelLoadError(f"failed to load model '{target_model}'") from exc

    def _build_prompt(self, messages: list[dict]) -> str:
        """Render normalized messages through the model's chat template.

        Qwen templates require a single leading system message and (for the thinking
        variants) the hard ``enable_thinking=False`` switch — prompt-only ``/no_think``
        was tested and is not reliable enough for this gateway.
        """
        clean = list(messages)
        model_name = str(self.current_model or "").lower()
        if "qwen" in model_name:
            system_parts = [
                str(m.get("content", "")).strip()
                for m in clean
                if m.get("role") == "system" and str(m.get("content", "")).strip()
            ]
            non_system = [m for m in clean if m.get("role") != "system"]
            if system_parts:
                clean = [{"role": "system", "content": "\n\n".join(system_parts)}] + non_system

        try:
            if hasattr(self._tokenizer_ref, "apply_chat_template"):
                kwargs = {"tokenize": False, "add_generation_prompt": True}
                if "qwen" in model_name:
                    kwargs["enable_thinking"] = False
                return self._tokenizer_ref.apply_chat_template(clean, **kwargs)
        except Exception as exc:
            logger.exception(f"CHAT_TEMPLATE_FAILED | {exc}")

        lines = [f"{m['role']}: {m['content']}" for m in clean]
        lines.append("assistant:")
        return "\n".join(lines)

    def complete(
        self,
        resolved_model: str,
        messages: list[dict],
        *,
        max_tokens: int,
        temperature: float | None = None,
    ) -> CompletionResult:
        self._swap_if_needed(resolved_model)
        _, generator = self._runtime()
        text = generator(
            self._model_ref,
            self._tokenizer_ref,
            prompt=self._build_prompt(messages),
            max_tokens=max_tokens,
            verbose=False,
        )
        return CompletionResult(text=str(text), model=self.current_model or resolved_model)

    def info(self) -> dict:
        return {"mode": self.name, "current_model": self.current_model}


class OpenAIBackend:
    """Forward completions to any OpenAI-compatible upstream over HTTP.

    This is the bring-your-own-model-plane path: point the gateway at an internal
    LLM-as-a-Service endpoint (or vLLM/TGI/Ollama/LM Studio) and the enforcement,
    audit, and guardrails run in front of it unchanged. Uses only the standard
    library so the platform-agnostic install stays dependency-light.
    """

    name = "openai"

    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 120.0):
        base = (base_url or "").strip().rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise ValueError(
                "PRIVATE_AI_UPSTREAM_BASE_URL must be an http(s) URL, "
                f"got: {base!r}"
            )
        self.base_url = base
        self._api_key = api_key or None
        self._timeout = timeout
        self.current_model: str | None = None

    def complete(
        self,
        resolved_model: str,
        messages: list[dict],
        *,
        max_tokens: int,
        temperature: float | None = None,
    ) -> CompletionResult:
        payload: dict = {
            "model": resolved_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if temperature is not None:
            payload["temperature"] = temperature

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        req = urllib.request.Request(  # scheme validated to http(s) in __init__  # nosec B310
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:  # nosec B110 — best-effort error detail only
                pass
            logger.error(f"UPSTREAM_HTTP_ERROR | status={exc.code} | {detail}")
            raise BackendError(f"upstream returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            logger.error(f"UPSTREAM_UNREACHABLE | {exc}")
            raise BackendError("upstream unreachable or returned invalid JSON") from exc

        try:
            text = body["choices"][0]["message"]["content"] or ""
            served = str(body.get("model") or resolved_model)
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError("upstream response was not an OpenAI-style completion") from exc

        self.current_model = served
        return CompletionResult(text=str(text), model=served)

    def info(self) -> dict:
        return {"mode": self.name, "base_url": self.base_url, "current_model": self.current_model}


class DemoBackend:
    """A deterministic offline simulator — no model, no network, same governance.

    Exists so the *enforcement plane* can be demonstrated anywhere: responses are
    canned and clearly labeled as simulated. One trigger phrase deliberately emits a
    well-known example credential (AWS's documented ``AKIAIOSFODNN7EXAMPLE``) so the
    egress guardrail can be watched firing on a live wire.
    """

    name = "demo"

    # The documented AWS example key — not a real credential.
    _EXAMPLE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # nosec B105

    _CANNED = {
        "research": (
            "Simulated research summary: Q2 exposure is concentrated in EU rates; "
            "two counterparties exceed the concentration threshold and are flagged "
            "for review."
        ),
        "kyc": (
            "Simulated KYC note: entity documentation is complete; no adverse media "
            "found in the simulated corpus; screening verdict is recorded separately "
            "by the sanctions tool."
        ),
        "trade": (
            "Simulated draft (suggest-only): reduce the EUR swap position by 10% and "
            "hedge the residual with futures. This is a proposal — execution authority "
            "is not granted at this autonomy level."
        ),
    }

    def __init__(self):
        self.current_model = "demo-simulator"

    def complete(
        self,
        resolved_model: str,
        messages: list[dict],
        *,
        max_tokens: int,
        temperature: float | None = None,
    ) -> CompletionResult:
        last_user = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user = str(m.get("content", ""))
                break
        lowered = last_user.lower()

        if "leak a secret" in lowered:
            # Deliberate: proves the guardrail redacts secrets on the wire in demos.
            text = f"As requested, the credential is {self._EXAMPLE_SECRET} — handle with care."
        else:
            text = next(
                (reply for key, reply in self._CANNED.items() if key in lowered),
                "Simulated response from the demo backend. The request cleared every "
                "governance gate — identity, model grant, autonomy ceiling, and rate "
                "limit — before this text was generated.",
            )
        return CompletionResult(text=text, model=f"demo::{resolved_model}")

    def info(self) -> dict:
        return {"mode": self.name, "current_model": self.current_model}


def mlx_available() -> bool:
    return (
        importlib.util.find_spec("mlx") is not None
        and importlib.util.find_spec("mlx_lm") is not None
    )


def select_backend(
    mode: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    mlx_ok: bool | None = None,
):
    """Build the backend for a mode string (``auto``/``mlx``/``openai``/``demo``).

    ``auto`` resolution order: explicit upstream URL → MLX where importable → demo.
    An unknown mode fails loudly rather than silently serving the wrong plane.
    """
    mode = (mode or "auto").strip().lower()
    mlx_ok = mlx_available() if mlx_ok is None else mlx_ok

    if mode == "auto":
        if base_url:
            mode = "openai"
        elif mlx_ok:
            mode = "mlx"
        else:
            mode = "demo"

    if mode == "openai":
        if not base_url:
            raise ValueError(
                "backend 'openai' requires PRIVATE_AI_UPSTREAM_BASE_URL "
                "(an OpenAI-compatible endpoint, e.g. http://127.0.0.1:11434/v1)"
            )
        return OpenAIBackend(base_url, api_key=api_key)
    if mode == "mlx":
        return MLXBackend()
    if mode == "demo":
        return DemoBackend()
    raise ValueError(f"unknown PRIVATE_AI_BACKEND mode: {mode!r}")
