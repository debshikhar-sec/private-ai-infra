"""Context optimization: deterministic prompt compression to cut token exchange.

Every token sent to a model costs money and latency, and long agent conversations
accumulate a lot of *redundant* tokens — repeated system preambles, duplicated context
pasted across turns, boilerplate, and whitespace. Microsoft's LLMLingua / LongLLMLingua
work shows prompt compression can reach up to ~20x with minimal quality loss by dropping
low-information tokens (LLMLingua, EMNLP 2023, arXiv:2310.05736; LongLLMLingua,
arXiv:2310.06839).

This module implements the *deterministic, model-free* subset of that idea — the part
that is safe to run inside a governance gateway with no extra model and no network:

  * **Whitespace + boilerplate normalization** — collapse runs, strip trailing space
    (lossless).
  * **Cross-message deduplication** — a block of context pasted into several turns is
    kept once and referenced (near-lossless; removes exact repeats only).
  * **Budget windowing** — when a conversation exceeds a token budget, keep the system
    instructions and the most recent turns that fit, dropping the oldest middle (lossy,
    opt-in, and reported).

It is deliberately *not* the neural LLMLingua compressor (which needs a small LM to score
token perplexity) and it is *not* weight quantization. It is honest structural
compression with exact before/after token accounting, so the savings reported are real
and reproducible rather than asserted.

Default posture is **measure, don't mutate**: the gateway reports potential savings
without altering prompts unless a principal's policy explicitly opts in — silently
rewriting a caller's prompt is itself a trust boundary.

Sources:
  LLMLingua — https://arxiv.org/abs/2310.05736
  LongLLMLingua — https://arxiv.org/abs/2310.06839
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Rough token estimate: ~4 characters per token, matching the gateway's own accounting
# (english-text heuristic; good enough for savings ratios, not billing).
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, len(text) // _CHARS_PER_TOKEN)


def messages_tokens(messages: list[dict]) -> int:
    return sum(estimate_tokens(str(m.get("content", ""))) for m in messages)


# ------------------------------------------------------------------ normalization
_MANY_BLANKLINES = re.compile(r"\n{3,}")
_MANY_SPACES = re.compile(r"[ \t]{2,}")


def normalize_whitespace(text: str) -> str:
    """Lossless: collapse redundant spacing that costs tokens but carries no meaning.

    Trailing whitespace is stripped with ``str.rstrip`` rather than a regex: this runs
    on caller-supplied prompt text, and a backtracking pattern like ``[ \\t]+(\\n|$)``
    is quadratic on long tab runs (CodeQL py/polynomial-redos). ``rstrip`` is linear.
    """
    text = "\n".join(line.rstrip(" \t") for line in text.split("\n"))
    text = _MANY_SPACES.sub(" ", text)
    text = _MANY_BLANKLINES.sub("\n\n", text)
    return text.strip()


def _paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


# ------------------------------------------------------------------ result type
@dataclass
class CompressionResult:
    messages: list[dict]
    original_tokens: int
    compressed_tokens: int
    applied: bool
    steps: list[str] = field(default_factory=list)

    @property
    def saved_tokens(self) -> int:
        return max(0, self.original_tokens - self.compressed_tokens)

    @property
    def ratio(self) -> float:
        """Compression ratio original/compressed (1.0 = no change)."""
        if self.compressed_tokens <= 0:
            return 1.0
        return round(self.original_tokens / self.compressed_tokens, 3)

    @property
    def saved_pct(self) -> float:
        if self.original_tokens <= 0:
            return 0.0
        return round(100.0 * self.saved_tokens / self.original_tokens, 1)

    def to_dict(self) -> dict:
        return {
            "original_tokens": self.original_tokens,
            "compressed_tokens": self.compressed_tokens,
            "saved_tokens": self.saved_tokens,
            "saved_pct": self.saved_pct,
            "ratio": self.ratio,
            "applied": self.applied,
            "steps": self.steps,
        }


# ------------------------------------------------------------------ compression
def compress_messages(
    messages: list[dict],
    *,
    budget: int | None = None,
    dedupe: bool = True,
    apply: bool = True,
) -> CompressionResult:
    """Compress a chat message list deterministically.

    ``apply=False`` measures the achievable savings without returning rewritten
    messages (the safe, default gateway posture). ``budget`` triggers lossy windowing
    only when the conversation exceeds it.
    """
    original = messages_tokens(messages)
    steps: list[str] = []
    work = [dict(m) for m in messages]

    # 1. Whitespace normalization (lossless).
    before = messages_tokens(work)
    for m in work:
        m["content"] = normalize_whitespace(str(m.get("content", "")))
    if messages_tokens(work) < before:
        steps.append("whitespace-normalized")

    # 2. Cross-message paragraph dedup (near-lossless: exact repeats only). A paragraph
    #    seen verbatim in an earlier message is dropped from later ones.
    if dedupe:
        seen: set[str] = set()
        removed = 0
        for m in work:
            kept: list[str] = []
            for para in _paragraphs(str(m.get("content", ""))):
                key = para.strip()
                if key in seen and len(key) > 40:  # only dedupe substantial blocks
                    removed += 1
                    continue
                seen.add(key)
                kept.append(para)
            m["content"] = "\n\n".join(kept)
        if removed:
            steps.append(f"deduped-{removed}-repeated-blocks")

    # 3. Budget windowing (lossy, only if over budget). Keep all system messages and the
    #    most recent turns that fit; drop the oldest non-system middle.
    windowed = _apply_budget(work, budget, steps) if budget else work

    compressed = messages_tokens(windowed)
    return CompressionResult(
        messages=windowed if apply else messages,
        original_tokens=original,
        compressed_tokens=compressed if apply else compressed,
        applied=apply and compressed < original,
        steps=steps,
    )


def _apply_budget(messages: list[dict], budget: int, steps: list[str]) -> list[dict]:
    if messages_tokens(messages) <= budget:
        return messages
    system = [m for m in messages if m.get("role") == "system"]
    rest = [m for m in messages if m.get("role") != "system"]

    kept_rev: list[dict] = []
    used = messages_tokens(system)
    dropped = 0
    for m in reversed(rest):  # newest first
        cost = estimate_tokens(str(m.get("content", "")))
        if used + cost > budget and kept_rev:
            dropped += 1
            continue
        used += cost
        kept_rev.append(m)
    if dropped:
        steps.append(f"budget-windowed-dropped-{dropped}-old-turns")
    return system + list(reversed(kept_rev))
