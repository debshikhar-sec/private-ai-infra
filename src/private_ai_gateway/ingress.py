"""Ingress AI-firewall: prompt-injection, jailbreak, and PII detection on the way in.

The egress guardrail (:mod:`private_ai_gateway.guardrails`) stops secrets leaving; this
is its mirror on the *inbound* side — a heuristic detector for the attacks that ride in
on a prompt. It is scoped to OWASP's LLM01:2025 *Prompt Injection* (direct jailbreaks and
instruction-override attempts) plus inbound PII, and it is deliberately **heuristic, not a
model**: transparent rules with stable ids, so a decision is explainable and auditable
rather than a black-box score. That honesty matters — a detector you cannot explain is one
a security reviewer cannot trust.

What makes it more than a keyword blocklist is the **normalization pass**. Real injection
payloads hide the trigger words from naive filters using Unicode: homoglyphs (Cyrillic
'о' for ASCII 'o'), zero-width joiners, combining diacritics, full-width forms, and
Unicode "tag" characters that are invisible but still tokenize. The scanner first folds
the text (NFKC, strip invisible/zero-width, drop tag characters, map a curated set of
confusables back to ASCII) and matches its rules on the *normalized* form — so "?gn0re
previous instructions" written with a homoglyph and a zero-width space is still caught,
and the evasion attempt itself becomes a signal that raises severity.

References:
  OWASP LLM01:2025 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
  Unicode UTS #39 (confusables / security) — https://www.unicode.org/reports/tr39/
  Character-level evasion taxonomy — arXiv:2504.11168
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


# ---------------------------------------------------------------- normalization
# A curated subset of the Unicode confusables (UTS #39): the lookalikes actually used to
# smuggle ASCII trigger words past filters. Not the full table — the high-signal ones.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "к": "k", "н": "h", "м": "m", "т": "t",
    "в": "b", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X",
    # Greek -> Latin
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    # Common symbol substitutions used in leetspeak-lite evasion
    "０": "0", "１": "1",
}

# Unicode invisibles/zero-width used purely to break up trigger words. Written as
# escapes (not literals) so this source file itself contains no invisible characters.
_ZERO_WIDTH = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space / BOM
    "᠎",  # mongolian vowel separator
    "­",  # soft hyphen
}
# Bidi controls that can visually reorder text to disguise intent — written as \u escapes
# so this file does not itself contain bidi controls (the very TrojanSource attack these
# detect, and which a SAST scanner would otherwise flag here).
_BIDI = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # LRE RLE PDF LRO RLO
    "\u2066", "\u2067", "\u2068", "\u2069",             # LRI RLI FSI PDI
}


def _is_tag_char(ch: str) -> bool:
    # Unicode "tag" block (U+E0000–U+E007F): invisible, historically used for smuggling.
    return 0xE0000 <= ord(ch) <= 0xE007F


@dataclass
class Normalized:
    text: str
    evasions: list[str] = field(default_factory=list)


def normalize(text: str) -> Normalized:
    """Fold a string toward canonical ASCII, recording which evasions were present."""
    evasions: list[str] = []

    if any(ch in _ZERO_WIDTH for ch in text):
        evasions.append("zero-width-characters")
    if any(ch in _BIDI for ch in text):
        evasions.append("bidi-control-characters")
    if any(_is_tag_char(ch) for ch in text):
        evasions.append("unicode-tag-smuggling")
    if any(ch in _CONFUSABLES for ch in text):
        evasions.append("homoglyph-substitution")

    out_chars: list[str] = []
    for ch in text:
        if ch in _ZERO_WIDTH or ch in _BIDI or _is_tag_char(ch):
            continue
        out_chars.append(_CONFUSABLES.get(ch, ch))
    folded = "".join(out_chars)

    # NFKC folds full-width/compatibility forms (e.g. 'ｉｇｎｏｒｅ' -> 'ignore') and
    # strips many combining marks after decomposition.
    nfkc = unicodedata.normalize("NFKC", folded)
    if nfkc != folded and "full-width-or-compatibility-forms" not in evasions:
        # Detect the specific full-width case for a clearer signal.
        if any(0xFF00 <= ord(c) <= 0xFFEF for c in folded):
            evasions.append("full-width-forms")

    # Drop leftover combining marks (diacritic-stuffing evasion).
    stripped = "".join(c for c in unicodedata.normalize("NFKD", nfkc)
                       if not unicodedata.combining(c))
    if stripped != nfkc and unicodedata.normalize("NFKC", stripped) != nfkc:
        evasions.append("combining-diacritics")

    return Normalized(text=stripped, evasions=sorted(set(evasions)))


# ---------------------------------------------------------------- detection rules
@dataclass(frozen=True)
class Rule:
    id: str
    category: str        # OWASP LLM01 sub-category or "pii"
    severity: str
    pattern: re.Pattern
    description: str
    validator: str = ""  # optional named post-check (e.g. luhn) for PII precision


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Injection / jailbreak rules operate on NORMALIZED text (so evasions are already folded).
_INJECTION_RULES: tuple[Rule, ...] = (
    Rule("PI-OVERRIDE-01", "direct-injection", "high",
         _rx(r"\bignore\s+(all\s+|any\s+)?(previous|prior|earlier|above)\s+"
             r"(instructions?|prompts?|rules?|directions?)"),
         "Instruction-override: asks the model to ignore prior instructions."),
    Rule("PI-OVERRIDE-02", "direct-injection", "high",
         _rx(r"\b(disregard|forget|discard)\s+(everything|all|the|your|previous|prior)"),
         "Instruction-override: asks the model to discard its instructions/context."),
    Rule("PI-ROLE-01", "jailbreak", "high",
         _rx(r"\byou\s+are\s+now\s+(a|an|in|no longer)\b|\bpretend\s+(you\s+are|to\s+be)"),
         "Role reassignment: attempts to redefine the assistant's identity/role."),
    Rule("PI-ROLE-02", "jailbreak", "critical",
         _rx(r"\b(developer\s+mode|dan\s+mode|do\s+anything\s+now|jailbreak|"
             r"unrestricted\s+mode)\b"),
         "Named jailbreak: invokes a known unrestricted-mode persona."),
    Rule("PI-SYSTEM-01", "system-prompt-leak", "high",
         _rx(r"\b(reveal|show|print|repeat|display|output)\s+(me\s+)?(your\s+)?"
             r"(system\s+prompt|initial\s+instructions?|the\s+prompt\s+above|"
             r"your\s+instructions?|everything\s+above)"),
         "System-prompt exfiltration: asks the model to reveal hidden instructions."),
    Rule("PI-SYSTEM-02", "system-prompt-leak", "medium",
         _rx(r"\brepeat\s+(the\s+)?(words?|text|everything)\s+above\b|"
             r"\bwhat\s+(were|are)\s+your\s+(original\s+)?instructions?\b"),
         "System-prompt exfiltration (indirect phrasing)."),
    Rule("PI-DELIM-01", "structured-injection", "medium",
         _rx(r"</?(system|assistant|user|im_start|im_end)>|\[/?(inst|sys)\]|"
             r"<\|.*?\|>"),
         "Delimiter injection: forges chat/role delimiters to break framing."),
    Rule("PI-OVERRIDE-03", "direct-injection", "medium",
         _rx(r"\bnew\s+(instructions?|rules?|task)\s*:|\bfrom\s+now\s+on\s+you\b|"
             r"\bfor\s+the\s+rest\s+of\s+(this|the)\s+conversation\b"),
         "Context reset: attempts to install new governing rules mid-conversation."),
)

# PII rules operate on the ORIGINAL text (normalization could mangle real values).
_PII_RULES: tuple[Rule, ...] = (
    Rule("PII-EMAIL-01", "pii", "low",
         _rx(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
         "Email address present in the prompt."),
    Rule("PII-SSN-01", "pii", "high",
         _rx(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
         "US SSN-shaped value present in the prompt."),
    Rule("PII-CARD-01", "pii", "high",
         _rx(r"\b(?:\d[ -]?){13,19}\b"),
         "Payment-card-shaped digit run present in the prompt.", validator="luhn"),
    Rule("PII-IBAN-01", "pii", "medium",
         _rx(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
         "IBAN-shaped value present in the prompt."),
)


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, d in enumerate(nums):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------- result
@dataclass(frozen=True)
class Detection:
    rule_id: str
    category: str
    severity: str
    description: str
    match: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "match": self.match,
        }


@dataclass
class IngressResult:
    detections: list[Detection]
    evasions: list[str]
    normalized_text: str
    action: str = "flag"  # off | flag | block

    @property
    def triggered(self) -> bool:
        return bool(self.detections)

    @property
    def max_severity(self) -> str:
        if not self.detections:
            return "none"
        return max((d.severity for d in self.detections), key=severity_rank)

    @property
    def categories(self) -> list[str]:
        return sorted({d.category for d in self.detections})

    def to_dict(self) -> dict:
        return {
            "triggered": self.triggered,
            "action": self.action,
            "max_severity": self.max_severity,
            "categories": self.categories,
            "evasions": self.evasions,
            "detections": [d.to_dict() for d in self.detections],
        }


_VALID_ACTIONS = ("off", "flag", "block")


class IngressFirewall:
    """Scan inbound prompt text for injection/jailbreak and PII, evasion-aware."""

    def __init__(self, action: str = "flag", *, block_threshold: str = "high"):
        self.action = action if action in _VALID_ACTIONS else "flag"
        self.block_threshold = block_threshold

    def scan(self, text: str) -> IngressResult:
        if self.action == "off" or not text:
            return IngressResult([], [], text or "", action="off")

        norm = normalize(text)
        detections: list[Detection] = []

        # Injection/jailbreak: match on normalized text so evasions are already folded.
        for rule in _INJECTION_RULES:
            m = rule.pattern.search(norm.text)
            if m:
                sev = rule.severity
                # An evasion attempt around an injection is itself aggravating.
                if norm.evasions and severity_rank(sev) < severity_rank("critical"):
                    sev = SEVERITY_ORDER[severity_rank(sev) + 1]
                detections.append(
                    Detection(rule.id, rule.category, sev, rule.description,
                              m.group(0)[:80])
                )

        # PII: match on the ORIGINAL text (normalization could corrupt real values).
        for rule in _PII_RULES:
            for m in rule.pattern.finditer(text):
                if rule.validator == "luhn" and not _luhn_ok(m.group(0)):
                    continue
                detections.append(
                    Detection(rule.id, rule.category, rule.severity, rule.description,
                              _mask(m.group(0)))
                )

        return IngressResult(
            detections=detections,
            evasions=norm.evasions,
            normalized_text=norm.text,
            action=self.action,
        )

    def should_block(self, result: IngressResult) -> bool:
        return (
            self.action == "block"
            and result.triggered
            and severity_rank(result.max_severity) >= severity_rank(self.block_threshold)
        )


def _mask(value: str) -> str:
    """Redact a matched PII value so the finding is auditable without re-leaking it."""
    digits = [c for c in value if c.isalnum()]
    if len(digits) <= 4:
        return "*" * len(value)
    return f"{value[:2]}…{value[-2:]} ({len(digits)} chars)"
