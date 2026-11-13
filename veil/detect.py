"""PII/PHI detection: custom regex + Presidio (spaCy NER) + GLiNER, merged into one span list."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity_type: str
    text: str
    score: float
    source: str


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Span]: ...


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 13:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class RegexDetector:
    """Structured identifiers that NER models miss or mislabel (MRN, policy/account numbers, SSN...)."""

    name = "regex"
    PATTERNS: list[tuple[str, re.Pattern, float]] = [
        ("EMAIL_ADDRESS", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), 0.99),
        ("US_SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.95),
        ("CREDIT_CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), 0.9),
        ("PHONE_NUMBER", re.compile(
            r"(?<![\w-])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w-])"), 0.85),
        ("MEDICAL_RECORD_NUMBER", re.compile(
            r"\b(?:MRN|medical record(?: number| no\.?| #)?)[\s:#-]*([A-Z]{0,3}\d{5,10})\b", re.I), 0.95),
        ("POLICY_NUMBER", re.compile(
            r"\b(?:policy|member|insurance|claim)(?: id| number| no\.?| #)?[\s:#-]*([A-Z]{1,4}-?\d{6,12})\b", re.I), 0.9),
        ("ACCOUNT_NUMBER", re.compile(
            r"\b(?:account|acct|routing)(?: number| no\.?| #)?[\s:#-]*(\d{6,17})\b", re.I), 0.9),
        ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), 0.9),
        ("DATE_OF_BIRTH", re.compile(
            r"\b(?:DOB|date of birth|born(?: on)?)[\s:]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|"
            r"[A-Z][a-z]+ \d{1,2},? \d{4})\b", re.I), 0.95),
    ]

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for etype, pat, score in self.PATTERNS:
            for m in pat.finditer(text):
                g = 1 if m.groups() else 0
                start, end = m.start(g), m.end(g)
                value = text[start:end]
                if etype == "CREDIT_CARD" and not _luhn_ok(value):
                    continue
                spans.append(Span(start, end, etype, value, score, self.name))
        return spans


class PresidioDetector:
    name = "presidio"

    def __init__(self, spacy_model: str | None = None):
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = spacy_model or os.getenv("VEIL_SPACY_MODEL", "en_core_web_lg")
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": model}],
        })
        self.engine = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])

    def detect(self, text: str) -> list[Span]:
        out = []
        for r in self.engine.analyze(text=text, language="en"):
            etype = {"DATE_TIME": "DATE", "NRP": "NRP"}.get(r.entity_type, r.entity_type)
            out.append(Span(r.start, r.end, etype, text[r.start:r.end], float(r.score), self.name))
        return out


GLINER_LABELS = {
    "person": "PERSON",
    "email": "EMAIL_ADDRESS",
    "phone number": "PHONE_NUMBER",
    "address": "ADDRESS",
    "location": "LOCATION",
    "social security number": "US_SSN",
    "credit card number": "CREDIT_CARD",
    "date of birth": "DATE_OF_BIRTH",
    "medical record number": "MEDICAL_RECORD_NUMBER",
    "bank account number": "ACCOUNT_NUMBER",
    "insurance policy number": "POLICY_NUMBER",
    "driver's license number": "US_DRIVER_LICENSE",
    "passport number": "US_PASSPORT",
    "username": "USERNAME",
    "ip address": "IP_ADDRESS",
}


class GlinerDetector:
    name = "gliner"

    def __init__(self, model_name: str | None = None, threshold: float = 0.5):
        from gliner import GLiNER

        self.model = GLiNER.from_pretrained(model_name or os.getenv("VEIL_GLINER_MODEL", "urchade/gliner_multi_pii-v1"))
        self.threshold = threshold

    def detect(self, text: str) -> list[Span]:
        out = []
        # GLiNER has a ~384-token window; chunk long text on sentence-ish boundaries.
        for offset, chunk in _chunks(text, 1200):
            for e in self.model.predict_entities(chunk, list(GLINER_LABELS), threshold=self.threshold):
                s, t = offset + e["start"], offset + e["end"]
                out.append(Span(s, t, GLINER_LABELS[e["label"]], text[s:t], float(e["score"]), self.name))
        return out


def _chunks(text: str, size: int):
    i = 0
    while i < len(text):
        j = min(len(text), i + size)
        if j < len(text):
            k = text.rfind(" ", i, j)
            j = k if k > i else j
        yield i, text[i:j]
        i = j


# Structured types from regex are more precise than NER guesses; prefer them on overlap.
_TYPE_PRIORITY = {"regex": 3, "gliner": 2, "presidio": 1}


def merge_spans(spans: list[Span]) -> list[Span]:
    """Resolve overlaps: keep the longest span; break ties by source priority then score."""
    ordered = sorted(spans, key=lambda s: (-(s.end - s.start), -_TYPE_PRIORITY.get(s.source, 0), -s.score))
    kept: list[Span] = []
    for s in ordered:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


class CompositeDetector:
    def __init__(self, detectors: list[Detector]):
        self.detectors = detectors
        self.name = "+".join(d.name for d in detectors)

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for d in self.detectors:
            spans.extend(d.detect(text))
        return merge_spans(spans)


@lru_cache(maxsize=4)
def build_detector(names: str | None = None) -> CompositeDetector:
    names = names or os.getenv("VEIL_DETECTORS", "regex,presidio")
    registry = {"regex": RegexDetector, "presidio": PresidioDetector, "gliner": GlinerDetector}
    return CompositeDetector([registry[n.strip()]() for n in names.split(",") if n.strip()])
