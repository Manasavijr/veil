from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_MASK = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IBAN_CODE",
    "IP_ADDRESS", "LOCATION", "ADDRESS", "DATE_OF_BIRTH", "MEDICAL_RECORD_NUMBER",
    "ACCOUNT_NUMBER", "POLICY_NUMBER", "US_DRIVER_LICENSE", "US_PASSPORT", "USERNAME",
]


@dataclass
class Policy:
    mask: set[str] = field(default_factory=lambda: set(DEFAULT_MASK))
    allow: set[str] = field(default_factory=set)
    min_score: float = 0.5

    def should_mask(self, entity_type: str, text: str, score: float) -> bool:
        if score < self.min_score:
            return False
        if text.strip().lower() in {a.lower() for a in self.allow}:
            return False
        return entity_type in self.mask

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Policy":
        path = path or os.getenv("VEIL_POLICY", "policy.yaml")
        p = Path(path)
        if not p.exists():
            return cls()
        data = yaml.safe_load(p.read_text()) or {}
        return cls(
            mask=set(data.get("mask", DEFAULT_MASK)),
            allow=set(data.get("allow", [])),
            min_score=float(data.get("min_score", 0.5)),
        )
