"""Consistent pseudonyms: the same real value always maps to the same realistic fake within a session,
so the LLM sees a coherent document and its answer can be restored exactly."""
from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass

from faker import Faker

from .detect import CompositeDetector, Span
from .policy import Policy
from .vault import Vault


@dataclass
class Replacement:
    entity_type: str
    start: int
    end: int
    fake: str
    source: str
    original: str = ""
    mstart: int = 0  # position of the pseudonym in the masked text
    mend: int = 0


def _seed(session: str, original: str, attempt: int) -> int:
    return int.from_bytes(hashlib.sha256(f"{session}|{original}|{attempt}".encode()).digest()[:8], "big")


def _generate(fk: Faker, etype: str, original: str) -> str:
    if etype == "PERSON":
        n = len(original.split())
        if n == 1:
            return fk.first_name()
        return " ".join([fk.first_name() for _ in range(n - 1)] + [fk.last_name()])
    gen = {
        "EMAIL_ADDRESS": fk.email,
        "PHONE_NUMBER": lambda: fk.numerify("(###) 555-####"),
        "US_SSN": lambda: fk.numerify("9##-##-####"),  # 9xx area numbers are never issued
        "CREDIT_CARD": lambda: fk.credit_card_number(card_type="visa16"),
        "IBAN_CODE": fk.iban,
        "IP_ADDRESS": fk.ipv4_private,
        "LOCATION": fk.city,
        "ADDRESS": fk.street_address,
        "DATE_OF_BIRTH": lambda: fk.date_of_birth(minimum_age=18, maximum_age=90).strftime("%m/%d/%Y"),
        "DATE": lambda: fk.date_this_decade().strftime("%B %d, %Y"),
        "MEDICAL_RECORD_NUMBER": lambda: fk.numerify("MR########"),
        "ACCOUNT_NUMBER": lambda: fk.numerify("##########"),
        "POLICY_NUMBER": lambda: fk.bothify("??-#########").upper(),
        "US_DRIVER_LICENSE": lambda: fk.bothify("?#######").upper(),
        "US_PASSPORT": lambda: fk.numerify("#########"),
        "USERNAME": fk.user_name,
    }.get(etype)
    return gen() if gen else f"[{etype}_{fk.numerify('####')}]"


class Pseudonymizer:
    def __init__(self, detector: CompositeDetector, vault: Vault, policy: Policy | None = None):
        self.detector = detector
        self.vault = vault
        self.policy = policy or Policy()

    def _fake_for(self, session: str, etype: str, original: str) -> str:
        existing = self.vault.get_fake(session, original)
        if existing:
            return existing
        # Partial name consistency: "Smith" after "John Smith" -> the same fake surname.
        if etype == "PERSON" and len(original.split()) == 1:
            token_fake = self.vault.get_fake(session, f"__tok__{original}")
            if token_fake:
                self.vault.put(session, etype, original, token_fake)
                return token_fake
        for attempt in range(50):
            fk = Faker("en_US")
            fk.seed_instance(_seed(session, original, attempt))
            fake = _generate(fk, etype, original)
            if fake != original and not self.vault.fake_taken(session, fake):
                break
        self.vault.put(session, etype, original, fake)
        if etype == "PERSON":
            for o_tok, f_tok in zip(original.split(), fake.split()):
                if not self.vault.get_fake(session, f"__tok__{o_tok}"):
                    self.vault.put(session, etype, f"__tok__{o_tok}", f_tok)
        return fake

    def mask(self, session: str, text: str) -> tuple[str, list[Replacement]]:
        spans: list[Span] = [
            s for s in self.detector.detect(text) if self.policy.should_mask(s.entity_type, s.text, s.score)
        ]
        out, reps, cursor, mpos = [], [], 0, 0
        for s in spans:
            fake = self._fake_for(session, s.entity_type, s.text)
            gap = text[cursor:s.start]
            out.append(gap)
            mpos += len(gap)
            reps.append(Replacement(s.entity_type, s.start, s.end, fake, s.source, s.text, mpos, mpos + len(fake)))
            out.append(fake)
            mpos += len(fake)
            cursor = s.end
        out.append(text[cursor:])
        return "".join(out), reps

    def restore_map(self, session: str) -> dict[str, str]:
        return {f: o for f, o in self.vault.reverse_map(session).items()}


def summarize(reps: list[Replacement]) -> dict[str, int]:
    return dict(Counter(r.entity_type for r in reps))
