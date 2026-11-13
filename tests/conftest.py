import os
import re

import pytest

os.environ.setdefault("VEIL_AUTOSTART", "0")

from veil.audit import AuditLog
from veil.detect import CompositeDetector, RegexDetector, Span
from veil.policy import Policy
from veil.pseudonym import Pseudonymizer
from veil.vault import Vault


class FakeNameDetector:
    """Stands in for spaCy/GLiNER in unit tests so they run offline and fast."""
    name = "presidio"
    NAMES = ["Priya Raman", "John Smith", "Smith", "Priya", "Boston"]

    def detect(self, text):
        out = []
        for n in self.NAMES:
            for m in re.finditer(rf"\b{re.escape(n)}\b", text):
                et = "LOCATION" if n == "Boston" else "PERSON"
                out.append(Span(m.start(), m.end(), et, n, 0.85, self.name))
        return out


@pytest.fixture
def pz(tmp_path):
    db = str(tmp_path / "t.db")
    det = CompositeDetector([RegexDetector(), FakeNameDetector()])
    return Pseudonymizer(det, Vault(db), Policy())


@pytest.fixture
def audit(tmp_path):
    return AuditLog(str(tmp_path / "a.db"))
