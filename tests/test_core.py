import sqlite3

from veil.detect import RegexDetector, merge_spans, Span
from veil.restore import StreamRestorer, restore

NOTE = ("Patient John Smith (DOB 04/12/1987, MRN 00482913) called from 213-555-0147 about claim "
        "policy HX-48291034. Email jsmith@gmail.com, SSN 123-45-6789. Smith lives in Boston.")


def test_regex_finds_structured_ids():
    types = {s.entity_type: s.text for s in RegexDetector().detect(NOTE)}
    assert types["MEDICAL_RECORD_NUMBER"] == "00482913"
    assert types["US_SSN"] == "123-45-6789"
    assert types["EMAIL_ADDRESS"] == "jsmith@gmail.com"
    assert types["DATE_OF_BIRTH"] == "04/12/1987"
    assert types["POLICY_NUMBER"] == "HX-48291034"
    assert "213-555-0147" in types["PHONE_NUMBER"]


def test_credit_card_requires_luhn():
    d = RegexDetector()
    assert any(s.entity_type == "CREDIT_CARD" for s in d.detect("card 4111 1111 1111 1111"))
    assert not any(s.entity_type == "CREDIT_CARD" for s in d.detect("order 1234 5678 9012 3456"))


def test_merge_prefers_longest():
    a = Span(0, 10, "PERSON", "x" * 10, 0.8, "presidio")
    b = Span(0, 4, "PERSON", "xxxx", 0.9, "gliner")
    assert merge_spans([a, b]) == [a]


def test_no_pii_survives_masking(pz):
    masked, reps = pz.mask("s1", NOTE)
    for secret in ["John Smith", "00482913", "213-555-0147", "HX-48291034", "jsmith@gmail.com",
                   "123-45-6789", "04/12/1987", "Boston"]:
        assert secret not in masked, secret
    assert len(reps) >= 9


def test_pseudonyms_are_consistent(pz):
    m1, _ = pz.mask("s1", "John Smith emailed. Later John Smith called.")
    fakes = [w for w in m1.split(".")]
    a, _ = pz.mask("s1", "John Smith")
    b, _ = pz.mask("s1", "John Smith")
    assert a == b and a != "John Smith"
    assert m1.count(a) == 2


def test_surname_alone_reuses_fake_surname(pz):
    full, _ = pz.mask("s1", "John Smith")
    last, _ = pz.mask("s1", "Smith")
    assert last == full.split()[-1]


def test_sessions_get_different_pseudonyms(pz):
    a, _ = pz.mask("s1", "John Smith")
    b, _ = pz.mask("s2", "John Smith")
    assert a != b


def test_round_trip_restore(pz):
    masked, _ = pz.mask("s1", NOTE)
    assert restore(masked, pz.restore_map("s1")) == NOTE


def test_stream_restore_across_chunk_boundaries(pz):
    masked, _ = pz.mask("s1", NOTE)
    rs = StreamRestorer(pz.restore_map("s1"))
    for size in (1, 2, 3, 7):
        rs = StreamRestorer(pz.restore_map("s1"))
        out = "".join(rs.feed(masked[i:i + size]) for i in range(0, len(masked), size)) + rs.flush()
        assert out == NOTE, size


def test_vault_stores_ciphertext_only(pz, tmp_path):
    pz.mask("s1", NOTE)
    raw = sqlite3.connect(pz.vault.path).execute("SELECT original_enc FROM tokens").fetchall()
    blob = b"".join(r[0] for r in raw)
    assert b"123-45-6789" not in blob and b"John Smith" not in blob


def test_audit_chain_detects_tampering(audit):
    for i in range(5):
        audit.append({"event": "chat", "i": i})
    assert audit.verify() == {"ok": True, "entries": 5, "head": audit.verify()["head"]}
    audit.db.execute("UPDATE audit SET event='{\"event\":\"chat\",\"i\":99}' WHERE id=3")
    audit.db.commit()
    v = audit.verify()
    assert v["ok"] is False and v["broken_at_id"] == 3


def test_allowlist(pz):
    pz.policy.allow.add("Boston")
    masked, _ = pz.mask("s1", "Meet in Boston")
    assert "Boston" in masked
