import json

import httpx
from fastapi.testclient import TestClient

from veil.gateway import create_app

SECRET = "John Smith, SSN 123-45-6789, email jsmith@gmail.com"


def make_upstream(seen: list):
    """Fake LLM: records what it received and echoes the user message back."""
    def handler(request: httpx.Request):
        body = json.loads(request.content)
        seen.append(body)
        text = "You said: " + body["messages"][-1]["content"]
        if body.get("stream"):
            chunks = [text[i:i + 3] for i in range(0, len(text), 3)]
            sse = "".join(
                "data: " + json.dumps({"id": "x", "object": "chat.completion.chunk",
                                       "choices": [{"index": 0, "delta": {"content": c}}]}) + "\n\n"
                for c in chunks) + "data: [DONE]\n\n"
            return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"id": "x", "object": "chat.completion",
                                         "choices": [{"index": 0, "message": {"role": "assistant", "content": text}}]})
    return httpx.MockTransport(handler)


def client(pz, audit, seen):
    app = create_app("http://upstream/v1", "k", pz, audit, transport=make_upstream(seen))
    return TestClient(app)


def test_upstream_never_sees_pii_and_answer_is_restored(pz, audit):
    seen = []
    c = client(pz, audit, seen)
    r = c.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": SECRET}]})
    sent = json.dumps(seen[0])
    for s in ["John Smith", "123-45-6789", "jsmith@gmail.com"]:
        assert s not in sent
    assert r.json()["choices"][0]["message"]["content"] == "You said: " + SECRET


def test_streaming_restore(pz, audit):
    seen = []
    c = client(pz, audit, seen)
    with c.stream("POST", "/v1/chat/completions",
                  json={"model": "m", "stream": True, "messages": [{"role": "user", "content": SECRET}]}) as r:
        text = ""
        for line in r.iter_lines():
            if line.startswith("data:") and "[DONE]" not in line:
                d = json.loads(line[5:])
                text += d["choices"][0]["delta"].get("content", "")
    assert text == "You said: " + SECRET
    assert "123-45-6789" not in json.dumps(seen[0])


def test_same_chat_keeps_same_pseudonyms_across_turns(pz, audit):
    seen = []
    c = client(pz, audit, seen)
    msgs = [{"role": "user", "content": SECRET}]
    c.post("/v1/chat/completions", json={"model": "m", "messages": msgs})
    msgs += [{"role": "assistant", "content": "ok"}, {"role": "user", "content": "What is John Smith's email?"}]
    c.post("/v1/chat/completions", json={"model": "m", "messages": msgs})
    fake_name_turn1 = seen[0]["messages"][0]["content"].split(",")[0]
    assert fake_name_turn1 in seen[1]["messages"][2]["content"]


def test_audit_logged_without_raw_values(pz, audit):
    c = client(pz, audit, [])
    c.post("/v1/chat/completions", json={"model": "m", "messages": [{"role": "user", "content": SECRET}]})
    v = c.get("/audit/verify").json()
    assert v["ok"] and v["entries"] == 1
    tail = json.dumps(c.get("/audit/tail").json())
    assert "123-45-6789" not in tail and "US_SSN" in tail
