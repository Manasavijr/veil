"""Utility eval: does masking hurt answer quality?

For each document we ask the same task twice: straight to the LLM (raw) and through Veil
(masked going in, restored coming out). A judge model sees the ORIGINAL document and both answers
in random order and scores each 1-10, plus a preference.

  # terminal 1: uvicorn veil.gateway:app --port 8000
  python -m eval.utility_eval --n 40 --veil http://localhost:8000/v1
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import time
from pathlib import Path

import httpx

from .data import load_examples

TASKS = [
    "Summarize this message in 2 sentences, keeping who is involved and what they need.",
    "Draft a short, polite reply to this message addressed to the sender by name.",
    "Extract every action item as a bullet list, including names, dates and contact details mentioned.",
]

JUDGE = """You are grading two answers to the same task about a document.

DOCUMENT:
{doc}

TASK: {task}

ANSWER A:
{a}

ANSWER B:
{b}

Score each answer 1-10 for correctness and faithfulness to the document (names, numbers and details must match the document exactly) and for usefulness. Reply with JSON only: {{"score_a": int, "score_b": int, "better": "A" | "B" | "tie"}}"""


def chat(base: str, key: str, model: str, prompt: str, session: str | None = None, retries: int = 5) -> str:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    if session:
        headers["X-Veil-Session"] = session
    for attempt in range(retries):
        r = httpx.post(f"{base.rstrip('/')}/chat/completions", headers=headers, timeout=120, json={
            "model": model, "temperature": 0, "messages": [{"role": "user", "content": prompt}]})
        if r.status_code == 429:
            time.sleep(2 ** attempt * 3)
            continue
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    raise RuntimeError("rate limited")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--veil", default="http://localhost:8000/v1")
    ap.add_argument("--upstream", default=os.getenv("VEIL_UPSTREAM_BASE_URL"))
    ap.add_argument("--model", default=os.getenv("VEIL_MODEL", "llama-3.1-8b-instant"))
    ap.add_argument("--judge-model", default=os.getenv("VEIL_JUDGE_MODEL", os.getenv("VEIL_MODEL", "llama-3.3-70b-versatile")))
    ap.add_argument("--sleep", type=float, default=2.0, help="seconds between calls (free-tier rate limits)")
    a = ap.parse_args()
    key = os.getenv("VEIL_UPSTREAM_API_KEY", "")
    rng = random.Random(7)
    docs = [d for d in load_examples(a.n * 3, split="validation") if len(d["text"]) > 200][: a.n]
    rows = []
    for i, d in enumerate(docs):
        task = TASKS[i % len(TASKS)]
        prompt = f"{task}\n\n---\n{d['text']}"
        raw = chat(a.upstream, key, a.model, prompt); time.sleep(a.sleep)
        veiled = chat(a.veil, "", a.model, prompt, session=f"util-{i}"); time.sleep(a.sleep)
        flip = rng.random() < 0.5
        A, B = (veiled, raw) if flip else (raw, veiled)
        verdict = chat(a.upstream, key, a.judge_model, JUDGE.format(doc=d["text"], task=task, a=A, b=B)); time.sleep(a.sleep)
        m = re.search(r"\{.*\}", verdict, re.S)
        v = json.loads(m.group(0)) if m else {}
        s_raw, s_veil = (v.get("score_b"), v.get("score_a")) if flip else (v.get("score_a"), v.get("score_b"))
        better = {"A": "veil" if flip else "raw", "B": "raw" if flip else "veil"}.get(v.get("better"), "tie")
        rows.append({"i": i, "task": task, "raw": raw, "veil": veiled, "score_raw": s_raw, "score_veil": s_veil, "better": better})
        print(f"[{i + 1}/{len(docs)}] raw={s_raw} veil={s_veil} better={better}")
    ok = [r for r in rows if isinstance(r["score_raw"], (int, float)) and isinstance(r["score_veil"], (int, float))]
    summary = {
        "examples": len(rows), "judged": len(ok), "model": a.model, "judge_model": a.judge_model,
        "mean_score_raw": statistics.mean(r["score_raw"] for r in ok) if ok else None,
        "mean_score_veil": statistics.mean(r["score_veil"] for r in ok) if ok else None,
        "veil_wins": sum(r["better"] == "veil" for r in rows),
        "raw_wins": sum(r["better"] == "raw" for r in rows),
        "ties": sum(r["better"] == "tie" for r in rows),
    }
    out = Path("eval/results")
    out.mkdir(parents=True, exist_ok=True)
    (out / "utility_rows.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    (out / "utility_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
