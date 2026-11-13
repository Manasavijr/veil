"""Leak eval: per-entity recall and residual leaks on ai4privacy.

  python -m eval.detection_eval --n 1000 --detectors regex,presidio,gliner
  python -m eval.detection_eval --n 300 --gate eval/baseline.json   # CI mode

A gold span counts as caught when >=90% of its characters fall inside masked spans.
A residual leak is a gold value that still appears verbatim in the masked text.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path

from veil.detect import build_detector
from veil.policy import Policy
from veil.pseudonym import Pseudonymizer
from veil.vault import Vault

from .data import load_examples

# Labels in ai4privacy that are not identifying on their own; reported but excluded from the headline.
NON_IDENTIFYING = {"AGE", "GENDER", "SEX", "TIME", "TITLE", "PREFIX"}


def run(n: int, detectors: str, split: str) -> dict:
    det = build_detector(detectors)
    pz = Pseudonymizer(det, Vault(":memory:"), Policy(min_score=0.0, mask=_all_types()))
    data = load_examples(n, split=split)
    caught, total = defaultdict(int), defaultdict(int)
    leaks, pred_spans, pred_hits, lat = 0, 0, 0, []
    examples_with_leak = 0
    for i, ex in enumerate(data):
        t0 = time.perf_counter()
        masked, reps = pz.mask(f"eval-{i}", ex["text"])
        lat.append((time.perf_counter() - t0) * 1000)
        covered = [False] * len(ex["text"])
        for r in reps:
            for k in range(r.start, r.end):
                covered[k] = True
        leaked_here = False
        for g in ex["spans"]:
            if g["label"] in NON_IDENTIFYING:
                continue
            total[g["label"]] += 1
            length = max(1, g["end"] - g["start"])
            if sum(covered[g["start"]:g["end"]]) / length >= 0.9:
                caught[g["label"]] += 1
            if len(g["value"]) >= 3 and g["value"] in masked:
                leaks += 1
                leaked_here = True
        examples_with_leak += leaked_here
        for r in reps:
            pred_spans += 1
            if any(r.start < g["end"] and g["start"] < r.end for g in ex["spans"]):
                pred_hits += 1
    n_gold = sum(total.values())
    return {
        "dataset": "ai4privacy/pii-masking-400k", "split": split, "examples": len(data), "detectors": detectors,
        "recall_overall": sum(caught.values()) / max(1, n_gold),
        "residual_leak_rate": leaks / max(1, n_gold),
        "examples_with_any_leak": examples_with_leak / max(1, len(data)),
        "precision_overlap": pred_hits / max(1, pred_spans),
        "latency_ms_p50": statistics.median(lat) if lat else None,
        "latency_ms_p95": statistics.quantiles(lat, n=20)[18] if len(lat) >= 20 else None,
        "per_label": {lab: {"recall": caught[lab] / total[lab], "support": total[lab]}
                      for lab in sorted(total, key=lambda k: -total[k])},
    }


def _all_types() -> set[str]:
    from veil.detect import GLINER_LABELS, RegexDetector
    return set(GLINER_LABELS.values()) | {p[0] for p in RegexDetector.PATTERNS} | {
        "DATE", "NRP", "URL", "IBAN_CODE", "US_BANK_NUMBER", "US_ITIN", "MEDICAL_LICENSE", "CRYPTO"}


def to_markdown(r: dict) -> str:
    lines = [f"**{r['detectors']}** on {r['examples']} {r['dataset']} ({r['split']}) examples", "",
             f"- Overall recall: {r['recall_overall']:.1%}",
             f"- Residual leak rate (gold values left verbatim): {r['residual_leak_rate']:.1%}",
             f"- Examples with any leak: {r['examples_with_any_leak']:.1%}",
             f"- Precision (masked spans overlapping gold): {r['precision_overlap']:.1%}",
             f"- Masking latency p50/p95: {r['latency_ms_p50']:.1f} / {r['latency_ms_p95'] or float('nan'):.1f} ms",
             "", "| Entity | Recall | Support |", "|---|---|---|"]
    lines += [f"| {k} | {v['recall']:.1%} | {v['support']} |" for k, v in r["per_label"].items()]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--split", default="validation")
    ap.add_argument("--detectors", default="regex,presidio")
    ap.add_argument("--gate", help="baseline JSON; fail if recall drops >2pts or leak rate rises >2pts")
    ap.add_argument("--out", default="eval/results")
    a = ap.parse_args()
    r = run(a.n, a.detectors, a.split)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tag = a.detectors.replace(",", "+")
    (out / f"detection_{tag}.json").write_text(json.dumps(r, indent=2))
    (out / f"detection_{tag}.md").write_text(to_markdown(r))
    print(to_markdown(r))
    if a.gate:
        base = json.loads(Path(a.gate).read_text())
        fails = []
        if r["recall_overall"] < base["recall_overall"] - 0.02:
            fails.append(f"recall {r['recall_overall']:.3f} < baseline {base['recall_overall']:.3f} - 0.02")
        if r["residual_leak_rate"] > base["residual_leak_rate"] + 0.02:
            fails.append(f"leak {r['residual_leak_rate']:.3f} > baseline {base['residual_leak_rate']:.3f} + 0.02")
        if fails:
            raise SystemExit("EVAL GATE FAILED: " + "; ".join(fails))
        print("Eval gate passed.")


if __name__ == "__main__":
    main()
