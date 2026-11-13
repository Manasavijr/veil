"""Load English examples from the open ai4privacy PII dataset (Hugging Face)."""
from __future__ import annotations

import json

DATASET = "ai4privacy/pii-masking-400k"


def load_examples(n: int = 1000, split: str = "validation", seed: int = 7) -> list[dict]:
    from datasets import load_dataset

    ds = load_dataset(DATASET, split=split)
    if "language" in ds.column_names:
        ds = ds.filter(lambda r: r["language"] == "en")
    ds = ds.shuffle(seed=seed).select(range(min(n, len(ds))))
    out = []
    for r in ds:
        mask = r["privacy_mask"]
        if isinstance(mask, str):
            mask = json.loads(mask)
        spans = [{"start": int(m["start"]), "end": int(m["end"]), "label": m["label"], "value": m["value"]}
                 for m in mask]
        out.append({"id": r.get("id", len(out)), "text": r["source_text"], "spans": spans})
    return out
