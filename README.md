# Veil

**Use any LLM on client data without leaking PII/PHI.**

Veil is an OpenAI-compatible proxy. Change one base URL and every prompt has names, SSNs, MRNs,
emails, phone numbers, account and policy numbers swapped for **consistent, realistic pseudonyms**
before it reaches the model. The answer comes back with the real values restored, including in
streamed responses. Every request lands in a tamper-evident audit log that records what was masked,
never the values themselves.

```
your app ──► Veil (detect → pseudonymize → vault) ──► any LLM (Groq, Gemini, OpenAI, Ollama)
         ◄── restore (streaming-safe)             ◄──
```

## Why pseudonyms instead of [REDACTED]

"John Smith" becomes "Mark Lee" everywhere in the conversation, and "Smith" alone becomes "Lee".
The model reasons over a coherent document, can write "Dear Mark", and Veil turns that back into
"Dear John". Redaction tags break both.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,mcp,eval,gliner]"
python -m spacy download en_core_web_lg
cp .env.example .env   # add a free Groq or Gemini key, or point at Ollama
set -a; source .env; set +a
uvicorn veil.gateway:app --port 8000
```

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")
client.chat.completions.create(model="llama-3.1-8b-instant",
    messages=[{"role": "user", "content": "Summarize: Patient John Smith, MRN 00482913, SSN 123-45-6789 ..."}])
```

The web UI at `/` has an **Ask Veil** helper on every screen. It answers through the same upstream model (Groq or Gemini via `VEIL_UPSTREAM_*`), so the API key stays on the server and the question is masked like any other request.

## How it works

| Piece | File | What it does |
|---|---|---|
| Detection | `veil/detect.py` | Custom regex (MRN, SSN, policy/account numbers, Luhn-checked cards) + Presidio/spaCy NER + GLiNER zero-shot PII model, merged by longest span and source priority |
| Pseudonyms | `veil/pseudonym.py` | Deterministic Faker values per session, collision-checked, with surname/first-name token consistency |
| Vault | `veil/vault.py` | Originals stored Fernet-encrypted, looked up by HMAC; per-session purge |
| Restore | `veil/restore.py` | Longest-match restore; streaming restorer holds back only text that could still become a pseudonym |
| Gateway | `veil/gateway.py` | `/v1/chat/completions` (streaming + non-streaming), `/v1/mask`, `/v1/unmask`, `/audit/verify` |
| Audit | `veil/audit.py` | SHA-256 hash chain; `verify()` pinpoints the first altered entry |
| Policy | `policy.yaml` | Which entity types to mask, allowlist, score threshold |
| MCP | `veil/mcp_server.py` | `mask_text`, `unmask_text`, `verify_audit_log` tools for Claude Desktop |

## Evals

```bash
python -m eval.detection_eval --n 1000 --detectors regex,presidio,gliner   # leak eval
python -m eval.utility_eval --n 40                                          # answer quality, raw vs. Veil
```

- **Leak eval** (`ai4privacy/pii-masking-400k`, English validation split): per-entity recall,
  residual leak rate (gold values left verbatim), precision, masking latency.
- **Utility eval**: same task sent raw and through Veil; an LLM judge sees the original document and
  both answers in random order and scores each.
- **CI gate**: GitHub Actions runs the unit tests and a 300-example leak eval, failing if recall or
  leak rate regresses more than 2 points against `eval/baseline.json`.

### Results

_Filled in from real runs only._

## MCP (Claude Desktop)

```json
{"mcpServers": {"veil": {"command": "/path/to/.venv/bin/veil-mcp", "env": {"VEIL_DB_PATH": "/path/to/veil.db"}}}}
```

## Limits

Detection is probabilistic: recall below 100% means some PII can get through, which is why the leak
rate is measured and gated rather than assumed. English only for now.
