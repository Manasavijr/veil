"""Swap pseudonyms in model output back to the real values, including in token-by-token streams."""
from __future__ import annotations

import re


def _clean(mapping: dict[str, str]) -> dict[str, str]:
    # Vault keys for name tokens are stored as "__tok__X"; the fake side is plain.
    return {fake: orig.removeprefix("__tok__") for fake, orig in mapping.items() if fake}


def restore(text: str, mapping: dict[str, str]) -> str:
    m = _clean(mapping)
    if not m:
        return text
    # Longest fakes first so "Mark Lee" wins over "Mark".
    pat = re.compile("|".join(re.escape(k) for k in sorted(m, key=len, reverse=True)))
    return pat.sub(lambda x: m[x.group(0)], text)


class StreamRestorer:
    """Buffers just enough of the stream to never emit half of a pseudonym.
    A pseudonym like "Mark Lee" can arrive as "Mar" + "k L" + "ee"; we hold back any tail
    that is still a prefix of some pseudonym and release it once it can't be one."""

    def __init__(self, mapping: dict[str, str]):
        self.mapping = _clean(mapping)
        self.buf = ""

    def feed(self, chunk: str) -> str:
        """Scan left to right with longest-match semantics (same as restore()). Stop at the first
        position where the rest of the buffer could still grow into a longer pseudonym."""
        self.buf += chunk  # raw (still pseudonymized) text
        out, i, buf = [], 0, self.buf
        while i < len(buf):
            rest = buf[i:]
            if any(len(f) > len(rest) and f.startswith(rest) for f in self.mapping):
                break  # undecided: wait for more tokens
            full = max((f for f in self.mapping if rest.startswith(f)), key=len, default=None)
            if full:
                out.append(self.mapping[full])
                i += len(full)
            else:
                out.append(buf[i])
                i += 1
        self.buf = buf[i:]
        return "".join(out)

    def flush(self) -> str:
        out, self.buf = restore(self.buf, self.mapping), ""
        return out
