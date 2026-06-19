"""Example 14 — Sanitize a document for safe RAG / LLM ingestion (0.5.0).

Instead of just blocking a risky document, produce a *cleaned copy* that is
safe to feed into a vector store / LLM pipeline: hidden text removed,
dangerous metadata emptied, active content stripped — visible content kept.

Usage:
    PYTHONPATH=src python examples/14_sanitize_for_rag.py path/to/document.docx
"""
from __future__ import annotations

import os
import sys

from doc_firewall import Scanner
from doc_firewall.enums import Verdict


def main(path: str) -> int:
    scanner = Scanner()

    before = scanner.scan(path)
    print(f"original verdict: {before.verdict.value}  (risk {before.risk_score:.2f})")

    result = scanner.sanitize(path)
    if not result.sanitized:
        print(f"could not sanitize: {result.reason}")
        print("→ BLOCK (no safe copy available)")
        return 1

    print(f"\nsanitized → {result.output_path}")
    if result.removed:
        print("removed:")
        for r in result.removed:
            line = f"  - [{r.kind}] {r.detail}"
            if r.excerpt:
                line += f"  «{r.excerpt[:60]}»"
            print(line)
    else:
        print("  (nothing unsafe found — copy is identical)")

    # Verify the cleaned copy is actually safe before ingesting.
    after = scanner.scan(result.output_path)
    print(f"\nsanitized verdict: {after.verdict.value}  (risk {after.risk_score:.2f})")
    safe = after.verdict == Verdict.ALLOW
    print("→ SAFE to ingest" if safe else "→ still risky; do NOT ingest")

    # In a real pipeline: ingest(result.output_path), then clean up.
    try:
        os.remove(result.output_path)
    except OSError:
        pass
    return 0 if safe else 2


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
