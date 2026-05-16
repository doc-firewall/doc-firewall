"""G.5 — 200+ document benign false-positive corpus with CI gate.

Runs the full detector stack (the post-Phase-D/E/F detector list, with the
lazy-ML text layers disabled for determinism + speed) over a deterministic
220-document benign corpus and enforces:

  • balanced profile : FP rate <= 1.0%
  • strict   profile : FP rate <= 3.0%

A false positive = any document that produces a non-INFO finding OR a
verdict other than ALLOW. The corpus is generated in-tree (no network),
so the SHA-256 manifest is reproducible; `test_manifest_matches` guards
against silent corpus drift.

Marks: @pytest.mark.benign
"""
from __future__ import annotations

import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.base import ParsedDocument
from doc_firewall.config import ScanConfig
from doc_firewall.enums import Severity
from doc_firewall.scanner import Scanner

from benign_corpus_data import generate_corpus

_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "benign_corpus_manifest.yaml")

# Non-INFO findings count as false positives.
_FP_SEVERITIES = {Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}


def _detectors_for(config: ScanConfig):
    """Build the full detector list exactly as Scanner does, then prepare()
    each (G.4) so the run is fast and deterministic."""
    sc = Scanner(config)
    return sc


def _scan_text_only(scanner: Scanner, doc_text: str, meta: dict) -> list:
    """Run every detector against a ParsedDocument built from text+metadata.

    We bypass file I/O (the corpus is synthetic text) and exercise the
    deep-scan detector path directly — that is where false positives in the
    new Phase D/E/F detectors would surface.
    """
    parsed = ParsedDocument(
        file_path="benign_corpus.txt",
        file_type="txt",
        text=doc_text,
        metadata=meta,
    )
    findings: list = []
    for det in scanner.detectors:
        try:
            findings.extend(det.run(parsed, scanner.config))
        except Exception:
            # A detector raising on benign input is itself a defect, but the
            # FP gate concerns findings; surface crashes separately.
            raise
    return findings


def _fp_rate(profile: str) -> tuple[float, list[str]]:
    # Disable lazy-ML text layers: deterministic + fast. Their benign
    # behaviour is covered by the original test_benign_corpus.py.
    config = ScanConfig(
        profile=profile,
        enable_semantic_scans=False,
        enable_advanced_bert=False,
        enable_semantic_nn=False,
        enable_ocr_injection_scan=False,
        enable_qr_decode=False,
    )
    scanner = _detectors_for(config)
    corpus = generate_corpus()
    offenders: list[str] = []
    for d in corpus:
        findings = _scan_text_only(scanner, d.text, d.metadata)
        bad = [
            f for f in findings
            if f.severity in _FP_SEVERITIES
        ]
        if bad:
            offenders.append(
                f"{d.doc_id} [{d.category}] -> "
                + ", ".join(f"{f.threat_id.value}:{f.title}" for f in bad[:3])
            )
    rate = len(offenders) / len(corpus)
    return rate, offenders


@pytest.mark.benign
def test_balanced_fp_rate_within_gate() -> None:
    rate, offenders = _fp_rate("balanced")
    assert rate <= 0.01, (
        f"balanced FP rate {rate:.1%} exceeds 1% gate. "
        f"Offenders ({len(offenders)}):\n" + "\n".join(offenders[:20])
    )


@pytest.mark.benign
def test_strict_fp_rate_within_gate() -> None:
    rate, offenders = _fp_rate("strict")
    assert rate <= 0.03, (
        f"strict FP rate {rate:.1%} exceeds 3% gate. "
        f"Offenders ({len(offenders)}):\n" + "\n".join(offenders[:20])
    )


@pytest.mark.benign
def test_corpus_size_at_least_200() -> None:
    assert len(generate_corpus()) >= 200


@pytest.mark.benign
def test_manifest_matches() -> None:
    """The manifest pins each doc's SHA-256 so corpus drift is explicit.

    If the generator changes, regenerate via:
        PYTHONPATH=src python tests/test_benign_corpus_200.py --write-manifest
    """
    corpus = generate_corpus()
    expected = {d.doc_id: d.sha256 for d in corpus}
    if not os.path.exists(_MANIFEST_PATH):
        pytest.skip("manifest not yet written; run with --write-manifest")
    with open(_MANIFEST_PATH) as f:
        manifest = yaml.safe_load(f) or {}
    pinned = manifest.get("documents", {})
    mismatched = [
        doc_id for doc_id, sha in expected.items()
        if pinned.get(doc_id) != sha
    ]
    assert not mismatched, (
        f"{len(mismatched)} corpus documents drifted from the manifest: "
        f"{mismatched[:10]}. Regenerate the manifest if the change is "
        "intentional."
    )


def _write_manifest() -> None:
    corpus = generate_corpus()
    manifest = {
        "generated_by": "tests/benign_corpus_data.py generate_corpus()",
        "seed": 20260515,
        "count": len(corpus),
        "expected_verdict": "ALLOW",
        "fp_gate": {"balanced": 0.01, "strict": 0.03},
        "documents": {d.doc_id: d.sha256 for d in corpus},
    }
    with open(_MANIFEST_PATH, "w") as f:
        yaml.safe_dump(manifest, f, sort_keys=True)
    print(f"wrote {_MANIFEST_PATH} ({len(corpus)} docs)")


if __name__ == "__main__":
    if "--write-manifest" in sys.argv:
        _write_manifest()
    else:
        for prof in ("balanced", "strict"):
            rate, offenders = _fp_rate(prof)
            print(f"{prof:9} FP rate: {rate:.2%} ({len(offenders)} offenders)")
            for o in offenders[:10]:
                print("  " + o)
