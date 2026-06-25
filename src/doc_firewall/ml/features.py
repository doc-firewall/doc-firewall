"""W2 (0.5.0) — feature extraction for the bundled injection classifier.

A single deterministic, dependency-light (numpy + stdlib) hashing feature
extractor used **identically** at training and inference time. The training
script (sklearn) and the runtime detector (numpy only) both call
``hash_features`` so the vendored weights line up exactly.

Features: lowercased word unigrams + bigrams, and character 3/4/5-grams,
hashed (signed) into a fixed-size vector with the hashing trick, then
L2-normalised. `re.\\w` is Unicode-aware, so CJK/Cyrillic/Arabic text is
tokenised and captured too — the classifier is multilingual by construction.
"""
from __future__ import annotations

import hashlib
import re
from typing import List

import numpy as np

from ..detectors.injection_normalizer import normalize_for_matching

DIM = 2048  # small vendored model: 2048 float32 ≈ 8 KB
_WORD_RE = re.compile(r"\w+", re.UNICODE)
_CHAR_NS = (3, 4, 5)


def _feature_strings(text: str) -> List[str]:
    # Fold obfuscation (zero-width, tag chars, math-script, homoglyphs,
    # single-char separators) to plain ASCII *before* featurising, so an
    # attacker can't move the classifier's score by encoding the same words
    # differently — and, symmetrically, a benign string that has merely been
    # obfuscation-encoded normalises back to benign and scores low. Applied
    # identically at training and inference time via this shared extractor.
    text = normalize_for_matching(text or "")
    words = _WORD_RE.findall(text)[:400]  # cap very long inputs
    feats: List[str] = []
    for w in words:
        feats.append("w:" + w)
    for a, b in zip(words, words[1:], strict=False):
        feats.append("ww:" + a + "_" + b)
    joined = " ".join(words)[:2000]
    for n in _CHAR_NS:
        for i in range(len(joined) - n + 1):
            feats.append(f"c{n}:{joined[i:i + n]}")
    return feats


def _hash(token: str) -> int:
    # md5 is deterministic and cross-platform; we only use it as a hash, not
    # for security, so it's an appropriate choice here.
    return int.from_bytes(hashlib.md5(token.encode("utf-8")).digest()[:8], "big")


def hash_features(text: str) -> np.ndarray:
    """Return the L2-normalised hashed feature vector for ``text``."""
    v = np.zeros(DIM, dtype=np.float32)
    for f in _feature_strings(text):
        h = _hash(f)
        idx = h % DIM
        sign = 1.0 if (h >> 12) & 1 else -1.0
        v[idx] += sign
    norm = float(np.linalg.norm(v))
    if norm > 0.0:
        v /= norm
    return v


def feature_matrix(texts: List[str]) -> np.ndarray:
    return np.vstack([hash_features(t) for t in texts]) if texts else np.zeros((0, DIM))
