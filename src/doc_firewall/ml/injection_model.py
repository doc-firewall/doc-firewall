"""W2 (0.5.0) — runtime loader for the bundled injection classifier.

Loads the vendored logistic-regression weights (``injection_clf.npz``,
shipped inside the package) and scores text. numpy-only — works in the base
install with no model download and no network.
"""
from __future__ import annotations

import os
from typing import Optional

import numpy as np

from .features import hash_features

_WEIGHTS_FILE = os.path.join(os.path.dirname(__file__), "injection_clf.npz")


class InjectionModel:
    def __init__(self, coef: np.ndarray, intercept: float, threshold: float,
                 meta: Optional[dict] = None):
        self.coef = coef.astype(np.float32)
        self.intercept = float(intercept)
        self.threshold = float(threshold)
        self.meta = meta or {}

    def score(self, text: str) -> float:
        """Return P(injection) in [0, 1] for ``text``."""
        x = hash_features(text)
        z = float(np.dot(self.coef, x) + self.intercept)
        return 1.0 / (1.0 + np.exp(-z))

    def is_injection(self, text: str) -> tuple[bool, float]:
        p = self.score(text)
        return p >= self.threshold, p


_CACHE: Optional[InjectionModel] = None
_LOAD_FAILED = False


def load_model() -> Optional[InjectionModel]:
    """Load (and cache) the bundled model, or None if it isn't present/loadable.

    Never raises — a missing/corrupt model simply disables the classifier
    layer (the regex + multilingual + script-mixing layers still run)."""
    global _CACHE, _LOAD_FAILED
    if _CACHE is not None:
        return _CACHE
    if _LOAD_FAILED or not os.path.exists(_WEIGHTS_FILE):
        return None
    try:
        data = np.load(_WEIGHTS_FILE, allow_pickle=False)
        _CACHE = InjectionModel(
            coef=data["coef"],
            intercept=float(data["intercept"]),
            threshold=float(data["threshold"]),
            meta={
                "trained": str(data["trained"]) if "trained" in data else "",
                "n_pos": int(data["n_pos"]) if "n_pos" in data else 0,
                "n_neg": int(data["n_neg"]) if "n_neg" in data else 0,
            },
        )
        return _CACHE
    except Exception:
        _LOAD_FAILED = True
        return None


def model_available() -> bool:
    return load_model() is not None
