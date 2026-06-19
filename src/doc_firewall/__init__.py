import os as _os

# Reduce per-process thread/subprocess oversubscription from the optional ML
# stack (torch, scikit-learn/joblib, HuggingFace tokenizers). When doc_firewall
# is run across many worker processes (the common bulk-scan pattern), each
# worker otherwise spawns one OpenMP/BLAS thread *and* a tokenizers fork-pool
# per CPU core — multiplying memory and leaking loky/semaphore resources. These
# are defaults only (`setdefault`), so an embedding caller can still override.
for _var, _val in (
    ("TOKENIZERS_PARALLELISM", "false"),
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("LOKY_MAX_CPU_COUNT", "1"),
):
    _os.environ.setdefault(_var, _val)

from .scanner import Scanner, scan
from .config import ScanConfig, Limits
from .report import ScanReport, Finding
from .policy import PolicyEngine, Policy

__all__ = [
    "Scanner",
    "ScanConfig",
    "Limits",
    "ScanReport",
    "Finding",
    "scan",
    "PolicyEngine",
    "Policy",
]
