"""Persistent Docling worker manager (0.5.0).

The Docling converter is hosted in ONE long-lived subprocess per process so the
~5 s docling+torch import and the model build are paid once, not per PDF. These
tests cover the manager's singleton / device-keying / lifecycle logic without
spawning a real Docling subprocess (the worker only starts lazily on the first
`convert`), so they're reliable regardless of whether Docling is installed.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.utils import docling_convert as dc


def teardown_function(_):
    dc._shutdown_docling_worker()


class TestSingleton:
    def test_same_device_returns_same_worker(self):
        w1 = dc._get_docling_worker("cpu")
        w2 = dc._get_docling_worker("cpu")
        assert w1 is w2  # one persistent worker, reused

    def test_device_change_rebuilds_worker(self):
        w_cpu = dc._get_docling_worker("cpu")
        w_gpu = dc._get_docling_worker("cuda")
        assert w_cpu is not w_gpu
        assert dc._docling_worker_device == "cuda"

    def test_shutdown_clears_singleton(self):
        dc._get_docling_worker("cpu")
        assert dc._docling_worker is not None
        dc._shutdown_docling_worker()
        assert dc._docling_worker is None


class TestLifecycle:
    def test_worker_starts_lazily_not_on_construction(self):
        # Constructing the manager / getting the singleton must NOT spawn the
        # subprocess — that only happens on the first convert().
        w = dc._get_docling_worker("cpu")
        assert w._proc is None

    def test_stop_is_idempotent(self):
        w = dc._DoclingWorker("cpu")
        w._stop()
        w._stop()  # must not raise on an already-stopped / never-started worker
        assert w._proc is None
