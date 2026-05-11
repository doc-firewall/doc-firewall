"""Model file integrity verification via SHA-256 manifest.

Protects against supply-chain attacks where an attacker with write access to
the model directory swaps in a model that always returns PASS (or exfiltrates
data). Verification runs at Scanner init time before any model is loaded.

Manifest format (JSON):
    {
        "config.json": "abc123...",
        "pytorch_model.bin": "def456...",
        "model.safetensors": "..."
    }

Keys are either bare filenames or relative paths from the model directory root.

Generate a fresh manifest with::

    ModelIntegrityChecker.generate_manifest(
        ["/mnt/models/deberta-v3-base-prompt-injection-v2"],
        output_path="/etc/docfw/model_manifest.json",
    )
"""
from __future__ import annotations

import hashlib
import json
import os

_CHUNK_SIZE = 65536


class ModelIntegrityError(RuntimeError):
    """Raised when a model file's hash does not match the manifest."""


def _sha256_path(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


class ModelIntegrityChecker:
    """Verifies ML model files against a SHA-256 manifest before they are loaded.

    Args:
        manifest_path: Path to the JSON manifest file produced by
            :meth:`generate_manifest`.
    """

    def __init__(self, manifest_path: str) -> None:
        self._manifest_path = manifest_path
        self._manifest: dict[str, str] = self._load_manifest()

    def _load_manifest(self) -> dict[str, str]:
        with open(self._manifest_path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError(
                f"Model manifest must be a JSON object: {self._manifest_path}"
            )
        return {k: v.lower() for k, v in data.items()}

    def verify(self, model_path: str) -> None:
        """Verify a model file or directory against the manifest.

        For a directory, every file whose relative path or basename appears
        in the manifest is verified. Files not listed in the manifest are
        silently skipped (they are not tracked, not blocked).

        Raises:
            ModelIntegrityError: If any tracked file is missing or its
                SHA-256 does not match the manifest entry.
        """
        if os.path.isfile(model_path):
            self._verify_single(model_path, os.path.basename(model_path))
        elif os.path.isdir(model_path):
            for root, _, files in os.walk(model_path):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, model_path)
                    key = rel if rel in self._manifest else fname
                    if key not in self._manifest:
                        continue
                    self._verify_single(fpath, key)
        else:
            raise ModelIntegrityError(
                f"Model path does not exist: {model_path}"
            )

    def _verify_single(self, path: str, manifest_key: str) -> None:
        if manifest_key not in self._manifest:
            raise ModelIntegrityError(
                f"'{manifest_key}' not found in manifest {self._manifest_path}"
            )
        actual = _sha256_path(path)
        expected = self._manifest[manifest_key]
        if actual != expected:
            raise ModelIntegrityError(
                f"Integrity failure for '{path}': "
                f"expected {expected[:12]}…, got {actual[:12]}…"
            )

    @classmethod
    def generate_manifest(
        cls,
        paths: list[str],
        output_path: str,
        *,
        overwrite: bool = False,
    ) -> None:
        """Generate a SHA-256 manifest from a list of model files/directories.

        Args:
            paths: List of file or directory paths to hash.
            output_path: Destination JSON file for the manifest.
            overwrite: If False (default), raise FileExistsError when
                *output_path* already exists, preventing accidental overwrites.
        """
        if not overwrite and os.path.exists(output_path):
            raise FileExistsError(
                f"Manifest already exists at {output_path}. "
                "Pass overwrite=True to regenerate."
            )

        manifest: dict[str, str] = {}
        for path in paths:
            if os.path.isfile(path):
                manifest[os.path.basename(path)] = _sha256_path(path)
            elif os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        rel = os.path.relpath(fpath, path)
                        manifest[rel] = _sha256_path(fpath)
            else:
                raise FileNotFoundError(f"Path not found: {path}")

        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        print(f"Manifest written: {output_path} ({len(manifest)} entries)")
