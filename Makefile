.PHONY: install-hooks sbom lock-deps verify-deps generate-model-manifest

## Activate the repo's pre-commit hooks (run once after cloning).
## Sets git's hooksPath to .githooks/ so the committed hook scripts are used.
install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit
	@echo "Pre-commit hooks installed."

## Generate a CycloneDX SBOM from the installed package environment.
## Requires: pip install cyclonedx-bom
## Output:   sbom.json  (CycloneDX JSON format)
sbom:
	@command -v cyclonedx-py >/dev/null 2>&1 || { \
	  echo "cyclonedx-bom not found. Run: pip install cyclonedx-bom"; exit 1; }
	cyclonedx-py environment --of Json -o sbom.json
	@echo "SBOM written to sbom.json"

## Pin all current dependencies with their SHA-256 hashes to requirements.lock.
## Run this after any dependency update and commit requirements.lock.
lock-deps:
	pip-compile --generate-hashes --output-file requirements.lock pyproject.toml
	@echo "Pinned requirements written to requirements.lock"

## Verify installed packages match the pinned requirements.lock hashes.
## Fails if any package hash does not match (tampered or wrong version).
verify-deps:
	pip install --require-hashes -r requirements.lock --dry-run
	@echo "All dependency hashes verified."

## Generate a SHA-256 model integrity manifest from local model directories.
## Usage: make generate-model-manifest MODELS=/mnt/models/deberta OUTPUT=/etc/docfw/model_manifest.json
MODELS ?= models/
OUTPUT ?= model_manifest.json
generate-model-manifest:
	python - <<'EOF'
	import sys
	sys.path.insert(0, "src")
	from doc_firewall.security.model_integrity import ModelIntegrityChecker
	import os
	paths = [p.strip() for p in "$(MODELS)".split(",") if p.strip()]
	ModelIntegrityChecker.generate_manifest(paths, "$(OUTPUT)", overwrite=True)
	EOF
