.PHONY: install-hooks

## Activate the repo's pre-commit hooks (run once after cloning).
## Sets git's hooksPath to .githooks/ so the committed hook scripts are used.
install-hooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-commit
	@echo "✅  Pre-commit hooks installed."
