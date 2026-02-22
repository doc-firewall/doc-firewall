# Contributing Guide

We welcome contributions to DocFirewall!

## Development Environment

### Prerequisites

-   Python 3.10+
-   Poetry (optional, but recommended)
-   Docker (for AV integration tests)

### Setup

```bash
git clone https://github.com/your-org/doc-firewall.git
cd doc-firewall
pip install -e ".[dev]"
pre-commit install
```

## Testing

We use `pytest` for unit and integration tests.

```bash
# Run all tests
pytest

# Run fast tests only
pytest -m "not slow"

# Run with coverage
pytest --cov=doc_firewall
```

## Code Style

We follow PEP 8 and use `black` for formatting.

```bash
# Format code
black src tests

# Check types
mypy src
```

## Pull Request Process

1.  Create a feature branch.
2.  Add tests for new features.
3.  Ensure all tests pass locally.
4.  Submit a PR with a description of changes.
