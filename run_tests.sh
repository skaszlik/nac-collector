#!/bin/bash
set -e

echo "=== Running Pre-commit Checks ==="
pre-commit run --all-files

echo "=== Running Tests ==="
poetry run pytest

echo "=== All tests passed! ==="
