# Local Testing for NAC Collector

This directory contains Docker-based testing setup to run the GitHub Actions workflow locally.

## ✅ Quick Start

```bash
# Run all tests (linting + pytest on all Python versions)
./sanity-checks.sh

# Run tests for Python 3.11 only
./sanity-checks.sh --python 3.11

# Run only linting
./sanity-checks.sh --lint-only
```

## Files

- `Dockerfile.test` - Multi-stage Dockerfile for testing with different Python versions
- `docker-compose.test.yml` - Docker Compose configuration for running tests
- `sanity-checks.sh` - Main test runner script (replaces test-local.sh)
- `run_tests.sh` - Internal script executed inside containers

## Quick Start

### Run All Tests (Default)
```bash
./sanity-checks.sh
```
This runs:
1. Linting checks (pre-commit)
2. Tests on Python 3.9, 3.10, 3.11, and 3.12

### Run Only Linting
```bash
./sanity-checks.sh --lint-only
```

### Run Only Tests (Skip Linting)
```bash
./sanity-checks.sh --tests-only
```

### Test Specific Python Version(s)
```bash
# Test only Python 3.11
./sanity-checks.sh --python 3.11

# Test Python 3.11 and 3.12
./sanity-checks.sh --python 3.11 --python 3.12
```

## Manual Docker Commands

### Build Images
```bash
docker-compose -f docker-compose.test.yml build
```

### Run Linting Only
```bash
docker-compose -f docker-compose.test.yml run --rm lint
```

### Run Tests for Specific Python Version
```bash
# Python 3.11
docker-compose -f docker-compose.test.yml run --rm test-py311

# Python 3.9
docker-compose -f docker-compose.test.yml run --rm test-py39
```

### Clean Up
```bash
docker-compose -f docker-compose.test.yml down
docker system prune -f
```

## What Gets Tested

This setup mirrors the GitHub Actions workflow (`test.yml`) and runs:

1. **Lint Job**: 
   - Pre-commit checks (ruff linting and formatting)

2. **Test Job**: 
   - Install dependencies with Poetry
   - Run pytest test suite
   - Test against multiple Python versions (3.9, 3.10, 3.11, 3.12)

## Requirements

- Docker
- Docker Compose

## Troubleshooting

### Docker Not Running
Make sure Docker Desktop is running before executing the test script.

### Permission Denied
If you get permission denied when running `./sanity-checks.sh`:
```bash
chmod +x sanity-checks.sh
```

### Out of Disk Space
Clean up Docker images and containers:
```bash
docker system prune -a
```

### Tests Failing Locally
1. Check if all dependencies are properly installed
2. Ensure your code passes the pre-commit hooks
3. Run tests individually to isolate issues

## GitHub Actions Equivalence

| GitHub Actions | Local Docker |
|----------------|--------------|
| `pre-commit/action@v3.0.1` | `docker-compose run lint` |
| `poetry install && poetry run pytest` | `docker-compose run test-py{version}` |
| Matrix strategy (Python 3.9-3.12) | Separate containers for each version |

## Example Output

```bash
🐳 NAC Collector Local Test Runner
==================================

[INFO] Building Docker images...
[INFO] Running linting checks...
[SUCCESS] Linting passed ✓

[INFO] Running tests for Python versions: 3.11
[INFO] Testing with Python 3.11...
[SUCCESS] Python 3.11 tests passed ✓

[SUCCESS] All tests passed! 🎉
[SUCCESS] Test run completed!
```
