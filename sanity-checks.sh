#!/bin/bash

# Test runner script for NAC Collector
# This script mimics the GitHub Actions workflow locally

set -e

echo "🐳 NAC Collector Local Test Runner"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose >/dev/null 2>&1; then
    print_error "Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

# Parse command line arguments
RUN_LINT=true
RUN_TESTS=true
PYTHON_VERSIONS=("3.9" "3.10" "3.11" "3.12")
SELECTED_VERSIONS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --lint-only)
            RUN_TESTS=false
            shift
            ;;
        --tests-only)
            RUN_LINT=false
            shift
            ;;
        --python)
            SELECTED_VERSIONS+=("$2")
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --lint-only          Run only linting checks"
            echo "  --tests-only         Run only tests (skip linting)"
            echo "  --python VERSION     Run tests for specific Python version(s)"
            echo "                       Can be used multiple times. Supported: 3.9, 3.10, 3.11, 3.12"
            echo "  --help, -h           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests for all Python versions"
            echo "  $0 --lint-only              # Run only linting"
            echo "  $0 --python 3.11             # Run tests only for Python 3.11"
            echo "  $0 --python 3.11 --python 3.12  # Run tests for Python 3.11 and 3.12"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

# If specific versions were selected, use those; otherwise use all
if [ ${#SELECTED_VERSIONS[@]} -gt 0 ]; then
    PYTHON_VERSIONS=("${SELECTED_VERSIONS[@]}")
fi

# Build the Docker images
print_status "Building Docker images..."
docker-compose -f docker-compose.test.yml build

echo ""

# Run linting if requested
if [ "$RUN_LINT" = true ]; then
    print_status "Running linting checks..."
    if docker-compose -f docker-compose.test.yml run --rm lint; then
        print_success "Linting passed ✓"
    else
        print_error "Linting failed ✗"
        exit 1
    fi
    echo ""
fi

# Run tests if requested
if [ "$RUN_TESTS" = true ]; then
    print_status "Running tests for Python versions: ${PYTHON_VERSIONS[*]}"
    echo ""
    
    FAILED_VERSIONS=()
    
    for version in "${PYTHON_VERSIONS[@]}"; do
        print_status "Testing with Python $version..."
        service_name="test-py${version//./}"
        
        if docker-compose -f docker-compose.test.yml run --rm "$service_name"; then
            print_success "Python $version tests passed ✓"
        else
            print_error "Python $version tests failed ✗"
            FAILED_VERSIONS+=("$version")
        fi
        echo ""
    done
    
    # Summary
    if [ ${#FAILED_VERSIONS[@]} -eq 0 ]; then
        print_success "All tests passed! 🎉"
    else
        print_error "Tests failed for Python versions: ${FAILED_VERSIONS[*]}"
        exit 1
    fi
else
    print_success "Skipping tests as requested."
fi

# Cleanup
print_status "Cleaning up..."
docker-compose -f docker-compose.test.yml down

print_success "Test run completed!"
