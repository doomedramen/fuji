#!/bin/bash

# Generate test coverage report and badge
# This script runs cargo-tarpaulin to generate coverage and creates a badge

set -e

echo "=== Generating Test Coverage Report ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Coverage thresholds
COVERAGE_GOOD=80
COVERAGE_OK=60

# Create coverage directory
mkdir -p target/coverage

# Run tests with coverage
echo "Running tests with coverage analysis..."
OUTPUT=$(cargo tarpaulin --lib --skip-clean --fail-under 0 --workspace --exclude-files="scripts/*" --ignore-tests 2>&1)

# Save output
echo "$OUTPUT" > target/coverage/tarpaulin-output.txt

# Extract coverage percentage from output (try different patterns)
COVERAGE=$(echo "$OUTPUT" | grep -o "Overall Coverage: [0-9.]*%" | head -1 | grep -o "[0-9.]*" || \
          echo "$OUTPUT" | grep -o "Coverage: [0-9.]*%" | head -1 | grep -o "[0-9.]*" || \
          echo "$OUTPUT" | grep -o "[0-9.]*%" | head -1 | grep -o "[0-9.]*" || \
          echo "0")

COVERAGE_INT=$(echo "$COVERAGE" | cut -d. -f1)

if [ "$COVERAGE" = "0" ]; then
    echo -e "${YELLOW}Warning: Could not extract coverage percentage, showing output:${NC}"
    echo "$OUTPUT" | tail -20
fi

echo
echo "Coverage: ${COVERAGE}%"

# Determine badge color
if [ "$COVERAGE_INT" -ge "$COVERAGE_GOOD" ]; then
    COLOR="brightgreen"
    STATUS="good"
elif [ "$COVERAGE_INT" -ge "$COVERAGE_OK" ]; then
    COLOR="yellow"
    STATUS="ok"
else
    COLOR="red"
    STATUS="poor"
fi

echo "Status: $STATUS"

# Generate badge
BADGE_FILE="docs/coverage-badge.svg"
BADGE_URL="https://img.shields.io/badge/coverage-${COVERAGE}%25-${COLOR}.svg"

# Create docs directory if it doesn't exist
mkdir -p docs

# Download the badge
echo "Downloading coverage badge..."
curl -s "$BADGE_URL" -o "$BADGE_FILE"

if [ -f "$BADGE_FILE" ]; then
    echo "Badge saved to: $BADGE_FILE"
else
    echo -e "${RED}Error: Failed to download badge${NC}"
    exit 1
fi

# Update README with badge
README_FILE="README.md"
if [ -f "$README_FILE" ]; then
    # Check if badge already exists
    if grep -q "coverage-badge.svg" "$README_FILE"; then
        # Replace existing badge
        sed -i.bak "s|!\[Coverage\](.*coverage-badge\.svg)|![Coverage](docs/coverage-badge.svg)|" "$README_FILE"
        echo "Updated existing coverage badge in README.md"
    else
        # Add badge at the top of README
        TEMP_FILE=$(mktemp)
        echo "![Coverage](docs/coverage-badge.svg)" > "$TEMP_FILE"
        cat "$README_FILE" >> "$TEMP_FILE"
        mv "$TEMP_FILE" "$README_FILE"
        echo "Added coverage badge to README.md"
    fi
else
    echo -e "${YELLOW}Warning: README.md not found, creating one with badge${NC}"
    echo "# Fuji" > "$README_FILE"
    echo "" >> "$README_FILE"
    echo "![Coverage](docs/coverage-badge.svg)" >> "$README_FILE"
    echo "" >> "$README_FILE"
    echo "A network file system mount manager with daemon-based architecture" >> "$README_FILE"
fi

# Output summary
echo
echo "=== Coverage Summary ==="
echo -e "Coverage: ${COVERAGE}%"
echo -e "Status: ${GREEN}$STATUS${NC}"
echo -e "Badge: ${GREEN}Generated${NC}"
echo -e "Report: ${GREEN}target/coverage/tarpaulin-output.txt${NC}"
echo

# Exit with appropriate code based on coverage
if [ "$COVERAGE_INT" -ge "$COVERAGE_GOOD" ]; then
    exit 0
elif [ "$COVERAGE_INT" -ge "$COVERAGE_OK" ]; then
    exit 0
else
    echo -e "${RED}Warning: Coverage below ${COVERAGE_OK}%${NC}"
    exit 1
fi