#!/bin/bash

# Generate code coverage using llvm-tools and grcov

echo "Generating coverage report..."

# Clean previous coverage data
rm -rf target/coverage
mkdir -p target/coverage

# Set environment variables for coverage
export LLVM_PROFILE_FILE="target/coverage/fuji-%p-%m.profraw"

# Clean any existing profraw files
rm -f target/coverage/*.profraw

# Run tests with coverage instrumentation
cargo test --lib 2>&1 | tee /dev/tty

# Find the profraw files
PROFDATA=$(find target/coverage -name "*.profraw" | head -1)

if [ -z "$PROFDATA" ]; then
    echo "No profiling data found. Trying with llvm-profdata..."

    # Try to use llvm-profdata to merge the data
    llvm-profdata merge -sparse target/coverage/*.profraw -o target/coverage/merged.profdata

    # Generate report
    llvm-cov report --use-color --ignore-filename-regex='(tests/|test-data/|target/|scripts/)' \
        --instr-profile=target/coverage/merged.profdata \
        $(find target/debug/deps -name "fuji-*" -executable -type f 2>/dev/null | head -1) \
        > target/coverage/coverage.txt

    # Generate lcov
    llvm-cov export --format=lcov --ignore-filename-regex='(tests/|test-data/|target/|scripts/)' \
        --instr-profile=target/coverage/merged.profdata \
        $(find target/debug/deps -name "fuji-*" -executable -type f 2>/dev/null | head -1) \
        > target/coverage/lcov.info

else
    echo "Found profraw files: $PROFDATA"

    # Use grcov to generate lcov
    grcov . \
        --binary-path ./target/debug/ \
        --source-dir . \
        --output-type lcov \
        --branch \
        --ignore-not-existing \
        --ignore "/*" \
        --ignore "target/*" \
        --ignore "tests/*" \
        --ignore "scripts/*" \
        --output-path target/coverage/lcov.info
fi

# Display coverage summary
if [ -f target/coverage/lcov.info ]; then
    echo "Coverage report generated at target/coverage/lcov.info"

    # Try to extract coverage percentage
    if command -v lcov &> /dev/null; then
        COVERAGE=$(lcov --summary target/coverage/lcov.info 2>&1 | grep "lines......" | grep -o "[0-9.]*%" | head -1)
        echo "Total coverage: $COVERAGE"
    fi
else
    echo "Failed to generate coverage report"
fi