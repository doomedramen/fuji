#!/bin/bash

# Generate code coverage using grcov

echo "Generating coverage report using grcov..."

# Clean previous coverage data
rm -rf target/coverage
mkdir -p target/coverage

# Set environment variables for coverage
export LLVM_PROFILE_FILE="target/coverage/%p-%m.profraw"

# Run tests with coverage instrumentation
cargo test --lib --workspace --exclude-files="scripts/*" \
    --skip security::key_derivation::tests::test_benchmark \
    --skip security::file_provider::tests::test_performance \
    --skip security::file_provider::tests::test_performance_comparison

# Generate coverage report using grcov
grcov target/coverage \
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

# Generate HTML report if lcov is available
if command -v lcov &> /dev/null; then
    genhtml -o target/coverage/html target/coverage/lcov.info
    echo "Coverage report generated at target/coverage/html/index.html"
else
    echo "Coverage report generated at target/coverage/lcov.info"
    echo "Install lcov to generate HTML report: brew install lcov"
fi

# Extract coverage percentage
if command -v lcov &> /dev/null; then
    COVERAGE=$(lcov --summary target/coverage/lcov.info 2>&1 | grep "lines......" | grep -o "[0-9.]*%" | head -1)
    echo "Total coverage: $COVERAGE"
fi