#!/bin/bash

# Generate code coverage report while skipping performance tests that fail under instrumentation

echo "Generating coverage report..."

# Run tarpaulin with specific tests skipped
cargo tarpaulin \
    --lib \
    --skip-clean \
    --workspace \
    --exclude-files="scripts/*" \
    --timeout 600 \
    --output-dir target/coverage \
    --out Xml \
    -- \
    --skip security::key_derivation::tests::test_benchmark \
    --skip security::file_provider::tests::test_performance \
    --skip security::file_provider::tests::test_performance_comparison

echo "Coverage report generated at target/coverage/tarpaulin-report.xml"
