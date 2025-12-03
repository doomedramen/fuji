#!/bin/bash

# Simplified but robust script to fix common Rust compilation warnings
# This version focuses on the most common and easily fixable warnings

set -e

echo "=== Fuji Cleanup Script for Rust Warnings v3 ==="
echo

# Count warnings before cleanup
echo "Counting current warnings..."
warnings_before=$(cargo check 2>&1 | grep -c "warning:" || echo "0")
errors_before=$(cargo check 2>&1 | grep -c "error:" || echo "0")
echo "Warnings before cleanup: $warnings_before"
echo "Errors before cleanup: $errors_before"
echo

# Function to fix unused imports by removing them
fix_unused_imports() {
    echo "=== Fixing Unused Imports ==="

    # Get all unused import warnings
    cargo check 2>&1 | grep "unused import:" | while read -r line; do
        # Extract file path and line number
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*unused import:.*`([^`]+)`.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            import="${BASH_REMATCH[3]}"

            echo "  - Removing unused import '$import' from $file:$line_num"

            # Remove the import line using sed
            sed -i.bak "${line_num}d" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix unused variables by prefixing with underscore
fix_unused_variables() {
    echo "=== Fixing Unused Variables ==="

    cargo check 2>&1 | grep "unused variable:" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*unused variable:.*`([^`]+)`.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            var="${BASH_REMATCH[3]}"

            echo "  - Prefixing unused variable '$var' with underscore in $file:$line_num"

            # Replace variable with underscore version (only whole word matches)
            sed -i.bak "${line_num}s/\\b${var}\\b/_${var}/g" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix unnecessary mut
fix_unnecessary_mut() {
    echo "=== Fixing Unnecessary mut ==="

    cargo check 2>&1 | grep "variable does not need to be mutable" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*variable `([^`]+)` does not need to be mutable.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            var="${BASH_REMATCH[3]}"

            echo "  - Removing unnecessary mut from '$var' in $file:$line_num"

            # Remove mut from variable declaration
            sed -i.bak "${line_num}s/mut ${var}/${var}/g" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix dead code warnings for functions by adding #[allow(dead_code)]
fix_dead_code_functions() {
    echo "=== Fixing Dead Code (Functions) ==="

    cargo check 2>&1 | grep "function.*is never used" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*function `([^`]+)` is never used.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            func="${BASH_REMATCH[3]}"

            echo "  - Adding #[allow(dead_code)] to function '$func' in $file:$line_num"

            # Add #[allow(dead_code)] before the function
            sed -i.bak "${line_num}i\\#[allow(dead_code)]" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix dead code warnings for structs by adding #[allow(dead_code)]
fix_dead_code_structs() {
    echo "=== Fixing Dead Code (Structs) ==="

    cargo check 2>&1 | grep "struct.*is never constructed" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*struct `([^`]+)` is never constructed.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            struct="${BASH_REMATCH[3]}"

            echo "  - Adding #[allow(dead_code)] to struct '$struct' in $file:$line_num"

            # Add #[allow(dead_code)] before the struct
            sed -i.bak "${line_num}i\\#[allow(dead_code)]" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix dead code warnings for enums by adding #[allow(dead_code)]
fix_dead_code_enums() {
    echo "=== Fixing Dead Code (Enums) ==="

    cargo check 2>&1 | grep "enum.*is never used" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*enum `([^`]+)` is never used.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            enum="${BASH_REMATCH[3]}"

            echo "  - Adding #[allow(dead_code)] to enum '$enum' in $file:$line_num"

            # Add #[allow(dead_code)] before the enum
            sed -i.bak "${line_num}i\\#[allow(dead_code)]" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix dead code warnings for traits by adding #[allow(dead_code)]
fix_dead_code_traits() {
    echo "=== Fixing Dead Code (Traits) ==="

    cargo check 2>&1 | grep "trait.*is never used" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*trait `([^`]+)` is never used.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            trait="${BASH_REMATCH[3]}"

            echo "  - Adding #[allow(dead_code)] to trait '$trait' in $file:$line_num"

            # Add #[allow(dead_code)] before the trait
            sed -i.bak "${line_num}i\\#[allow(dead_code)]" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix unused fields by prefixing with underscore
fix_unused_fields() {
    echo "=== Fixing Unused Fields ==="

    cargo check 2>&1 | grep "field.*is never read" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*field `([^`]+)` is never read.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            field="${BASH_REMATCH[3]}"

            echo "  - Prefixing unused field '$field' with underscore in $file:$line_num"

            # Replace field with underscore version (only whole word matches)
            sed -i.bak "${line_num}s/\\b${field}:/_${field}:/g" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Function to fix unused assignments
fix_unused_assignments() {
    echo "=== Fixing Unused Assignments ==="

    cargo check 2>&1 | grep "value assigned to `.*` is never read" | while read -r line; do
        if [[ $line =~ ^([^:]+):([0-9]+):[0-9]+:.*warning:.*value assigned to `([^`]+)` is never read.* ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"
            var="${BASH_REMATCH[3]}"

            echo "  - Prefixing assigned variable '$var' with underscore in $file:$line_num"

            # Replace variable with underscore version in assignments
            sed -i.bak "${line_num}s/\\b${var}\\b/_${var}/g" "$file" 2>/dev/null || true

            # Remove backup file
            rm -f "$file.bak"
        fi
    done
}

# Run all fixes
fix_unused_imports
fix_unused_variables
fix_unnecessary_mut
fix_unused_assignments
fix_dead_code_functions
fix_dead_code_structs
fix_dead_code_enums
fix_dead_code_traits
fix_unused_fields

echo
echo "=== Cleanup Complete ==="
echo

# Count warnings after cleanup
echo "Running cargo check to count remaining warnings..."
warnings_after=$(cargo check 2>&1 | grep -c "warning:" || echo "0")
errors_after=$(cargo check 2>&1 | grep -c "error:" || echo "0")

echo "Warnings before cleanup: $warnings_before"
echo "Warnings after cleanup: $warnings_after"
echo "Errors before cleanup: $errors_before"
echo "Errors after cleanup: $errors_after"

warnings_fixed=$((warnings_before - warnings_after))
echo "Warnings fixed: $warnings_fixed"

if [ $warnings_after -gt 0 ]; then
    echo
    echo "Remaining warnings (first 10):"
    cargo check 2>&1 | grep "warning:" | head -10
fi