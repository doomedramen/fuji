#!/bin/bash

# Simple script to fix common Rust compilation warnings
# This script focuses on the most common warning patterns

set -e

echo "=== Fuji Cleanup Script for Rust Warnings ==="
echo

# Function to remove unused import from a file
remove_unused_import() {
    local file="$1"
    local import="$2"

    echo "  - Removing unused import '$import' from $file"

    # Use sed to remove the import
    sed -i.tmp "/^use $import[^a-zA-Z_]/d" "$file"

    # Remove trailing commas and clean up
    sed -i.tmp -e 's/use {\([^}]*)}, *use /use { \1 } /g' \
               -e 's/use {\([^}]*)} *, *use /use { \1 }/g' \
               -e 's/, *$//' \
               "$file"

    # Remove temporary file if it exists
    rm -f "$file.tmp"
}

# Function to prefix unused variable with underscore
prefix_unused_var() {
    local file="$1"
    local var="$2"
    local line_num="$3"

    echo "  - Prefixing unused variable '$var' with underscore in $file:$line_num"

    # Replace the variable with prefixed version
    sed -i.tmp "${line_num}s/\\b$var\\b/_$var/g" "$file"
    rm -f "$file.tmp"
}

# Function to remove unnecessary mut
remove_unnecessary_mut() {
    local file="$1"
    local var="$2"
    local line_num="$3"

    echo "  - Removing unnecessary mut from '$var' in $file:$line_num"

    # Replace mut var with just var
    sed -i.tmp "${line_num}s/mut $var/$var/g" "$file"
    rm -f "$file.tmp"
}

# Function to add #[allow(dead_code)] attribute
add_dead_code_allow() {
    local file="$1"
    local item_type="$2"  # function, struct, enum, trait, etc.
    local item_name="$3"

    echo "  - Adding #[allow(dead_code)] to $item_type '$item_name' in $file"

    # Find the item and add the attribute before it
    awk -v '//' "$file" | \
    awk -v '^[[:space:]]*\/\/' \
        -v item_type="$item_type" \
        -v item_name="$item_name" '
        /^([[:space:]]*pub[[:space:]]+)?'"$item_type"'[[:space:]]+"'"$item_name"'/ {
            print "#[allow(dead_code)]"
            print $0
            next
        }
        { print }
    ' > "$file.tmp" && \
    mv "$file.tmp" "$file"
}

# Main cleanup function
cleanup_warnings() {
    echo "Analyzing compilation warnings..."
    echo

    # Get cargo check output
    cargo check 2>&1 | tee /tmp/cargo_check_output.txt

    # Process unused imports
    echo
    echo "=== Processing Unused Imports ==="
    grep "unused import" /tmp/cargo_check_output.txt | while read -r line; do
        if [[ $line =~ .*src/(.*)\.rs:(.*) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"

            # Extract import name
            import=$(echo "$line" | sed -n 's/.*unused import: *`\(.*\)`.*/\1/p')

            if [[ -n "$import" && -f "src/$file" ]]; then
                remove_unused_import "src/$file" "$import"
            fi
        fi
    done

    # Process unused variables
    echo
    echo "=== Processing Unused Variables ==="
    grep "unused variable" /tmp/cargo_check_output.txt | while read -r line; do
        if [[ $line =~ .*src/(.*)\.rs:(.*) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"

            # Extract variable name
            var=$(echo "$line" | sed -n 's/.*unused variable: *`\([^`]*\)`*.*/\1/p')

            if [[ -n "$var" && -f "src/$file" ]]; then
                prefix_unused_var "src/$file" "$var" "$line_num"
            fi
        fi
    done

    # Process unnecessary mut
    echo
    echo "=== Processing Unnecessary mut ==="
    grep "variable does not need to be mutable" /tmp/cargo_check_output.txt | while read -r line; do
        if [[ $line =~ .*src/(.*)\.rs:(.*) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"

            # Extract variable name
            var=$(echo "$line" | sed -n 's/.*variable `\([^`]*\)` does not need to be mutable.*/\1/p')

            if [[ -n "$var" && -f "src/$file" ]]; then
                remove_unnecessary_mut "src/$file" "$var" "$line_num"
            fi
        fi
    done

    # Process dead code warnings
    echo
    echo "=== Processing Dead Code ==="
    grep "function.*is never used" /tmp/cargo_check_output.txt | while read -r line; do
        if [[ $line =~ .*src/(.*)\.rs:(.*) ]]; then
            file="${BASH_REMATCH[1]}"

            # Extract function name
            func=$(echo "$line" | sed -n 's/.*function `\([^`]*\)` is never used.*/\1/p')

            if [[ -n "$func" && -f "src/$file" ]]; then
                add_dead_code_allow "src/$file" "fn" "$func"
            fi
        fi
    done

    # Process unused fields
    echo
    echo "=== Processing Unused Fields ==="
    grep "field.*is never read" /tmp/cargo_check_output.txt | while read -r line; do
        if [[ $line =~ .*src/(.*)\.rs:(.*) ]]; then
            file="${BASH_REMATCH[1]}"
            line_num="${BASH_REMATCH[2]}"

            # Extract field name
            field=$(echo "$line" | sed -n 's/.*field `\([^`]*\)` is never read.*/\1/p')

            if [[ -n "$field" && -f "src/$file" ]]; then
                # For fields, we need to prefix with underscore in the struct definition
                prefix_unused_var "src/$file" "$field" "$line_num"
            fi
        fi
    done

    # Clean up
    rm -f /tmp/cargo_check_output.txt

    echo
    echo "=== Cleanup Complete ==="
    echo
    echo "Running cargo check again to verify improvements..."
    cargo check 2>&1 | grep -E "(warning:|error:)" | wc -l
}

# Run the cleanup
cleanup_warnings