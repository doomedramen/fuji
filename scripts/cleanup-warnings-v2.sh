#!/bin/bash

# Improved script to fix common Rust compilation warnings
# This version uses more robust parsing patterns

set -e

echo "=== Fuji Cleanup Script for Rust Warnings v2 ==="
echo

# Function to remove unused import from a file
remove_unused_import() {
    local file="$1"
    local import="$2"

    echo "  - Removing unused import '$import' from $file"

    # Use a more robust sed approach to handle complex import patterns
    # First remove the import line entirely
    sed -i.tmp "/^use.*\<$import\>/d" "$file" 2>/dev/null || true

    # Clean up trailing commas and whitespace in use statements
    sed -i.tmp -e '/^use {/,/^use }/ {
        :a
        N
        s/use {$/use {/
        /}/
        ta
        s/use {$/use {/
        }$/
        t
    }' "$file" 2>/dev/null || true

    # Remove empty use blocks
    sed -i.tmp '/^use { *}$/d' "$file" 2>/dev/null || true

    # Remove temporary file if it exists
    rm -f "$file.tmp"
}

# Function to prefix unused variable with underscore
prefix_unused_var() {
    local file="$1"
    local var="$2"
    local line_num="$3"

    echo "  - Prefixing unused variable '$var' with underscore in $file:$line_num"

    # Replace the variable with prefixed version only (not partial matches)
    sed -i.tmp "${line_num}s/\<$var\>/_$var>/g" "$file"
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

    # Use a more careful approach to add the attribute
    awk -v '//' "$file" | \
    awk -v '^[[:space:]]*\/\/' \
        -v item_type="$item_type" \
        -v item_name="$item_name" '
        {
            # Found the line, add attribute before it
            print "#[allow(dead_code)]"
            print $0
            next
        }
        {
            print
        }
    ' > "$file.tmp" && \
    mv "$file.tmp" "$file" 2>/dev/null || true
}

# Function to remove cfg feature user
remove_cfg_user() {
    local file="$1"
    local line_num="$2"

    echo "  - Removing cfg(feature = \"user\") from $file:$line_num"

    # Comment out the problematic line
    sed -i.tmp "${line_num}s/^/\/\/ /" "$file"
    rm -f "$file.tmp"
}

# Function to prefix unused field with underscore
prefix_unused_field() {
    local file="$1"
    local field="$2"
    local line_num="$3"

    echo "  - Prefixing unused field '$field' with underscore in $file:$line_num"

    # Replace field with _field in struct definition
    sed -i.tmp "${line_num}s/\\<$field\\>/_$field/g" "$file"
    rm -f "$file.tmp"
}

# Function to remove 'useless' attribute comment
remove_useless_attr_comment() {
    local file="$1"
    local line_num="$2"

    echo "  - Removing 'useless' attribute comment in $file:$line_num"

    # Comment out the line with 'useless'
    sed -i.tmp "${line_num}s/^/\/\/ useless: /" "$file"
    rm -f "$file.tmp"
}

# Main cleanup function
cleanup_warnings() {
    echo "Analyzing compilation warnings..."
    echo

    # Create a temporary file to store parsing results
    echo "" > /tmp/warnings_parsed.txt

    # Parse warnings in detail
    cargo check 2>&1 | tee /tmp/cargo_check_output.txt | while IFS= read -r line; do
        # Skip lines that don't contain warnings
        if [[ ! "$line" =~ (warning|error) ]]; then
            continue
        fi

        # Extract file, line number, and warning details
        if [[ $line =~ ^(.+\.rs):([0-9]+):(.*)$ ]]; then
            file="${BASH_REMATCH[1]}"
            line="${BASH_REMATCH[2]}"
            message="${BASH_REMATCH[3]}"

            # Extract specific warning type
            if [[ $message =~ unused\ import:\ `([^`]+)` ]]; then
                echo "$file|$line|unused_import|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ unused\ variable:\ ([^ ]+) ]]; then
                echo "$file|$line|unused_var|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ variable\ does\ not\ need\ to\ be\ mutable ]]; then
                echo "$file|$line|unnecessary_mut|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ value\ assigned\ to\ `([^`]+)`\ is\ never\ read ]]; then
                echo "$file|$line|unused_assign|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ function\ `([^`]+)`\ is\ never\ used ]]; then
                echo "$file|$line|dead_code|fn|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ struct\ `([^`]+)`\ is\ never\ constructed ]]; then
                echo "$file|$line|dead_code|struct|${BASH_REMATCH[1]}" >> /tmp/warnings.txt
            elif [[ $message =~ multiple\ associated\ items\ are\ never\ used ]]; then
                echo "$file|$line|dead_code|multi|${BASH_REMATCH[1]}" >> /tmp/warnings.txt
            elif [[ $message =~ field\ `([^`]+)`\ is\ never\ read ]]; then
                echo "$file|$line|unused_field|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ trait\ `([^`]+)`\ is\ never\ used ]]; then
                echo "$file|$line|dead_code|trait|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ enum\ `([^`]+)`\ is\ never\ used ]]; then
                echo "$file|$line|dead_code|enum|${BASH_REMATCH[1]}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ unexpected\ `cfg\ condition\ value:\ `user` ]]; then
                echo "$file|$line|cfg_user|${line_num}" >> /tmp/warnings_parsed.txt
            elif [[ $message =~ useless\ attribute ]]; then
                echo "$file|$line|useless_attr|${line_num}" >> /tmp/warnings_parsed.txt
            fi
        fi
    done

    # Process parsed warnings
    echo
    echo "=== Processing Parsed Warnings ==="

    # Track which files we've modified to avoid conflicts
    declare -A modified_files=()

    # Process each warning
    while IFS='|' read -r file_line_type var_line_num; do
        file="${file_line_parts[0]}"

        # Skip if we've already modified this file in a way that might conflict
        if [[ -n "${modified_files[$file]:-}" ]]; then
            # We've already modified this file, skip to avoid conflicts
            continue
        fi

        case "$var_line_type" in
            "unused_import")
                import="${var_line_parts[1]}"
                remove_unused_import "$file" "$import"
                modified_files["$file"]=1
                ;;
            "unused_var")
                var="${var_line_parts[1]}"
                line_num="${var_line_parts[2]}"
                prefix_unused_var "$file" "$var" "$line_num"
                modified_files["$file"]=1
                ;;
            "unnecessary_mut")
                var="${var_line_parts[1]}"
                line_num="${var_line_parts[2]}"
                remove_unnecessary_mut "$file" "$var" "$line_num"
                modified_files["$file"]=1
                ;;
            "unused_assign")
                var="${var_line_parts[1]}"
                prefix_unused_var "$file" "$var" "$line_num"
                modified_files["$file"]=1
                ;;
            "dead_code")
                item_type="${var_line_parts[1]}"
                case "$item_type" in
                    "fn") name="${var_line_parts[2]}" ;;
                    "struct") name="${var_line_parts[2]}" ;;
                    "enum") name="${var_line_parts[2]}" ;;
                    "trait") name="${var_line_parts[2]}" ;;
                    *) name="" ;;
                esac
                if [[ -n "$name" ]]; then
                    add_dead_code_allow "$file" "$item_type" "$name"
                    modified_files["$file"]=1
                fi
                ;;
            "cfg_user")
                line_num="${var_line_parts[1]}"
                remove_cfg_user "$file" "$line_num"
                modified_files["$file"]=1
                ;;
            "useless_attr")
                line_num="${var_line_parts[1]}"
                remove_useless_attr_comment "$file" "$line_num"
                modified_files["$file"]=1
                ;;
            "unused_field")
                field="${var_line_parts[1]}"
                line_num="${var_line_parts[2]}"
                prefix_unused_field "$file" "$field" "$line_num"
                modified_files["$file"]=1
                ;;
            "dead_code")
                item_type="${var_line_parts[1]}"
                # Special handling for "multiple associated items are never used"
                if [[ "$item_type" == "multi" ]]; then
                    # Add #[allow(dead_code)] to the impl block
                    impl_line=$(grep -n "impl " "$file" | head -1 | cut -d: -f1)
                    if [[ -n "$impl_line" ]]; then
                        echo "  - Adding #[allow(dead_code)] to impl block in $file:$impl_line"
                        sed -i.tmp "${impl_line}i/^/    #\[allow(dead_code)\]/" "$file" 2>/dev/null || true
                        rm -f "$file.tmp"
                    fi
                    modified_files["$file"]=1
                fi
                ;;
            *)
                echo "  - Unhandled warning type: $var_line_type"
                ;;
        esac
    done < /tmp/warnings_parsed.txt

    # Clean up
    rm -f /tmp/warnings_parsed.txt /tmp/cargo_check_output.txt

    echo
    echo "=== Cleanup Complete ==="
    echo
    echo "Running cargo check again to verify improvements..."

    # Count remaining warnings
    remaining=$(cargo check 2>&1 | grep -c "warning:" || echo "0")
    echo "Remaining warnings: $remaining"

    # Count errors (should be 0)
    errors=$(cargo check 2>&1 | grep -c "error:" || echo "0")
    echo "Errors: $errors"
}

# Run the cleanup
cleanup_warnings