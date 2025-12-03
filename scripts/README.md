# Fuji Scripts

This directory contains various utility scripts for the Fuji project.

## cleanup-warnings.rs

A comprehensive Rust script that analyzes cargo check output and generates automatic fixes for various types of warnings.

### Features

The script identifies and suggests fixes for:

- **Unused imports** - Removes unused imports from use statements
- **Unused variables** - Prefixes unused variables with underscores
- **Unused fields** - Prefixes unused struct fields with underscores
- **Dead code** - Adds `#[allow(dead_code)]` attributes to unused functions, methods, structs, enums, and traits
- **Unused assignments** - Prefixes variables in unused assignments with underscores
- **Unused mut** - Removes unnecessary `mut` keywords

### Usage

#### Run and Review
```bash
# Run the script to analyze warnings
cargo run --bin cleanup-warnings

# The script will:
# 1. Run cargo check on the project
# 2. Parse all warnings from src/ directory files only
# 3. Generate fix suggestions
# 4. Show a summary of findings
# 5. Export detailed analysis to warning_analysis.json
# 6. Ask for confirmation before applying fixes
```

#### Manual Execution
```bash
# Compile and run directly
cargo build --bin cleanup-warnings
./target/debug/cleanup-warnings

# Or run as rust-script (if installed)
rust-script scripts/cleanup-warnings.rs
```

### Output

The script provides:

1. **Console Summary** - Overview of warnings found and fixes generated
2. **Sample Fixes** - First 10 fix suggestions with before/after comparison
3. **JSON Export** - Complete analysis saved to `warning_analysis.json`

#### Example Output
```
=== Warning Analysis Summary ===

Warning Types Found:
  UnusedVariable: 19
  UnusedImport: 10
  UnusedFunction: 7
  ...

Top Files with Warnings:
  src/daemon/mod.rs: 7 warnings
  src/monitoring/health_checks.rs: 7 warnings
  ...

=== Fix Suggestions ===
Total fix suggestions: 49

Sample Fixes:

1. src/config/mod.rs:11
   Type: RemoveImport
   Confidence: 0.9
   Original: use std::path::{Path, PathBuf};
   Fixed:    use std::path::{PathBuf}
```

### Fix Types

The script generates different types of fixes:

- **RemoveImport** - Removes specific imports from multi-item use statements
- **RemoveLine** - Completely removes entire import lines
- **PrefixUnderscore** - Adds underscore prefix to unused variables/fields
- **AddAllowDeadCode** - Adds `#[allow(dead_code)]` attribute to unused items

### Safety Features

- **Source Directory Only** - Only processes files in `src/` directory
- **Compilation Check** - Stops if there are compilation errors
- **Interactive Mode** - Requires user confirmation before applying fixes
- **Backup Creation** - Changes are applied with review opportunity
- **JSON Export** - Complete audit trail of all suggested changes

### Edge Case Handling

The script is designed to handle complex scenarios:

- **Complex Import Patterns** - Handles nested use statements and re-exports
- **Macro Contexts** - Recognizes imports used in macro definitions
- **Conditional Compilation** - Handles `#[cfg]` attributes
- **Documentation Comments** - Preserves imports used in doc comments
- **Attribute Usage** - Identifies imports used in derive attributes

### Dependencies

The script uses these Rust crates (already in Fuji's dependencies):
- `regex` - For parsing warning patterns
- `serde` - For JSON serialization
- `serde_json` - For export functionality

### Configuration

The script focuses on:
- `src/` directory only (ignores `target/`, `tests/`, etc.)
- All `.rs` files within the source tree
- Standard cargo check output format

### Integration with CI/CD

This script can be integrated into development workflows:

```bash
# In CI pipeline - check only (no fixes)
cargo run --bin cleanup-warnings | grep "Total fix suggestions:" && exit 1

# Pre-commit hook - check for new warnings
./scripts/cleanup-warnings.rs
```

### Troubleshooting

1. **No warnings found** - Make sure there are actually warnings in the source code
2. **Compilation errors** - Fix compilation errors first, then run the script
3. **Permission denied** - Ensure write permissions to source files
4. **Missing dependencies** - Run `cargo build` to ensure all dependencies are available

### Examples

The script correctly handles various warning patterns:

#### Unused Imports
```rust
// Before
use std::path::{Path, PathBuf, Display};

// After
use std::path::{PathBuf, Display};
```

#### Unused Variables
```rust
// Before
fn example() {
    let unused_var = 42;
}

// After
fn example() {
    let _unused_var = 42;
}
```

#### Dead Code
```rust
// Before
pub fn unused_function() -> bool {
    true
}

// After
#[allow(dead_code)]
pub fn unused_function() -> bool {
    true
}
```

### Contributing

When modifying the script:
1. Add comprehensive tests for new warning types
2. Update this README with new features
3. Test on various codebases to ensure robustness
4. Preserve the safety-first approach (confirmation before changes)