# Unwrap() Call Analysis for src/daemon/mod.rs

## Summary
Found **13 unwrap() calls** and **16 unwrap_or() calls** in daemon/mod.rs (not 75+ as initially estimated).

## Categorization

### 1. Critical unwrap() calls (will panic on failure)
These calls will crash the daemon if they fail:

#### A. Config/State Management (7 calls)
- Line 373: `get_mount_mut(&mount_id).unwrap()` - Mount status update
- Line 383: `get_mount_mut(&mount_id).unwrap()` - Mount status update
- Line 700: `get_mount_mut(&mount_id).unwrap()` - Mount status update
- Line 814: `get_mount_mut(&mount.id).unwrap()` - Mount status update
- Line 827: `get_mount_mut(&mount.id).unwrap()` - Mount status update
- Line 864: `get_mount_mut(&mount.id).unwrap()` - Mount status update
- Line 874: `get_mount_mut(&mount.id).unwrap()` - Mount status update
- Line 935: `get_mount_mut(&mount.id).unwrap()` - Mount status update
- Line 945: `get_mount_mut(&mount.id).unwrap()` - Mount status update

**Risk**: HIGH - These will panic if the mount is not found, which could happen during race conditions or if the mount was removed.

#### B. Regex Compilation (4 calls)
- Line 458: `regex::Regex::new("^$").unwrap()` - Fallback regex
- Line 479: `regex::Regex::new("^$").unwrap()` - Fallback regex
- Line 561: `regex::Regex::new("^$").unwrap()` - Fallback regex
- Line 586: `regex::Regex::new("^$").unwrap()` - Fallback regex

**Risk**: LOW - These are simple, hardcoded regex patterns that shouldn't fail.

### 2. Non-critical unwrap_or() calls (have defaults)
These provide default values and won't panic:

#### A. Protocol Parsing (9 calls)
- Lines 179, 309, 418, 601, 677, 806, 845, 921: `url.split("://").next().unwrap_or("")`
- **Risk**: LOW - Safe fallback to empty string

#### B. Error Handling (1 call)
- Line 857: `last_error.unwrap_or_else(|| "Unknown".to_string())`
- **Risk**: LOW - Safe fallback to "Unknown"

#### C. Optional Values (6 calls)
- Line 486: `monitor.get_health_score(&mount.id).await.unwrap_or(0)`
- Lines 456, 477, 559, 584: `regex::Regex::new(...).unwrap_or_else(|_| regex::Regex::new("^$").unwrap())`
- **Risk**: LOW - All have reasonable defaults

## Recommended Priority for Replacement

### Priority 1 (HIGH) - Critical State Management
All `get_mount_mut().unwrap()` calls should be replaced first as they can cause daemon crashes.

### Priority 2 (MEDIUM) - Regex Compilation
Replace fallback regex compilation with compiled static regexes to avoid unnecessary compilation.

### Priority 3 (LOW) - Protocol Parsing
The `unwrap_or("")` calls are already safe but could be made more explicit.

## Error Types Needed

1. **MountNotFoundError** - For when a mount ID is not found
2. **ConfigurationError** - For config-related failures
3. **RegexCompilationError** - For regex compilation failures
4. **StateError** - For general state management errors

## Implementation Strategy

1. Create custom error types using thiserror
2. Replace unwrap() calls with proper error propagation
3. Add logging for error context
4. Use expect() only for truly unrecoverable errors with clear messages