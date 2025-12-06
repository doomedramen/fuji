# Release Process

This document describes how to release new versions of Fuji.

## Prerequisites

### One-time Setup

1. **Create the `HOMEBREW_TAP_TOKEN` secret** in the fuji repository:
   - Go to [GitHub Personal Access Tokens](https://github.com/settings/tokens)
   - Click "Generate new token (classic)"
   - Name: `Fuji Homebrew Tap Update`
   - Scopes: Select `repo` (Full control of private repositories)
   - Generate and copy the token
   - Go to [fuji repository secrets](https://github.com/DoomedRamen/fuji/settings/secrets/actions)
   - Click "New repository secret"
   - Name: `HOMEBREW_TAP_TOKEN`
   - Value: paste the token

2. **Set up the homebrew-fuji repository**:
   - Copy the contents of `homebrew-tap-files/` to the `doomedramen/homebrew-fuji` repository:
     - `Formula/fuji.rb`
     - `.github/workflows/update-formula.yml`
     - `README.md`

## Creating a Release

### 1. Update the version

Edit `Cargo.toml` and update the version number:

```toml
[package]
version = "X.Y.Z"
```

### 2. Commit the version bump

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: bump version to X.Y.Z"
git push origin master
```

### 3. Create and push the tag

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

### 4. Monitor the release

1. Go to [Actions](https://github.com/DoomedRamen/fuji/actions)
2. Watch the "Release" workflow
3. Once complete, check [Releases](https://github.com/DoomedRamen/fuji/releases)

### 5. Verify Homebrew update

Check the [homebrew-fuji repository](https://github.com/doomedramen/homebrew-fuji) for the auto-commit.

Test installation:

```bash
brew tap doomedramen/fuji
brew install fuji
# or if already installed:
brew update && brew upgrade fuji
```

## Pre-release Versions

For testing, create a pre-release tag with a hyphen (e.g., `v0.2.0-beta.1`):

```bash
git tag -a v0.2.0-beta.1 -m "Pre-release v0.2.0-beta.1"
git push origin v0.2.0-beta.1
```

Pre-releases:
- Are marked as "Pre-release" on GitHub
- Do NOT trigger Homebrew formula updates
- Can be deleted after testing

## Build Targets

The release workflow builds binaries for:

| Target | Runner | Description |
|--------|--------|-------------|
| `x86_64-unknown-linux-gnu` | ubuntu-latest | Linux Intel/AMD 64-bit |
| `aarch64-unknown-linux-gnu` | ubuntu-latest | Linux ARM 64-bit |
| `x86_64-apple-darwin` | macos-13 | macOS Intel |
| `aarch64-apple-darwin` | macos-14 | macOS Apple Silicon |

## Troubleshooting

### Release workflow failed

1. Check the [Actions logs](https://github.com/DoomedRamen/fuji/actions)
2. Common issues:
   - Compilation errors: fix and create a new tag
   - Missing secret: ensure `HOMEBREW_TAP_TOKEN` is set

### Homebrew formula not updated

1. Check that the tag does NOT contain a hyphen (pre-releases don't update Homebrew)
2. Verify `HOMEBREW_TAP_TOKEN` secret is set and valid
3. Check [homebrew-fuji Actions](https://github.com/doomedramen/homebrew-fuji/actions) for errors

### Manual Homebrew update

If automatic update fails, trigger manually:

1. Go to [homebrew-fuji Actions](https://github.com/doomedramen/homebrew-fuji/actions)
2. Click "Update Formula"
3. Click "Run workflow"
4. Enter the version (without `v` prefix)
