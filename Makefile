.PHONY: help build test clean install release check-version

# Default target
help:
	@echo "Available commands:"
	@echo "  build      - Build the project"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install the project"
	@echo "  release    - Create a tagged release (bumps version by 0.0.1)"
	@echo "  check-version - Check current version"

# Build the project
build:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Install the project
install: build
	cargo install --path .

# Check current version
check-version:
	@echo "Current version: $$(git describe --tags --abbrev=0 2>/dev/null || echo '0.0.0')"

# Create a tagged release (bumps version by 0.0.1)
release: check-version
	@echo "Creating a new release..."
	@current_version=$$(git describe --tags --abbrev=0 2>/dev/null || echo '0.0.0'); \
	new_version=$$(echo $$current_version | awk -F. '{printf "%d.%d.%d", $$1, $$2, $$3+1}'); \
	echo "Bumping version from $$current_version to $$new_version"; \
	read -p "Continue? (y/N) " confirm && [ "$$confirm" = "y" ] || exit 1; \
	cargo build --release && \
	echo "Version $$new_version" > VERSION && \
	git add VERSION && \
	git commit -m "chore: bump version to $$new_version" && \
	git tag -a "v$$new_version" -m "Release v$$new_version" && \
	echo "Created tag v$$new_version" && \
	echo "Run 'git push origin v$$new_version' to push the release"