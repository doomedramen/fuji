.PHONY: help build build-dev test test-unit test-security test-integration clean install release check-version fmt clippy ci

# Default target
help:
	@echo "Available commands:"
	@echo "  build          - Build the project in release mode"
	@echo "  build-dev      - Build the project in development mode"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-security  - Run security tests only"
	@echo "  test-integration - Run integration tests (requires Docker)"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install the project"
	@echo "  release        - Create a tagged release (bumps version by 0.0.1)"
	@echo "  check-version  - Check current version"
	@echo "  fmt            - Format code"
	@echo "  clippy         - Run clippy lints"
	@echo "  ci             - Run full CI checks locally"

# Build the project in release mode
build:
	cargo build --release

# Build the project in development mode
build-dev:
	cargo build

# Run all tests
test: test-unit test-security

# Run unit tests only
test-unit:
	cargo test --all-features --lib --bins --no-fail-fast

# Run security tests only
test-security:
	cargo test security_* --all-features --no-fail-fast

# Run integration tests (requires Docker services)
test-integration:
	@echo "Starting Docker services..."
	docker compose up -d nfs-server smb-server
	@echo "Waiting for services to be ready..."
	@for i in $$(seq 1 30); do \
		if docker compose exec -T nfs-server showmount -e localhost 2>/dev/null; then \
			echo "NFS server is ready"; break; \
		fi; \
		echo "Waiting for NFS server... ($$i/30)"; sleep 5; \
	done
	@for i in $$(seq 1 30); do \
		if docker compose exec -T smb-server smbclient -L localhost -N 2>/dev/null; then \
			echo "SMB server is ready"; break; \
		fi; \
		echo "Waiting for SMB server... ($$i/30)"; sleep 5; \
	done
	@echo "Running integration tests..."
	cargo test integration_tests --all-features
	@echo "Cleaning up Docker services..."
	docker compose down -v

# Clean build artifacts
clean:
	cargo clean

# Install the project
install: build
	cargo install --path .

# Check current version
check-version:
	@echo "Current version: $$(git describe --tags --abbrev=0 2>/dev/null || echo '0.0.0')"

# Format code
fmt:
	cargo fmt --all

# Run clippy lints
clippy:
	cargo clippy --all-targets --all-features

# Run full CI checks locally
ci: fmt clippy test
	@echo "All CI checks passed!"

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