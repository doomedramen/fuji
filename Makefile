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
	@echo "Waiting for NFS server (up to 120 seconds)..."
	@nfs_ready=0; \
	for i in $$(seq 1 120); do \
		if docker compose exec -T nfs-server showmount -e localhost 2>/dev/null; then \
			echo "NFS server is ready after $$i seconds"; \
			nfs_ready=1; \
			break; \
		fi; \
		sleep 1; \
	done; \
	if [ "$$nfs_ready" != "1" ]; then \
		echo "ERROR: NFS server failed to start within 120 seconds"; \
		docker compose logs nfs-server; \
		docker compose down -v; \
		exit 1; \
	fi
	@echo "Waiting for SMB server (up to 120 seconds)..."
	@smb_ready=0; \
	for i in $$(seq 1 120); do \
		if docker compose exec -T smb-server smbclient -L localhost -N 2>/dev/null; then \
			echo "SMB server is ready after $$i seconds"; \
			smb_ready=1; \
			break; \
		fi; \
		sleep 1; \
	done; \
	if [ "$$smb_ready" != "1" ]; then \
		echo "ERROR: SMB server failed to start within 120 seconds"; \
		docker compose logs smb-server; \
		docker compose down -v; \
		exit 1; \
	fi
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
	@echo "Current version: v$$($(MAKE) -s get-version)"

# Get version from Cargo.toml
get-version:
	@cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | cut -d'"' -f4

# Format code
fmt:
	cargo fmt --all

# Run clippy lints
clippy:
	cargo clippy --all-targets --all-features

# Run full CI checks locally
ci: fmt clippy test
	@echo "All CI checks passed!"

# Create a tagged release using version from Cargo.toml
release: check-version build
	@echo "Creating a new release..."
	@version=$$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | cut -d'"' -f4); \
	echo "Release version: v$$version"; \
	read -p "Continue? (y/N) " confirm && [ "$$confirm" = "y" ] || exit 1; \
	git tag -a "v$$version" -m "Release v$$version" && \
	echo "Created tag v$$version" && \
	echo "Pushing tag to origin..." && \
	git push origin v$$version && \
	echo "Release v$$version pushed successfully!"

# Create a tagged release without confirmation (for automation)
release-auto: check-version build
	@echo "Creating a new release (auto)..."
	@version=$$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | cut -d'"' -f4); \
	echo "Release version: v$$version"; \
	git tag -a "v$$version" -m "Release v$$version" && \
	echo "Created tag v$$version" && \
	echo "Pushing tag to origin..." && \
	git push origin v$$version && \
	echo "Release v$$version pushed successfully!"