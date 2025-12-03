#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up integration test environment...${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Build Fuji first
echo -e "${YELLOW}Building Fuji...${NC}"
cargo build --release

# Start test servers
echo -e "${YELLOW}Starting NFS and SMB servers...${NC}"
docker-compose up -d nfs-server smb-server

# Wait for servers to be healthy
echo -e "${YELLOW}Waiting for servers to be ready...${NC}"
timeout 60 bash -c 'until docker-compose exec -T nfs-server showmount -e localhost &> /dev/null; do sleep 1; done'
timeout 60 bash -c 'until docker-compose exec -T smb-server smbclient -L localhost -N &> /dev/null; do sleep 1; done'

# Check if servers are ready
if docker-compose ps | grep -q "unhealthy\|Exit"; then
    echo -e "${RED}Error: Test servers failed to start${NC}"
    docker-compose ps
    docker-compose logs
    exit 1
fi

echo -e "${GREEN}Test servers are ready${NC}"

# Run integration tests
echo -e "${YELLOW}Running integration tests...${NC}"
RUST_LOG=debug cargo test --test integration_tests -- --nocapture

# Cleanup
echo -e "${YELLOW}Cleaning up...${NC}"
docker-compose down -v

echo -e "${GREEN}All integration tests passed!${NC}"