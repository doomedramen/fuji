#!/bin/bash
# Ensure devcontainer is running before executing commands
# This script checks if the devcontainer is running and starts it if needed

set -e

# Check if devcontainer is running
if devcontainer exec --workspace-folder . echo "alive" &>/dev/null; then
    # Container is already running
    exit 0
fi

echo "Devcontainer is not running. Starting it now..."
echo "This may take 20-30 seconds..."

# Start the devcontainer
devcontainer up --workspace-folder .

# Verify it started successfully
if devcontainer exec --workspace-folder . echo "alive" &>/dev/null; then
    echo "✓ Devcontainer started successfully"
    exit 0
else
    echo "✗ Failed to start devcontainer"
    exit 1
fi
