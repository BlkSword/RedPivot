#!/bin/bash
# Build script for RedPivot

VERSION=${VERSION:-"dev"}
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.version=${VERSION}"

echo "Building RedPivot ${VERSION}..."

# Create output directory
mkdir -p bin

# Build server
echo "Building redd (server)..."
CGO_ENABLED=0 go build -ldflags "${LDFLAGS}" -o bin/redd ./cmd/redd

# Build client
echo "Building redctl (client)..."
CGO_ENABLED=0 go build -ldflags "${LDFLAGS}" -o bin/redctl ./cmd/redctl

echo "Build complete!"
echo "Binaries:"
ls -la bin/
