#!/bin/bash

# Generate Go code from protobuf definitions using buf

set -e

echo "Generating protobuf code..."

# Check if buf is installed
if ! command -v buf &> /dev/null; then
    echo "buf is not installed. Installing..."
    go install github.com/bufbuild/buf/cmd/buf@latest
fi

# Generate Go code
buf generate

echo "Protobuf code generation completed successfully!"
