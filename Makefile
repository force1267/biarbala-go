.PHONY: help build run test clean proto docker docker-compose dev

# Default target
help:
	@echo "Available targets:"
	@echo "  build         - Build the application"
	@echo "  run           - Run the application"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  proto         - Generate protobuf code"
	@echo "  docker        - Build Docker image"
	@echo "  docker-compose - Run with Docker Compose"
	@echo "  dev           - Run in development mode"

# Build the application
build: proto
	@echo "Building Biarbala..."
	go build -o bin/biarbala ./cmd/server

# Run the application
run: build
	@echo "Running Biarbala..."
	./bin/biarbala

# Run tests
test:
	@echo "Running tests..."
	go test ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -rf protos/gen/
	go clean

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	./scripts/generate-protos.sh

# Build Docker image
docker:
	@echo "Building Docker image..."
	docker build -t biarbala:latest .

# Run with Docker Compose
docker-compose:
	@echo "Starting with Docker Compose..."
	docker-compose up --build

# Development mode (with hot reload)
dev:
	@echo "Starting development mode..."
	@echo "Make sure to install air: go install github.com/cosmtrek/air@latest"
	air

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Setup development environment
setup: deps proto
	@echo "Setting up development environment..."
	mkdir -p uploads served temp
	@echo "Development environment ready!"

# Create directories
dirs:
	mkdir -p uploads served temp bin protos/gen
