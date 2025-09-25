.PHONY: help build run test clean proto docker docker-compose dev init-db db-setup db-reset dev-setup init-postgresql

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
	@echo "  init-db        - Initialize MongoDB database"
	@echo "  init-postgresql - Initialize PostgreSQL database for Keycloak"
	@echo "  db-setup       - Setup databases with Docker Compose"
	@echo "  db-reset       - Reset database (drop and recreate)"
	@echo "  dev-setup      - Full development environment setup"

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

# Database initialization targets
init-db:
	@echo "Initializing MongoDB database..."
	@if command -v mongosh >/dev/null 2>&1; then \
		./scripts/init-mongodb.sh; \
	else \
		echo "❌ mongosh not found. Please install MongoDB Shell:"; \
		echo "   macOS: brew install mongosh"; \
		echo "   Ubuntu: https://docs.mongodb.com/mongodb-shell/install/"; \
		echo "   Or use Docker: docker run --rm -it --network host mongo:7.0 mongosh"; \
		exit 1; \
	fi

# Setup database with Docker Compose
db-setup:
	@echo "Setting up databases with Docker Compose..."
	@echo "Starting MongoDB and PostgreSQL containers..."
	docker-compose up -d mongodb postgresql
	@echo "Waiting for databases to be ready..."
	@sleep 15
	@echo "Initializing MongoDB database..."
	@MONGO_HOST=localhost MONGO_PORT=27017 MONGO_DATABASE=biarbala ./scripts/init-mongodb.sh
	@echo "Initializing PostgreSQL database..."
	@POSTGRES_HOST=localhost POSTGRES_PORT=5432 POSTGRES_DATABASE=keycloak POSTGRES_USER=keycloak POSTGRES_PASSWORD=keycloak ./scripts/init-postgresql.sh

# Reset database (drop and recreate)
db-reset:
	@echo "⚠️  WARNING: This will drop all data in the biarbala database!"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ] || exit 1
	@echo "Dropping database..."
	@if command -v mongosh >/dev/null 2>&1; then \
		mongosh mongodb://localhost:27017/biarbala --eval "db.dropDatabase()" --quiet; \
		echo "Database dropped. Reinitializing..."; \
		./scripts/init-mongodb.sh; \
	else \
		echo "❌ mongosh not found. Please install MongoDB Shell or use Docker:"; \
		echo "   docker run --rm -it --network host mongo:7.0 mongosh mongodb://localhost:27017/biarbala --eval 'db.dropDatabase()'"; \
		exit 1; \
	fi

# Full development setup
# Initialize PostgreSQL database
init-postgresql:
	@echo "Initializing PostgreSQL database for Keycloak..."
	@if command -v psql >/dev/null 2>&1; then \
		./scripts/init-postgresql.sh; \
	else \
		echo "❌ psql not found. Please install PostgreSQL client:"; \
		echo "   macOS: brew install postgresql"; \
		echo "   Ubuntu: sudo apt-get install postgresql-client"; \
		echo "   Or use Docker: docker run --rm -it --network host postgres:15 psql"; \
		exit 1; \
	fi

dev-setup: deps proto dirs db-setup
	@echo "Development environment setup complete!"
	@echo "Run 'make dev' to start the application in development mode"
