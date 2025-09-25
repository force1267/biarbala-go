# Scripts Directory

This directory contains utility scripts for the Biarbala project.

## Database Initialization

### `init-mongodb.sh`

Initializes the MongoDB database for the Biarbala application.

### `init-postgresql.sh`

Initializes the PostgreSQL database for Keycloak authentication service.

#### Features

- Creates the Keycloak database if it doesn't exist
- Creates the Keycloak user with proper permissions
- Enables required PostgreSQL extensions (uuid-ossp)
- Sets up basic test table for connection verification
- Provides database connection information

#### Usage

```bash
# Using environment variables
POSTGRES_HOST=localhost POSTGRES_PORT=5432 POSTGRES_DATABASE=keycloak POSTGRES_USER=keycloak POSTGRES_PASSWORD=keycloak ./scripts/init-postgresql.sh

# Using default values
./scripts/init-postgresql.sh
```

#### Environment Variables

- `POSTGRES_HOST`: PostgreSQL host (default: localhost)
- `POSTGRES_PORT`: PostgreSQL port (default: 5432)
- `POSTGRES_DATABASE`: Database name (default: keycloak)
- `POSTGRES_USER`: Database user (default: keycloak)
- `POSTGRES_PASSWORD`: Database password (default: keycloak)

#### Requirements

- PostgreSQL client (`psql`) must be installed
- PostgreSQL server must be running and accessible
- User must have permission to create databases and users

Initializes the MongoDB database with the necessary collections, indexes, and validation rules for the Biarbala application.

#### Features

- Creates collections: `projects`, `project_metrics`, `domain_verifications`
- Sets up proper validation schemas for data integrity
- Creates performance-optimized indexes
- Sets up TTL indexes for automatic cleanup
- Optional sample data creation

#### Usage

```bash
# Basic initialization
./scripts/init-mongodb.sh

# With custom MongoDB connection
MONGO_HOST=localhost MONGO_PORT=27017 MONGO_DATABASE=biarbala ./scripts/init-mongodb.sh

# With sample project creation
CREATE_SAMPLE_PROJECT=true ./scripts/init-mongodb.sh
```

#### Environment Variables

- `MONGO_HOST`: MongoDB host (default: localhost)
- `MONGO_PORT`: MongoDB port (default: 27017)
- `MONGO_DATABASE`: Database name (default: biarbala)
- `CREATE_SAMPLE_PROJECT`: Create sample project (default: false)

#### Requirements

- MongoDB Shell (`mongosh`) installed
- MongoDB server running and accessible
- Proper permissions to create collections and indexes

#### Collections Created

1. **projects**: Stores project information
   - Unique indexes on `project_id` and `domain`
   - Indexes on `user_id`, `created_at`, `status`

2. **project_metrics**: Stores usage metrics
   - Unique index on `project_id`
   - Indexes on `last_accessed`, `updated_at`

3. **domain_verifications**: Stores domain verification challenges
   - Unique compound index on `project_id` and `domain`
   - TTL index on `expires_at` for automatic cleanup
   - Indexes on `domain`, `verified`

#### Makefile Integration

The script is integrated with the Makefile for easy database management:

```bash
# Initialize database
make init-db

# Setup database with Docker Compose
make db-setup

# Reset database (drop and recreate)
make db-reset

# Full development setup
make dev-setup
```

### `generate-protos.sh`

Generates Go code from Protocol Buffer definitions using buf.

## Installation Requirements

### MongoDB Shell

**macOS:**
```bash
brew install mongosh
```

**Ubuntu/Debian:**
```bash
# Follow instructions at: https://docs.mongodb.com/mongodb-shell/install/
```

**Using Docker:**
```bash
# Run MongoDB shell in Docker
docker run --rm -it --network host mongo:7.0 mongosh
```

### buf (for protobuf generation)

```bash
# Install buf
go install github.com/bufbuild/buf/cmd/buf@latest
```
