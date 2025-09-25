#!/bin/bash
# PostgreSQL Initialization Script for Keycloak

# Default values
POSTGRES_HOST=${POSTGRES_HOST:-localhost}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DATABASE=${POSTGRES_DATABASE:-keycloak}
POSTGRES_USER=${POSTGRES_USER:-keycloak}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-keycloak}

echo "Initializing PostgreSQL database for Keycloak..."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
until pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" > /dev/null 2>&1; do
  echo "PostgreSQL is unavailable - sleeping"
  sleep 2
done

echo "PostgreSQL is ready. Initializing database '$POSTGRES_DATABASE'..."

# Set password for the user
export PGPASSWORD="$POSTGRES_PASSWORD"

# Create database if it doesn't exist
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres -c "CREATE DATABASE $POSTGRES_DATABASE;" 2>/dev/null || echo "Database $POSTGRES_DATABASE already exists"

# Create user if it doesn't exist
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres -c "CREATE USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';" 2>/dev/null || echo "User $POSTGRES_USER already exists"

# Grant privileges
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DATABASE TO $POSTGRES_USER;" 2>/dev/null || echo "Privileges already granted"

# Connect to the database and set up basic configuration
psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE" <<EOF
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create a simple table to test the connection
CREATE TABLE IF NOT EXISTS keycloak_test (
    id SERIAL PRIMARY KEY,
    test_data VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
INSERT INTO keycloak_test (test_data) VALUES ('Keycloak database initialized successfully') ON CONFLICT DO NOTHING;

-- Display database info
SELECT 'Database initialized successfully' as status;
SELECT current_database() as database_name;
SELECT current_user as user_name;
SELECT version() as postgresql_version;
EOF

if [ $? -eq 0 ]; then
    echo "✅ PostgreSQL database '$POSTGRES_DATABASE' initialized successfully!"
    echo "   Host: $POSTGRES_HOST"
    echo "   Port: $POSTGRES_PORT"
    echo "   Database: $POSTGRES_DATABASE"
    echo "   User: $POSTGRES_USER"
else
    echo "❌ Failed to initialize PostgreSQL database"
    exit 1
fi

# Unset password
unset PGPASSWORD

echo "PostgreSQL initialization complete."
