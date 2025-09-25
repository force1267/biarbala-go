#!/bin/bash

# MongoDB Initialization Script for Biarbala
# This script creates the necessary collections and indexes for the Biarbala application

set -e

# Configuration
MONGO_HOST=${MONGO_HOST:-localhost}
MONGO_PORT=${MONGO_PORT:-27017}
MONGO_DATABASE=${MONGO_DATABASE:-biarbala}
MONGO_URI="mongodb://${MONGO_HOST}:${MONGO_PORT}/${MONGO_DATABASE}"

echo "Initializing MongoDB for Biarbala..."
echo "Host: ${MONGO_HOST}:${MONGO_PORT}"
echo "Database: ${MONGO_DATABASE}"

# Function to execute MongoDB commands
execute_mongo_command() {
    local command="$1"
    local description="$2"
    
    echo "  ${description}..."
    
    if ! mongosh "${MONGO_URI}" --eval "${command}" --quiet; then
        echo "  ❌ Failed: ${description}"
        return 1
    else
        echo "  ✅ Success: ${description}"
    fi
}

# Wait for MongoDB to be ready
echo "Waiting for MongoDB to be ready..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if mongosh "${MONGO_URI}" --eval "db.runCommand('ping')" --quiet > /dev/null 2>&1; then
        echo "✅ MongoDB is ready!"
        break
    fi
    
    echo "  Attempt ${attempt}/${max_attempts}: MongoDB not ready yet, waiting..."
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -gt $max_attempts ]; then
    echo "❌ MongoDB failed to become ready after ${max_attempts} attempts"
    exit 1
fi

# Create collections and indexes
echo "Creating collections and indexes..."

# Projects collection
execute_mongo_command "
db.createCollection('projects', {
    validator: {
        \$jsonSchema: {
            bsonType: 'object',
            required: ['project_id', 'project_name', 'access_password', 'project_url', 'status'],
            properties: {
                project_id: { bsonType: 'string' },
                project_name: { bsonType: 'string' },
                user_id: { bsonType: 'string' },
                access_password: { bsonType: 'string' },
                project_url: { bsonType: 'string' },
                status: { bsonType: 'string' },
                file_size: { bsonType: 'long' },
                file_format: { bsonType: 'string' },
                domain: { bsonType: 'string' },
                is_custom_domain: { bsonType: 'bool' },
                domain_verified: { bsonType: 'bool' },
                created_at: { bsonType: 'date' },
                updated_at: { bsonType: 'date' }
            }
        }
    }
})
" "Creating projects collection"

# Project metrics collection
execute_mongo_command "
db.createCollection('project_metrics', {
    validator: {
        \$jsonSchema: {
            bsonType: 'object',
            required: ['project_id', 'total_requests', 'total_bandwidth_bytes', 'unique_visitors'],
            properties: {
                project_id: { bsonType: 'string' },
                total_requests: { bsonType: 'long' },
                total_bandwidth_bytes: { bsonType: 'long' },
                unique_visitors: { bsonType: 'long' },
                last_accessed: { bsonType: 'date' },
                updated_at: { bsonType: 'date' },
                daily_metrics: {
                    bsonType: 'array',
                    items: {
                        bsonType: 'object',
                        properties: {
                            date: { bsonType: 'date' },
                            requests: { bsonType: 'long' },
                            bandwidth_bytes: { bsonType: 'long' },
                            unique_visitors: { bsonType: 'long' }
                        }
                    }
                }
            }
        }
    }
})
" "Creating project_metrics collection"

# Domain verifications collection
execute_mongo_command "
db.createCollection('domain_verifications', {
    validator: {
        \$jsonSchema: {
            bsonType: 'object',
            required: ['project_id', 'domain', 'txt_record', 'verified'],
            properties: {
                project_id: { bsonType: 'string' },
                domain: { bsonType: 'string' },
                txt_record: { bsonType: 'string' },
                verified: { bsonType: 'bool' },
                created_at: { bsonType: 'date' },
                expires_at: { bsonType: 'date' },
                verified_at: { bsonType: 'date' }
            }
        }
    }
})
" "Creating domain_verifications collection"

# Create indexes for better performance
echo "Creating indexes..."

# Projects indexes
execute_mongo_command "
db.projects.createIndex({ 'project_id': 1 }, { unique: true })
" "Creating unique index on projects.project_id"

execute_mongo_command "
db.projects.createIndex({ 'user_id': 1 })
" "Creating index on projects.user_id"

execute_mongo_command "
db.projects.createIndex({ 'domain': 1 }, { unique: true, sparse: true })
" "Creating unique index on projects.domain"

execute_mongo_command "
db.projects.createIndex({ 'created_at': -1 })
" "Creating index on projects.created_at"

execute_mongo_command "
db.projects.createIndex({ 'status': 1 })
" "Creating index on projects.status"

# Project metrics indexes
execute_mongo_command "
db.project_metrics.createIndex({ 'project_id': 1 }, { unique: true })
" "Creating unique index on project_metrics.project_id"

execute_mongo_command "
db.project_metrics.createIndex({ 'last_accessed': -1 })
" "Creating index on project_metrics.last_accessed"

execute_mongo_command "
db.project_metrics.createIndex({ 'updated_at': -1 })
" "Creating index on project_metrics.updated_at"

# Domain verifications indexes
execute_mongo_command "
db.domain_verifications.createIndex({ 'project_id': 1, 'domain': 1 }, { unique: true })
" "Creating unique compound index on domain_verifications"

execute_mongo_command "
db.domain_verifications.createIndex({ 'domain': 1 })
" "Creating index on domain_verifications.domain"

execute_mongo_command "
db.domain_verifications.createIndex({ 'expires_at': 1 }, { expireAfterSeconds: 0 })
" "Creating TTL index on domain_verifications.expires_at"

execute_mongo_command "
db.domain_verifications.createIndex({ 'verified': 1 })
" "Creating index on domain_verifications.verified"

# Create a sample project for testing (optional)
if [ "${CREATE_SAMPLE_PROJECT:-false}" = "true" ]; then
    echo "Creating sample project..."
    execute_mongo_command "
    db.projects.insertOne({
        project_id: 'sample-project-001',
        project_name: 'Sample Project',
        user_id: 'sample-user',
        access_password: 'sample123',
        project_url: '/projects/sample-project-001',
        domain: 'sample-project.biarbala.ir',
        is_custom_domain: false,
        domain_verified: true,
        status: 'active',
        file_size: 1024,
        file_format: 'zip',
        settings: {},
        created_at: new Date(),
        updated_at: new Date()
    })
    " "Creating sample project"
    
    execute_mongo_command "
    db.project_metrics.insertOne({
        project_id: 'sample-project-001',
        total_requests: 0,
        total_bandwidth_bytes: 0,
        unique_visitors: 0,
        last_accessed: new Date(),
        daily_metrics: [],
        updated_at: new Date()
    })
    " "Creating sample project metrics"
fi

# Display collection statistics
echo "Database initialization completed!"
echo ""
echo "Collection statistics:"
mongosh "${MONGO_URI}" --eval "
print('Projects:', db.projects.countDocuments());
print('Project Metrics:', db.project_metrics.countDocuments());
print('Domain Verifications:', db.domain_verifications.countDocuments());
" --quiet

echo ""
echo "✅ MongoDB initialization completed successfully!"
echo "Database: ${MONGO_DATABASE}"
echo "Collections created: projects, project_metrics, domain_verifications"
echo "Indexes created: Multiple indexes for optimal performance"
