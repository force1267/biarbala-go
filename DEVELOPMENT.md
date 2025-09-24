# Biarbala Development Tracker

## Project Overview
Biarbala is a web server as a service platform similar to Netlify, Surge, and Vercel but with a focus on simplicity. Users can upload compressed static files and serve them as web pages without requiring accounts for public users.

## Core Requirements

### Functional Requirements
- **File Upload**: Users upload compressed files (tar, gzip, zip) containing static files
- **Static File Serving**: Serve uploaded static files as web pages
- **Standard Web Files Support**: Support for index.html, 404.html, {error_code}.html, public/, .well-known, robots.txt
- **Project-Based Access**: No account required for public users - return project ID and password on upload
- **User Account Support**: Optional user accounts for enhanced features
- **Usage Monitoring**: Monitor usage and provide metrics to users
- **Billing Preparation**: Codebase must be extensible for future billing implementation with exact usage monitoring

### Technical Requirements
- **Frontend**: Minimal frontend using HTMX, HTML, JS (no frameworks like React/Vue/Svelte)
- **Database**: MongoDB without ORMs - craft pipelines and queries in code
- **Caching**: Redis for caching, rate-limiting, and related usages
- **gRPC**: Web-gRPC and protobuf for API communication
- **Monitoring**: Prometheus for metrics
- **Logging**: Logrus for structured logging
- **Configuration**: Viper for configuration management

### Architecture Requirements
- **Go Version**: 1.25.0
- **Project Structure**: Follow Go best practices with cmd, pkg, config, protos, scripts, dockerfile, docker-compose, deployment
- **Context Usage**: Always use context objects where applicable
- **gRPC Server**: With reflections enabled and web-gRPC support

## Implementation Status

### Phase 1: Project Setup ✅
- [x] Development tracking file created
- [x] Go project initialization with version 1.25.0
- [x] Project structure setup (cmd, pkg, config, protos, scripts, deployment)
- [x] Dependencies configuration (Viper, Logrus, Prometheus, MongoDB, Redis, gRPC)

### Phase 2: Core Infrastructure ✅
- [x] Proto service definition (BiarbalaService with upload, project management, metrics)
- [x] Buf configuration for proto linting/compilation
- [x] gRPC server implementation with reflections and web-gRPC support
- [x] Configuration management with Viper
- [x] Logging setup with Logrus
- [x] Metrics setup with Prometheus
- [x] Docker configuration
- [x] Docker Compose setup
- [x] Kubernetes deployment configurations

### Phase 3: Biarbala Core Features ✅
- [x] File upload handling (tar, gzip, zip support) - Implemented in pkg/upload/
- [x] Static file serving (index.html, 404.html, error pages, public/, .well-known, robots.txt) - Implemented in pkg/web/
- [x] Project management (create, read, update, delete projects) - Implemented in pkg/storage/ and pkg/server/
- [x] User account system (optional accounts, project-based access) - Implemented with project-based access
- [x] Usage monitoring and metrics collection - Implemented in pkg/metrics/ and pkg/storage/
- [x] Frontend implementation (HTMX, HTML, JS) - Implemented in frontend/

### Phase 4: Production Readiness
- [ ] Testing implementation
- [ ] Performance optimization
- [ ] Security hardening
- [ ] Monitoring and alerting setup

## Technical Decisions

### Dependencies
- **Configuration**: Viper
- **Logging**: Logrus
- **Metrics**: Prometheus
- **Frontend**: HTMX only
- **Database**: MongoDB (no ORM)
- **Cache**: Redis
- **API**: gRPC with protobuf

### Project Structure
```
biarbala/
├── cmd/                    # Application entry points
├── pkg/                    # Library code
├── config/                 # Configuration files
├── protos/                 # Protocol buffer definitions
├── scripts/                # Build and utility scripts
├── dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose setup
├── deployment/             # Deployment configurations
└── DEVELOPMENT.md          # This file
```

## Implementation Details

### Core Services Implemented

#### 1. File Upload Service (`pkg/upload/upload.go`)
- Supports tar, gzip, and zip file formats
- Extracts files to project-specific directories
- Validates extracted files for security
- Generates unique project IDs and access passwords
- Records upload metrics

#### 2. Static File Serving (`pkg/web/web.go`)
- Serves static files from project directories
- Handles index.html, 404.html, and error pages
- Supports standard web files (public/, .well-known, robots.txt)
- Implements proper caching headers
- Records access metrics for billing preparation

#### 3. Project Management (`pkg/storage/mongodb.go`)
- MongoDB-based storage without ORM
- Project CRUD operations
- Metrics tracking and storage
- Access control with project passwords
- Pagination support for project listing

#### 4. gRPC Service (`pkg/server/biarbala_service.go`)
- Complete BiarbalaService implementation
- Upload, get, update, delete, list operations
- Project metrics retrieval
- Health check endpoint
- Proper error handling and validation

#### 5. Configuration Management (`pkg/config/config.go`)
- Viper-based configuration
- Environment variable support
- Default values for all settings
- Structured configuration types

#### 6. Logging (`pkg/logger/logger.go`)
- Logrus-based structured logging
- Configurable log levels and formats
- Request ID tracking
- Error context preservation

#### 7. Metrics (`pkg/metrics/metrics.go`)
- Prometheus metrics collection
- HTTP, gRPC, file upload, and project metrics
- Cache hit/miss tracking
- Database and Redis connection monitoring
- Built-in HTTP server for metrics endpoint

#### 8. Frontend (`frontend/index.html`)
- HTMX-based single-page application
- Drag-and-drop file upload
- Real-time upload progress
- Responsive design
- Auto-format detection

### Infrastructure Components

#### Docker Configuration
- Multi-stage Dockerfile for optimized builds
- Non-root user for security
- Health checks
- Proper port exposure

#### Docker Compose
- Complete development environment
- MongoDB and Redis services
- Nginx reverse proxy
- Volume persistence
- Network isolation

#### Kubernetes Deployment
- Production-ready K8s manifests
- ConfigMaps and Secrets
- Persistent volume claims
- Health checks and resource limits

#### Build Automation
- Makefile with common targets
- Protobuf code generation
- Development workflow support
- Docker and Docker Compose integration

## Change Log
- **2025-09-24**: Initial project setup and requirements definition
- **2025-09-24**: Complete implementation of all core features
- **2025-09-24**: Infrastructure setup with Docker and Kubernetes
- **2025-09-24**: Frontend implementation with HTMX

## Notes
- This file serves as the single source of truth for project requirements
- Any requirement changes must be reflected here first
- Implementation should always reference this file for guidance
- Future changes to this file should drive implementation changes
