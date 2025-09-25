# Biarbala Development Tracker

## Project Overview
Biarbala is a web server as a service platform similar to Netlify, Surge, and Vercel but with a focus on simplicity. Users can upload compressed static files and serve them as web pages without requiring accounts for public users.

## Core Requirements

### Functional Requirements
- **File Upload**: Users upload compressed files (tar, gzip, zip) containing static files
- **Static File Serving**: Serve uploaded static files as web pages
- **Standard Web Files Support**: Support for index.html, 404.html, {error_code}.html, public/, .well-known, robots.txt
- **Project-Based Access**: No account required for public users - return project ID and password on upload
- **User Account Support**: Full user account system with authentication and authorization
- **Usage Monitoring**: Monitor usage and provide metrics to users
- **Billing Preparation**: Codebase must be extensible for future billing implementation with exact usage monitoring

### Authentication & Authorization Requirements
- **Identity Provider**: Keycloak for centralized user management and authentication
- **Social Login Support**: 
  - GitHub OAuth integration
  - Google OAuth integration
- **Email Authentication**: 
  - Email + password registration/login
  - Email OTP (One-Time Password) verification
  - Email verification for account activation
- **User Types**: 
  - Public users (no account required)
  - Registered users (authenticated users)
  - Admin users (administrative privileges)
- **Access Control**: 
  - Public endpoints (no authentication required)
  - User endpoints (authenticated users only)
  - Admin endpoints (admin users only)

### Domain Management Requirements
- **Main Domain**: `biarbala.ir` as the primary domain
- **Subdomain Validation**: 
  - Must have at least one dash "-" not at beginning or end: `hello-world` allowed, `hello` not allowed
  - No consecutive dashes: `hello--world` not allowed
  - Minimum 6 characters: `abc.biarbala.ir` not allowed
  - Only digits, alphabet, and dash allowed
- **Default Subdomains**: Generate meaningful names with dashes like `pretty-good-site.biarbala.ir`
- **Subdomain Changes**: Users can change their subdomains
- **Custom Domains**: Users can use their own domains
- **Domain Ownership Verification**: TXT domain challenge for custom domain ownership
- **SSL Certificates**: Automatic SSL certificate issuance using Let's Encrypt
- **Domain Traffic Routing**: Serve projects based on domain/subdomain

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

### Phase 4: Domain Management ✅
- [x] Subdomain validation and generation - Implemented in pkg/domain/
- [x] Custom domain support with TXT verification - Implemented in pkg/domain/verification.go
- [x] SSL certificate management with Let's Encrypt - Implemented in pkg/ssl/
- [x] Domain routing and traffic management - Implemented in pkg/web/
- [x] Domain change functionality - Implemented in pkg/server/biarbala_service.go

### Phase 5: Authentication & Authorization ✅
- [x] Keycloak integration and configuration
- [x] Email service implementation
- [x] User management system
- [x] Authentication middleware
- [x] Authorization and access control
- [x] GitHub OAuth integration
- [x] Google OAuth integration
- [x] Email verification and OTP system
- [x] Admin user management
- [x] Keycloak database configuration fixed (PostgreSQL support)
- [x] User admin gRPC service implementation
- [x] OAuth provider integration centralized through Keycloak

### Phase 6: Production Readiness
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
- **Database**: MongoDB (no ORM), PostgreSQL (for Keycloak)
- **Object Storage**: MinIO (S3-compatible)
- **Cache**: Redis
- **API**: gRPC with protobuf
- **Authentication**: Keycloak, JWT tokens
- **Email**: SMTP client for email notifications and verification
- **OAuth**: GitHub and Google OAuth via Keycloak identity providers
- **User Management**: Keycloak-based user system with role-based access control
- **Admin Services**: gRPC-based user administration API

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
- Extracts files to memory and uploads to object storage
- Validates extracted files for security
- Generates unique project IDs and access passwords
- Records upload metrics
- Uses MinIO for S3-compatible object storage

#### 2. Static File Serving (`pkg/web/web.go`)
- Serves static files from object storage
- Handles index.html, 404.html, and error pages
- Supports standard web files (public/, .well-known, robots.txt)
- Implements proper caching headers
- Records access metrics for billing preparation
- Uses MinIO for file retrieval

#### 3. Project Management (`pkg/database/mongodb.go`)
- MongoDB-based storage without ORM
- Project CRUD operations
- Metrics tracking and storage
- Access control with project passwords
- Pagination support for project listing
- User management with role-based access control

#### 4. Object Storage (`pkg/storage/minio.go`)
- MinIO-based S3-compatible object storage
- Project file upload and retrieval
- Content type detection
- File streaming support
- Bucket management and health checks

#### 5. gRPC Service (`pkg/server/biarbala_service.go`)
- Complete BiarbalaService implementation
- Upload, get, update, delete, list operations
- Project metrics retrieval
- Health check endpoint
- Proper error handling and validation

#### 6. Configuration Management (`pkg/config/config.go`)
- Viper-based configuration
- Environment variable support
- Default values for all settings
- Structured configuration types

#### 7. Logging (`pkg/logger/logger.go`)
- Logrus-based structured logging
- Configurable log levels and formats
- Request ID tracking
- Error context preservation

#### 8. Metrics (`pkg/metrics/metrics.go`)
- Prometheus metrics collection
- HTTP, gRPC, file upload, and project metrics
- Cache hit/miss tracking
- Database and Redis connection monitoring
- Built-in HTTP server for metrics endpoint

#### 9. Frontend (`frontend/index.html`)
- HTMX-based single-page application
- Drag-and-drop file upload
- Real-time upload progress
- Responsive design
- Auto-format detection

#### 10. Domain Management (`pkg/domain/`)
- Subdomain validation with Biarbala rules
- Custom domain validation
- Meaningful subdomain generation
- Domain verification with TXT challenges
- DNS lookup and verification

#### 11. SSL Certificate Management (`pkg/ssl/`)
- Let's Encrypt provider implementation
- Certificate request, renewal, and revocation
- Self-signed certificates for development
- Certificate validation and expiry checking
- TLS configuration management

#### 12. Domain Routing (`pkg/web/web.go`)
- Domain-based project serving
- Custom domain verification checks
- SSL certificate validation
- Domain-specific error handling

#### 13. Web-gRPC Support (`pkg/server/server.go`)
- HTTP-to-gRPC bridge implementation
- RESTful API endpoints for web clients
- Multipart file upload support
- JSON-to-protobuf conversion
- CORS headers for web integration
- API endpoints:
  - `POST /api/v1/projects` - Upload project
  - `GET /api/v1/projects/{id}` - Get project
  - `PUT /api/v1/projects/{id}` - Update project
  - `DELETE /api/v1/projects/{id}` - Delete project
  - `GET /api/v1/health` - Health check

#### 14. Authentication System (`pkg/auth/`)
- JWT token generation, validation, and refresh
- Keycloak OAuth2/OpenID Connect integration
- GitHub and Google OAuth via Keycloak identity providers
- Authentication middleware with role-based access control
- Identity service for unified authentication management
- OAuth state validation for CSRF protection
- Centralized OAuth provider management through Keycloak

#### 15. User Management (`pkg/users/user.go`)
- Comprehensive user data model with Keycloak integration
- User types: Public, User, Admin with role-based access
- User status management: Pending, Active, Suspended, Deleted
- Email verification with expiration codes (stored as user attributes)
- OTP (One-Time Password) management for various purposes (stored as user attributes)
- Password reset functionality with secure tokens (stored as user attributes)
- Keycloak Admin API integration for user operations
- Automatic token management for Keycloak admin authentication

#### 16. Email Service (`pkg/email/smtp.go`)
- SMTP client with TLS support
- Email templates for verification and OTP
- Configurable SMTP settings
- HTML and plain text email support
- Error handling and logging

#### 17. Authentication API Endpoints
- `POST /api/v1/auth/login` - User login with email/password
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/refresh` - Token refresh
- `GET /api/v1/auth/profile` - Get user profile
- `GET /api/v1/auth/keycloak` - Keycloak OAuth initiation
- `GET /api/v1/auth/keycloak/callback` - Keycloak OAuth callback
- `GET /api/v1/auth/github` - GitHub OAuth initiation
- `GET /api/v1/auth/github/callback` - GitHub OAuth callback
- `GET /api/v1/auth/google` - Google OAuth initiation
- `GET /api/v1/auth/google/callback` - Google OAuth callback
- `POST /api/v1/auth/otp/send` - Send OTP
- `POST /api/v1/auth/otp/verify` - Verify OTP
- `GET /api/v1/auth/verify-email` - Email verification
- `POST /api/v1/auth/reset-password` - Password reset request
- `POST /api/v1/auth/reset-password/confirm` - Password reset confirmation

#### 18. User Admin Service (`pkg/server/user_admin_service.go`)
- Comprehensive user management via gRPC API
- Create, read, update, delete user operations
- User listing with pagination and filtering
- Password management (change/reset)
- User status management (active, suspended, deleted)
- Role assignment and removal
- Admin-only access control
- Integration with user service and authentication system

#### 19. User Admin gRPC API Endpoints
- `CreateUser` - Create new user (admin only)
- `GetUser` - Get user information
- `UpdateUser` - Update user details
- `DeleteUser` - Soft delete user
- `ListUsers` - List users with pagination
- `ChangeUserPassword` - Change user password
- `ResetUserPassword` - Reset user password
- `UpdateUserStatus` - Update user status
- `AssignUserRoles` - Assign roles to user
- `RemoveUserRoles` - Remove roles from user

#### 20. Keycloak OAuth Integration
- **Centralized OAuth Management**: All OAuth providers (GitHub, Google) are configured in Keycloak as identity providers
- **Unified Authentication Flow**: Users authenticate through Keycloak, which handles the OAuth flow with external providers
- **Provider Configuration**: GitHub and Google OAuth credentials are configured in Keycloak admin console
- **User Information**: All user data comes from Keycloak's userinfo endpoint, regardless of the original OAuth provider
- **Token Management**: Keycloak issues JWT tokens that can be validated by the backend
- **Identity Provider Hints**: Backend uses `kc_idp_hint` parameter to direct users to specific OAuth providers
- **Callback Handling**: All OAuth callbacks are handled through Keycloak's unified callback endpoint

### Infrastructure Components

#### Docker Configuration
- Multi-stage Dockerfile for optimized builds
- Non-root user for security
- Health checks
- Proper port exposure

#### Docker Compose
- Complete development environment
- MongoDB and Redis services
- MinIO object storage service
- PostgreSQL database for Keycloak
- Keycloak authentication service (fixed database configuration)
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
- **2025-09-26**: Added MinIO object storage support
- **2025-09-26**: Refactored storage package to database package
- **2025-09-26**: Updated file serving to use object storage instead of local files

## Notes
- This file serves as the single source of truth for project requirements
- Any requirement changes must be reflected here first
- Implementation should always reference this file for guidance
- Future changes to this file should drive implementation changes
