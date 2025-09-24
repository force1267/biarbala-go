# Biarbala

A simple static hosting platform similar to Netlify, Surge, and Vercel, but with a focus on simplicity and ease of use.

## Features

- **Simple Upload**: Upload compressed files (tar, gzip, zip) containing your static website files
- **Instant Deployment**: Get a live URL immediately after upload
- **Project-Based Access**: No account required for public users - each project gets a unique ID and password
- **Usage Metrics**: Track your website's performance with detailed analytics
- **Secure Access**: Each project has a unique access password for management
- **Fast Serving**: Optimized static file serving with caching
- **gRPC API**: Modern API with gRPC and HTTP support
- **Web Interface**: Simple HTMX-based frontend

## Quick Start

### Prerequisites

- Go 1.25+
- MongoDB
- Redis
- Docker (optional)

### Development Setup

1. Clone the repository:
```bash
git clone github.com/force1267/biarbala-go.git
cd biarbala
```

2. Install dependencies:
```bash
make deps
```

3. Generate protobuf code:
```bash
make proto
```

4. Set up directories:
```bash
make dirs
```

5. Start dependencies (MongoDB and Redis):
```bash
docker-compose up mongodb redis -d
```

6. Run the application:
```bash
make run
```

The application will be available at:
- Frontend: http://localhost:8081
- gRPC API: localhost:8080
- Metrics: http://localhost:9090/metrics

### Using Docker Compose

For a complete setup with all dependencies:

```bash
docker-compose up --build
```

This will start:
- Biarbala application
- MongoDB database
- Redis cache
- Nginx reverse proxy

## API Usage

### Upload a Project

```bash
curl -X POST http://localhost:8081/api/v1/biarbala.BiarbalaService/UploadProject \
  -F "project_name=my-website" \
  -F "file_format=zip" \
  -F "file_data=@website.zip"
```

### Get Project Information

```bash
curl -X POST http://localhost:8081/api/v1/biarbala.BiarbalaService/GetProject \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "your-project-id",
    "access_password": "your-password"
  }'
```

## Project Structure

```
biarbala/
├── cmd/server/          # Application entry point
├── pkg/                # Library code
│   ├── config/         # Configuration management
│   ├── logger/         # Logging utilities
│   ├── metrics/        # Prometheus metrics
│   ├── server/         # gRPC server implementation
│   ├── storage/        # MongoDB storage layer
│   ├── upload/         # File upload handling
│   └── web/            # Static file serving
├── protos/             # Protocol buffer definitions
├── scripts/            # Build and utility scripts
├── config/             # Configuration files
├── frontend/           # HTMX frontend
├── deployment/         # Kubernetes deployment configs
├── docker-compose.yml  # Docker Compose setup
├── Dockerfile          # Docker configuration
└── Makefile           # Build automation
```

## Configuration

Configuration is managed through `config/config.yaml` and environment variables:

```yaml
server:
  grpc:
    port: 8080
    host: "0.0.0.0"
    enable_reflection: true
    enable_web_grpc: true
  http:
    port: 8081
    host: "0.0.0.0"

database:
  mongodb:
    uri: "mongodb://localhost:27017"
    database: "biarbala"

cache:
  redis:
    addr: "localhost:6379"
```

## Development

### Available Make Targets

- `make build` - Build the application
- `make run` - Run the application
- `make test` - Run tests
- `make clean` - Clean build artifacts
- `make proto` - Generate protobuf code
- `make docker` - Build Docker image
- `make docker-compose` - Run with Docker Compose
- `make dev` - Run in development mode with hot reload
- `make setup` - Set up development environment

### Adding New Features

1. Update the protobuf definitions in `protos/`
2. Run `make proto` to generate Go code
3. Implement the service methods in `pkg/server/`
4. Add tests
5. Update documentation

## Deployment

### Docker

```bash
docker build -t biarbala:latest .
docker run -p 8080:8080 -p 8081:8081 -p 9090:9090 biarbala:latest
```

### Kubernetes

```bash
kubectl apply -f deployment/k8s-deployment.yaml
```

## Monitoring

The application exposes Prometheus metrics at `/metrics`:

- HTTP request metrics
- gRPC request metrics
- File upload metrics
- Project metrics
- Database and cache connection metrics

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions, please open an issue on GitHub.
