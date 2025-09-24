package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/metrics"
	protos "github.com/force1267/biarbala-go/protos/gen"
)

// Server represents the gRPC and HTTP server
type Server struct {
	config          *config.Config
	logger          *logrus.Logger
	metrics         *metrics.Metrics
	grpcServer      *grpc.Server
	httpServer      *http.Server
	biarbalaService *BiarbalaServiceImpl
}

// New creates a new server instance
func New(cfg *config.Config, logger *logrus.Logger, m *metrics.Metrics, biarbalaService *BiarbalaServiceImpl) *Server {
	return &Server{
		config:          cfg,
		logger:          logger,
		metrics:         m,
		biarbalaService: biarbalaService,
	}
}

// Start starts both gRPC and HTTP servers
func (s *Server) Start(ctx context.Context) error {
	// Start gRPC server
	if err := s.startGRPCServer(ctx); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Start HTTP server
	if err := s.startHTTPServer(ctx); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	return nil
}

// startGRPCServer starts the gRPC server
func (s *Server) startGRPCServer(ctx context.Context) error {
	// Create gRPC server
	s.grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(s.unaryInterceptor()),
		grpc.StreamInterceptor(s.streamInterceptor()),
	)

	// Register Biarbala service
	protos.RegisterBiarbalaServiceServer(s.grpcServer, s.biarbalaService)

	// Enable reflection if configured
	if s.config.Server.GRPC.EnableReflection {
		reflection.Register(s.grpcServer)
		s.logger.Info("gRPC reflection enabled")
	}

	// Start server
	addr := fmt.Sprintf("%s:%d", s.config.Server.GRPC.Host, s.config.Server.GRPC.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	s.logger.WithField("address", addr).Info("Starting gRPC server")

	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			s.logger.WithError(err).Error("gRPC server failed")
		}
	}()

	return nil
}

// startHTTPServer starts an HTTP server with web-gRPC support
func (s *Server) startHTTPServer(ctx context.Context) error {
	// Create HTTP mux for web-gRPC and health checks
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", s.healthHandler)

	// Web-gRPC endpoints
	mux.HandleFunc("/api/v1/projects", s.handleProjectsAPI)
	mux.HandleFunc("/api/v1/projects/", s.handleProjectAPI)
	mux.HandleFunc("/api/v1/health", s.handleHealthAPI)

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", s.config.Server.HTTP.Host, s.config.Server.HTTP.Port),
		Handler:      s.httpHandler(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.WithField("address", s.httpServer.Addr).Info("Starting HTTP server with web-gRPC support")

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithError(err).Error("HTTP server failed")
		}
	}()

	return nil
}

// healthHandler handles health check requests
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"biarbala"}`))
}

// handleProjectsAPI handles /api/v1/projects endpoint
func (s *Server) handleProjectsAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		s.handleUploadProject(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleProjectAPI handles /api/v1/projects/{id} endpoint
func (s *Server) handleProjectAPI(w http.ResponseWriter, r *http.Request) {
	// Extract project ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Project ID required", http.StatusBadRequest)
		return
	}
	projectID := parts[0]

	switch r.Method {
	case "GET":
		s.handleGetProject(w, r, projectID)
	case "PUT":
		s.handleUpdateProject(w, r, projectID)
	case "DELETE":
		s.handleDeleteProject(w, r, projectID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealthAPI handles /api/v1/health endpoint (gRPC health check)
func (s *Server) handleHealthAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Call gRPC health check
	ctx := context.Background()
	resp, err := s.biarbalaService.HealthCheck(ctx, &emptypb.Empty{})
	if err != nil {
		s.logger.WithError(err).Error("Health check failed")
		http.Error(w, "Health check failed", http.StatusInternalServerError)
		return
	}

	// Convert to JSON
	jsonResp, err := protojson.Marshal(resp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal health response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResp)
}

// handleUploadProject handles POST /api/v1/projects
func (s *Server) handleUploadProject(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form for file upload
	err := r.ParseMultipartForm(32 << 20) // 32 MB max
	if err != nil {
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}

	// Get project name
	projectName := r.FormValue("project_name")
	if projectName == "" {
		http.Error(w, "project_name is required", http.StatusBadRequest)
		return
	}

	// Get uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get uploaded file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read file data
	fileData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file data", http.StatusInternalServerError)
		return
	}

	// Determine file format
	fileFormat := "unknown"
	if strings.HasSuffix(header.Filename, ".tar") {
		fileFormat = "tar"
	} else if strings.HasSuffix(header.Filename, ".tar.gz") || strings.HasSuffix(header.Filename, ".tgz") {
		fileFormat = "gzip"
	} else if strings.HasSuffix(header.Filename, ".zip") {
		fileFormat = "zip"
	}

	// Create gRPC request
	req := &protos.UploadProjectRequest{
		ProjectName: projectName,
		FileData:    fileData,
		FileFormat:  fileFormat,
	}

	// Call gRPC service
	ctx := context.Background()
	resp, err := s.biarbalaService.UploadProject(ctx, req)
	if err != nil {
		s.logger.WithError(err).Error("Upload project failed")
		http.Error(w, "Upload failed", http.StatusInternalServerError)
		return
	}

	// Convert to JSON
	jsonResp, err := protojson.Marshal(resp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal upload response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResp)
}

// handleGetProject handles GET /api/v1/projects/{id}
func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request, projectID string) {
	// Get access password from query parameter
	accessPassword := r.URL.Query().Get("access_password")
	if accessPassword == "" {
		http.Error(w, "access_password query parameter required", http.StatusBadRequest)
		return
	}

	// Create gRPC request
	req := &protos.GetProjectRequest{
		ProjectId:      projectID,
		AccessPassword: accessPassword,
	}

	// Call gRPC service
	ctx := context.Background()
	resp, err := s.biarbalaService.GetProject(ctx, req)
	if err != nil {
		s.logger.WithError(err).Error("Get project failed")
		http.Error(w, "Get project failed", http.StatusInternalServerError)
		return
	}

	// Convert to JSON
	jsonResp, err := protojson.Marshal(resp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal get project response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResp)
}

// handleUpdateProject handles PUT /api/v1/projects/{id}
func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request, projectID string) {
	// Parse JSON body
	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Get access password
	accessPassword, ok := updateData["access_password"].(string)
	if !ok || accessPassword == "" {
		http.Error(w, "access_password is required", http.StatusBadRequest)
		return
	}

	// Create gRPC request
	req := &protos.UpdateProjectRequest{
		ProjectId:      projectID,
		AccessPassword: accessPassword,
		ProjectName:    updateData["project_name"].(string),
		Settings:       make(map[string]string),
	}

	// Convert settings if present
	if settings, ok := updateData["settings"].(map[string]interface{}); ok {
		for k, v := range settings {
			if str, ok := v.(string); ok {
				req.Settings[k] = str
			}
		}
	}

	// Call gRPC service
	ctx := context.Background()
	resp, err := s.biarbalaService.UpdateProject(ctx, req)
	if err != nil {
		s.logger.WithError(err).Error("Update project failed")
		http.Error(w, "Update failed", http.StatusInternalServerError)
		return
	}

	// Convert to JSON
	jsonResp, err := protojson.Marshal(resp)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal update response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResp)
}

// handleDeleteProject handles DELETE /api/v1/projects/{id}
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request, projectID string) {
	// Get access password from query parameter
	accessPassword := r.URL.Query().Get("access_password")
	if accessPassword == "" {
		http.Error(w, "access_password query parameter required", http.StatusBadRequest)
		return
	}

	// Create gRPC request
	req := &protos.DeleteProjectRequest{
		ProjectId:      projectID,
		AccessPassword: accessPassword,
	}

	// Call gRPC service
	ctx := context.Background()
	_, err := s.biarbalaService.DeleteProject(ctx, req)
	if err != nil {
		s.logger.WithError(err).Error("Delete project failed")
		http.Error(w, "Delete failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// httpHandler creates the HTTP handler with middleware
func (s *Server) httpHandler(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Add CORS headers for web-gRPC
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Grpc-Web")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Serve the request
		mux.ServeHTTP(w, r)

		// Record metrics
		duration := time.Since(start)
		s.metrics.RecordHTTPRequest(r.Method, r.URL.Path, "200", duration)
	})
}

// unaryInterceptor creates a unary interceptor for gRPC
func (s *Server) unaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Add request ID to context
		ctx = s.addRequestID(ctx)

		// Log request
		s.logger.WithFields(logrus.Fields{
			"method":     info.FullMethod,
			"request_id": s.getRequestID(ctx),
		}).Debug("gRPC request started")

		// Call handler
		resp, err := handler(ctx, req)

		// Record metrics
		duration := time.Since(start)
		status := "OK"
		if err != nil {
			status = "ERROR"
		}
		s.metrics.RecordGRPCRequest(info.FullMethod, status, duration)

		// Log response
		s.logger.WithFields(logrus.Fields{
			"method":     info.FullMethod,
			"request_id": s.getRequestID(ctx),
			"duration":   duration,
			"error":      err,
		}).Debug("gRPC request completed")

		return resp, err
	}
}

// streamInterceptor creates a stream interceptor for gRPC
func (s *Server) streamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		// Add request ID to context
		ctx := s.addRequestID(ss.Context())
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}

		// Log request
		s.logger.WithFields(logrus.Fields{
			"method":     info.FullMethod,
			"request_id": s.getRequestID(ctx),
		}).Debug("gRPC stream started")

		// Call handler
		err := handler(srv, wrapped)

		// Record metrics
		duration := time.Since(start)
		status := "OK"
		if err != nil {
			status = "ERROR"
		}
		s.metrics.RecordGRPCRequest(info.FullMethod, status, duration)

		// Log response
		s.logger.WithFields(logrus.Fields{
			"method":     info.FullMethod,
			"request_id": s.getRequestID(ctx),
			"duration":   duration,
			"error":      err,
		}).Debug("gRPC stream completed")

		return err
	}
}

// addRequestID adds a request ID to the context
func (s *Server) addRequestID(ctx context.Context) context.Context {
	requestID := fmt.Sprintf("%d", time.Now().UnixNano())
	return context.WithValue(ctx, "request_id", requestID)
}

// getRequestID gets the request ID from the context
func (s *Server) getRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value("request_id").(string); ok {
		return requestID
	}
	return "unknown"
}

// Stop gracefully stops the servers
func (s *Server) Stop(ctx context.Context) error {
	var errs []error

	// Stop HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown HTTP server: %w", err))
		}
	}

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	return nil
}

// wrappedServerStream wraps grpc.ServerStream to override Context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
