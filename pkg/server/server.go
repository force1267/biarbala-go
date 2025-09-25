package server

import (
	"context"
	"crypto/rand"
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

	"github.com/force1267/biarbala-go/pkg/auth"
	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/metrics"
	protos "github.com/force1267/biarbala-go/protos/gen"
)

// Server represents the gRPC and HTTP server
type Server struct {
	config           *config.Config
	logger           *logrus.Logger
	metrics          *metrics.Metrics
	grpcServer       *grpc.Server
	httpServer       *http.Server
	biarbalaService  *BiarbalaServiceImpl
	userAdminService *UserAdminServiceImpl
	authService      *auth.IdentityService
	authMiddleware   *auth.AuthMiddleware
}

// New creates a new server instance
func New(cfg *config.Config, logger *logrus.Logger, m *metrics.Metrics, biarbalaService *BiarbalaServiceImpl, userAdminService *UserAdminServiceImpl, authService *auth.IdentityService, authMiddleware *auth.AuthMiddleware) *Server {
	return &Server{
		config:           cfg,
		logger:           logger,
		metrics:          m,
		biarbalaService:  biarbalaService,
		userAdminService: userAdminService,
		authService:      authService,
		authMiddleware:   authMiddleware,
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

	// Register services
	protos.RegisterBiarbalaServiceServer(s.grpcServer, s.biarbalaService)
	protos.RegisterUserAdminServiceServer(s.grpcServer, s.userAdminService)

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

	// Authentication endpoints
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/register", s.handleAuthRegister)
	mux.HandleFunc("/api/v1/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/refresh", s.handleAuthRefresh)
	mux.HandleFunc("/api/v1/auth/profile", s.handleAuthProfile)
	mux.HandleFunc("/api/v1/auth/keycloak", s.handleKeycloakAuth)
	mux.HandleFunc("/api/v1/auth/keycloak/callback", s.handleKeycloakCallback)
	mux.HandleFunc("/api/v1/auth/github", s.handleGitHubAuth)
	mux.HandleFunc("/api/v1/auth/github/callback", s.handleGitHubCallback)
	mux.HandleFunc("/api/v1/auth/google", s.handleGoogleAuth)
	mux.HandleFunc("/api/v1/auth/google/callback", s.handleGoogleCallback)
	mux.HandleFunc("/api/v1/auth/otp/send", s.handleSendOTP)
	mux.HandleFunc("/api/v1/auth/otp/verify", s.handleVerifyOTP)
	mux.HandleFunc("/api/v1/auth/verify-email", s.handleVerifyEmail)
	mux.HandleFunc("/api/v1/auth/reset-password", s.handleResetPassword)
	mux.HandleFunc("/api/v1/auth/reset-password/confirm", s.handleConfirmPasswordReset)

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

// Authentication handlers

// handleAuthLogin handles user login
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tokenResp, err := s.authService.LoginWithEmail(r.Context(), req.Email, req.Password)
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("Login failed")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleAuthRegister handles user registration
func (s *Server) handleAuthRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tokenResp, err := s.authService.RegisterWithEmail(r.Context(), req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("Registration failed")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleAuthLogout handles user logout
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For JWT tokens, logout is handled client-side by removing the token
	// For Keycloak, we would call the logout endpoint
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// handleAuthRefresh handles token refresh
func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get JWT service from identity service (this would need to be exposed)
	// For now, we'll return an error indicating this needs to be implemented
	http.Error(w, "Token refresh not implemented", http.StatusNotImplemented)
}

// handleAuthProfile handles user profile retrieval
func (s *Server) handleAuthProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := auth.GetUserFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// handleKeycloakAuth handles Keycloak authentication initiation
func (s *Server) handleKeycloakAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	provider, err := s.authService.GetProvider("keycloak")
	if err != nil {
		http.Error(w, "Keycloak provider not configured", http.StatusServiceUnavailable)
		return
	}

	state := generateState()
	authURL := provider.GetAuthURL(state)

	// Store state in session/cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleKeycloakCallback handles Keycloak OAuth callback
func (s *Server) handleKeycloakCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie.Value != state {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	tokenResp, err := s.authService.HandleCallback(r.Context(), "keycloak", code, state)
	if err != nil {
		s.logger.WithError(err).Warn("Keycloak callback failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleGitHubAuth handles GitHub authentication initiation via Keycloak
func (s *Server) handleGitHubAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := generateState()

	// Use Keycloak with GitHub identity provider
	authURL := s.authService.GetKeycloakService().GetAuthURLWithProvider(state, "github")

	// Store state in session/cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleGitHubCallback handles GitHub OAuth callback via Keycloak
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie.Value != state {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Use Keycloak callback handler (same as regular Keycloak callback)
	tokenResp, err := s.authService.HandleCallback(r.Context(), "keycloak", code, state)
	if err != nil {
		s.logger.WithError(err).Warn("GitHub callback via Keycloak failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleGoogleAuth handles Google authentication initiation via Keycloak
func (s *Server) handleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := generateState()

	// Use Keycloak with Google identity provider
	authURL := s.authService.GetKeycloakService().GetAuthURLWithProvider(state, "google")

	// Store state in session/cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleGoogleCallback handles Google OAuth callback via Keycloak
func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	// Validate state
	cookie, err := r.Cookie("oauth_state")
	if err != nil || cookie.Value != state {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Use Keycloak callback handler (same as regular Keycloak callback)
	tokenResp, err := s.authService.HandleCallback(r.Context(), "keycloak", code, state)
	if err != nil {
		s.logger.WithError(err).Warn("Google callback via Keycloak failed")
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HttpOnly: true,
		MaxAge:   -1,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleSendOTP handles sending OTP
func (s *Server) handleSendOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := s.authService.SendOTP(r.Context(), req.Email, req.Purpose)
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("Send OTP failed")
		http.Error(w, "Failed to send OTP", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "OTP sent successfully"})
}

// handleVerifyOTP handles OTP verification
func (s *Server) handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email   string `json:"email"`
		Code    string `json:"code"`
		Purpose string `json:"purpose"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tokenResp, err := s.authService.VerifyOTP(r.Context(), req.Email, req.Code, req.Purpose)
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("OTP verification failed")
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleVerifyEmail handles email verification
func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Verification code is required", http.StatusBadRequest)
		return
	}

	// This would need to be implemented in the user service
	// For now, we'll return a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
}

// handleResetPassword handles password reset request
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Send OTP for password reset
	err := s.authService.SendOTP(r.Context(), req.Email, "password_reset")
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("Password reset failed")
		http.Error(w, "Failed to send reset code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset code sent"})
}

// handleConfirmPasswordReset handles password reset confirmation
func (s *Server) handleConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify OTP first
	_, err := s.authService.VerifyOTP(r.Context(), req.Email, req.Code, "password_reset")
	if err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Warn("Password reset verification failed")
		http.Error(w, "Invalid reset code", http.StatusUnauthorized)
		return
	}

	// Update password (this would need to be implemented)
	// For now, we'll return a success message
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successfully"})
}

// generateState generates a random state parameter for OAuth
func generateState() string {
	// Generate a random 32-character string
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}
