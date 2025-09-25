package web

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/database"
	"github.com/force1267/biarbala-go/pkg/metrics"
	"github.com/force1267/biarbala-go/pkg/storage"
)

// WebService handles static file serving
type WebService struct {
	config      *config.Config
	logger      *logrus.Logger
	database    *database.MongoDBStorage
	objectStore *storage.MinIOStorage
	metrics     *metrics.Metrics
}

// NewWebService creates a new web service
func NewWebService(cfg *config.Config, logger *logrus.Logger, db *database.MongoDBStorage, objectStore *storage.MinIOStorage, m *metrics.Metrics) *WebService {
	return &WebService{
		config:      cfg,
		logger:      logger,
		database:    db,
		objectStore: objectStore,
		metrics:     m,
	}
}

// ServeProject serves static files for a project by ID
func (s *WebService) ServeProject(w http.ResponseWriter, r *http.Request, projectID string) {
	start := time.Now()

	// Get project from database
	project, err := s.database.GetProject(r.Context(), projectID)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", projectID).Error("Failed to get project")
		s.serveError(w, r, http.StatusNotFound, "Project not found")
		return
	}

	// Check if project is active
	if project.Status != "active" {
		s.serveError(w, r, http.StatusNotFound, "Project not available")
		return
	}

	// Record access metrics
	defer func() {
		duration := time.Since(start)
		bandwidth := s.calculateBandwidth(r)
		s.metrics.RecordHTTPRequest(r.Method, r.URL.Path, "200", duration)

		// Record project access
		if err := s.database.RecordAccess(r.Context(), projectID, bandwidth); err != nil {
			s.logger.WithError(err).Warn("Failed to record project access")
		}
	}()

	// Get requested file path
	requestedPath := strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/projects/%s", projectID))
	if requestedPath == "" {
		requestedPath = "/"
	}

	// Serve the file
	s.serveFile(w, r, projectID, requestedPath)
}

// serveFile serves a specific file from the project
func (s *WebService) serveFile(w http.ResponseWriter, r *http.Request, projectID, requestedPath string) {
	// Handle root path
	if requestedPath == "/" {
		requestedPath = "/index.html"
	}

	// Clean the path
	requestedPath = strings.TrimPrefix(requestedPath, "/")

	// Try to get the file from object storage
	content, err := s.objectStore.GetProjectFile(r.Context(), projectID, requestedPath)
	if err != nil {
		// Try to serve 404.html
		notFoundContent, notFoundErr := s.objectStore.GetProjectFile(r.Context(), projectID, "404.html")
		if notFoundErr == nil {
			s.serveContent(w, r, notFoundContent, "404.html")
			return
		}

		// Serve default 404
		s.serveError(w, r, http.StatusNotFound, "File not found")
		return
	}

	// Serve the file content
	s.serveContent(w, r, content, requestedPath)
}

// serveContent serves file content with appropriate headers
func (s *WebService) serveContent(w http.ResponseWriter, r *http.Request, content []byte, fileName string) {
	// Set content type based on file extension
	contentType := s.getContentType(fileName)
	w.Header().Set("Content-Type", contentType)

	// Set cache headers for static assets
	if s.isStaticAsset(fileName) {
		w.Header().Set("Cache-Control", "public, max-age=31536000") // 1 year
		w.Header().Set("Expires", time.Now().Add(365*24*time.Hour).Format(time.RFC1123))
	} else {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	}

	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Set content length
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))

	// Write the content
	w.Write(content)
}

// serveError serves an error page
func (s *WebService) serveError(w http.ResponseWriter, r *http.Request, statusCode int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	errorHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>%d - %s</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        p { color: #666; }
    </style>
</head>
<body>
    <h1>%d</h1>
    <p>%s</p>
</body>
</html>`, statusCode, message, statusCode, message)

	fmt.Fprint(w, errorHTML)
}

// getContentType returns the appropriate content type for a file
func (s *WebService) getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".eot":
		return "application/vnd.ms-fontobject"
	case ".txt":
		return "text/plain"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

// isStaticAsset checks if a file is a static asset that can be cached
func (s *WebService) isStaticAsset(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	staticExtensions := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}

	for _, staticExt := range staticExtensions {
		if ext == staticExt {
			return true
		}
	}

	return false
}

// calculateBandwidth estimates the bandwidth usage for a request
func (s *WebService) calculateBandwidth(r *http.Request) int64 {
	// TODO: Implement this
	// This is a simplified calculation
	// In a real implementation, you'd track the actual response size
	return int64(len(r.URL.Path) + 1000) // Rough estimate
}

// ServeProjectByDomain serves static files for a project by domain
func (s *WebService) ServeProjectByDomain(w http.ResponseWriter, r *http.Request, domain string) {
	start := time.Now()

	// Get project from database by domain
	project, err := s.database.GetProjectByDomain(r.Context(), domain)
	if err != nil {
		s.logger.WithError(err).WithField("domain", domain).Error("Failed to get project by domain")
		s.serveError(w, r, http.StatusNotFound, "Project not found")
		return
	}

	// Check if project is active
	if project.Status != "active" {
		s.serveError(w, r, http.StatusNotFound, "Project not available")
		return
	}

	// Check if domain is verified (for custom domains)
	if project.IsCustomDomain && !project.DomainVerified {
		s.serveError(w, r, http.StatusNotFound, "Domain not verified")
		return
	}

	// Record access metrics
	defer func() {
		duration := time.Since(start)
		bandwidth := s.calculateBandwidth(r)
		s.metrics.RecordHTTPRequest(r.Method, r.URL.Path, "200", duration)

		// Record project access
		if err := s.database.RecordAccess(r.Context(), project.ProjectID, bandwidth); err != nil {
			s.logger.WithError(err).Warn("Failed to record project access")
		}
	}()

	// Get requested file path
	requestedPath := r.URL.Path
	if requestedPath == "" {
		requestedPath = "/"
	}

	// Serve the file
	s.serveFileByProject(w, r, project, requestedPath)
}

// serveFileByProject serves a specific file from the project
func (s *WebService) serveFileByProject(w http.ResponseWriter, r *http.Request, project *database.Project, requestedPath string) {
	// Handle root path
	if requestedPath == "/" {
		requestedPath = "/index.html"
	}

	// Clean the path
	requestedPath = strings.TrimPrefix(requestedPath, "/")

	// Try to get the file from object storage
	content, err := s.objectStore.GetProjectFile(r.Context(), project.ProjectID, requestedPath)
	if err != nil {
		// Try to serve 404.html
		notFoundContent, notFoundErr := s.objectStore.GetProjectFile(r.Context(), project.ProjectID, "404.html")
		if notFoundErr == nil {
			s.serveContent(w, r, notFoundContent, "404.html")
			return
		}

		// Serve default 404
		s.serveError(w, r, http.StatusNotFound, "File not found")
		return
	}

	// Serve the file content
	s.serveContent(w, r, content, requestedPath)
}

// ServeHealthCheck serves the health check endpoint
func (s *WebService) ServeHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	healthResponse := `{
		"status": "healthy",
		"timestamp": "` + time.Now().Format(time.RFC3339) + `",
		"version": "1.0.0"
	}`

	fmt.Fprint(w, healthResponse)
}
