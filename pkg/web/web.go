package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/metrics"
	"github.com/force1267/biarbala-go/pkg/storage"
)

// WebService handles static file serving
type WebService struct {
	config  *config.Config
	logger  *logrus.Logger
	storage *storage.MongoDBStorage
	metrics *metrics.Metrics
}

// NewWebService creates a new web service
func NewWebService(cfg *config.Config, logger *logrus.Logger, storage *storage.MongoDBStorage, m *metrics.Metrics) *WebService {
	return &WebService{
		config:  cfg,
		logger:  logger,
		storage: storage,
		metrics: m,
	}
}

// ServeProject serves static files for a project
func (s *WebService) ServeProject(w http.ResponseWriter, r *http.Request, projectID string) {
	start := time.Now()

	// Get project from database
	project, err := s.storage.GetProject(r.Context(), projectID)
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
		if err := s.storage.RecordAccess(r.Context(), projectID, bandwidth); err != nil {
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
	projectDir := filepath.Join(s.config.Server.Static.ServeDir, projectID)

	// Handle root path
	if requestedPath == "/" {
		requestedPath = "/index.html"
	}

	// Try to find the file
	filePath := filepath.Join(projectDir, requestedPath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Try to serve 404.html
		notFoundPath := filepath.Join(projectDir, "404.html")
		if _, err := os.Stat(notFoundPath); err == nil {
			s.serveStaticFile(w, r, notFoundPath)
			return
		}

		// Serve default 404
		s.serveError(w, r, http.StatusNotFound, "File not found")
		return
	}

	// Serve the file
	s.serveStaticFile(w, r, filePath)
}

// serveStaticFile serves a static file with appropriate headers
func (s *WebService) serveStaticFile(w http.ResponseWriter, r *http.Request, filePath string) {
	// Set content type based on file extension
	contentType := s.getContentType(filePath)
	w.Header().Set("Content-Type", contentType)

	// Set cache headers for static assets
	if s.isStaticAsset(filePath) {
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

	// Serve the file
	http.ServeFile(w, r, filePath)
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
	// This is a simplified calculation
	// In a real implementation, you'd track the actual response size
	return int64(len(r.URL.Path) + 1000) // Rough estimate
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
