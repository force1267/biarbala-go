package upload

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/database"
	"github.com/force1267/biarbala-go/pkg/domain"
	"github.com/force1267/biarbala-go/pkg/storage"
)

// UploadService handles file uploads and extraction
type UploadService struct {
	config      *config.Config
	logger      *logrus.Logger
	database    *database.MongoDBStorage
	objectStore *storage.MinIOStorage
	validator   *domain.SubdomainValidator
}

// NewUploadService creates a new upload service
func NewUploadService(cfg *config.Config, logger *logrus.Logger, db *database.MongoDBStorage, objectStore *storage.MinIOStorage) *UploadService {
	return &UploadService{
		config:      cfg,
		logger:      logger,
		database:    db,
		objectStore: objectStore,
		validator:   domain.NewSubdomainValidator(),
	}
}

// UploadResult contains the result of an upload operation
type UploadResult struct {
	ProjectID      string
	AccessPassword string
	ProjectURL     string
	Domain         string
	FileSize       int64
	ExtractedFiles []string
}

// UploadProject uploads and processes a compressed project file
func (s *UploadService) UploadProject(ctx context.Context, projectName, userID string, fileData []byte, fileFormat string) (*UploadResult, error) {
	// Generate project ID and password
	projectID := uuid.New().String()
	accessPassword := generatePassword()

	// Generate default subdomain
	defaultSubdomain := s.generateUniqueSubdomain()
	defaultDomain := defaultSubdomain + "." + domain.MainDomain

	// Extract files to memory
	extractedFiles, fileContents, err := s.extractFilesToMemory(ctx, fileData, fileFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to extract files: %w", err)
	}

	// Upload files to object storage
	if err := s.objectStore.UploadProject(ctx, projectID, fileContents); err != nil {
		return nil, fmt.Errorf("failed to upload files to object storage: %w", err)
	}

	// Create project record
	project := &database.Project{
		ProjectID:      projectID,
		ProjectName:    projectName,
		UserID:         userID,
		AccessPassword: accessPassword,
		ProjectURL:     fmt.Sprintf("/projects/%s", projectID),
		Domain:         defaultDomain,
		IsCustomDomain: false,
		DomainVerified: true, // Default subdomains are automatically verified
		Status:         "active",
		FileSize:       int64(len(fileData)),
		FileFormat:     fileFormat,
		Settings:       make(map[string]string),
	}

	// Save to database
	if err := s.database.CreateProject(ctx, project); err != nil {
		// Clean up object storage on error
		s.objectStore.DeleteProject(ctx, projectID)
		return nil, fmt.Errorf("failed to save project: %w", err)
	}

	// Create initial metrics
	metrics := &database.ProjectMetrics{
		ProjectID:      projectID,
		TotalRequests:  0,
		TotalBandwidth: 0,
		UniqueVisitors: 0,
		LastAccessed:   time.Now(),
		DailyMetrics:   []database.DailyMetrics{},
	}

	if err := s.database.CreateProjectMetrics(ctx, metrics); err != nil {
		s.logger.WithError(err).Warn("Failed to create initial project metrics")
	}

	s.logger.WithFields(logrus.Fields{
		"project_id":      projectID,
		"project_name":    projectName,
		"file_size":       len(fileData),
		"file_format":     fileFormat,
		"extracted_files": len(extractedFiles),
	}).Info("Project uploaded successfully")

	return &UploadResult{
		ProjectID:      projectID,
		AccessPassword: accessPassword,
		ProjectURL:     project.ProjectURL,
		Domain:         defaultDomain,
		FileSize:       int64(len(fileData)),
		ExtractedFiles: extractedFiles,
	}, nil
}

// extractFilesToMemory extracts files from compressed data to memory
func (s *UploadService) extractFilesToMemory(ctx context.Context, fileData []byte, format string) ([]string, map[string][]byte, error) {
	var extractedFiles []string
	var fileContents map[string][]byte

	switch strings.ToLower(format) {
	case "tar":
		files, contents, err := s.extractTarToMemory(ctx, fileData)
		if err != nil {
			return nil, nil, err
		}
		extractedFiles = files
		fileContents = contents
	case "gz", "gzip":
		files, contents, err := s.extractTarGzToMemory(ctx, fileData)
		if err != nil {
			return nil, nil, err
		}
		extractedFiles = files
		fileContents = contents
	case "zip":
		files, contents, err := s.extractZipToMemory(ctx, fileData)
		if err != nil {
			return nil, nil, err
		}
		extractedFiles = files
		fileContents = contents
	default:
		return nil, nil, fmt.Errorf("unsupported file format: %s", format)
	}

	// Validate extracted files
	if err := s.validateExtractedFiles(extractedFiles); err != nil {
		return nil, nil, fmt.Errorf("validation failed: %w", err)
	}

	return extractedFiles, fileContents, nil
}

// extractFiles extracts files from compressed data (legacy method for backward compatibility)
func (s *UploadService) extractFiles(ctx context.Context, fileData []byte, format, destDir string) ([]string, error) {
	var extractedFiles []string

	switch strings.ToLower(format) {
	case "tar":
		files, err := s.extractTar(ctx, fileData, destDir)
		if err != nil {
			return nil, err
		}
		extractedFiles = files
	case "gz", "gzip":
		files, err := s.extractTarGz(ctx, fileData, destDir)
		if err != nil {
			return nil, err
		}
		extractedFiles = files
	case "zip":
		files, err := s.extractZip(ctx, fileData, destDir)
		if err != nil {
			return nil, err
		}
		extractedFiles = files
	default:
		return nil, fmt.Errorf("unsupported file format: %s", format)
	}

	// Validate extracted files
	if err := s.validateExtractedFiles(extractedFiles); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return extractedFiles, nil
}

// extractTar extracts files from a tar archive
func (s *UploadService) extractTar(ctx context.Context, fileData []byte, destDir string) ([]string, error) {
	var extractedFiles []string

	reader := strings.NewReader(string(fileData))
	tarReader := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Create file path
		filePath := filepath.Join(destDir, header.Name)

		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}

		// Create file
		file, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file: %w", err)
		}

		// Copy file content
		if _, err := io.Copy(file, tarReader); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}

		file.Close()
		extractedFiles = append(extractedFiles, header.Name)
	}

	return extractedFiles, nil
}

// extractTarGz extracts files from a gzipped tar archive
func (s *UploadService) extractTarGz(ctx context.Context, fileData []byte, destDir string) ([]string, error) {
	reader := strings.NewReader(string(fileData))
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var extractedFiles []string
	tarReader := tar.NewReader(gzReader)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Create file path
		filePath := filepath.Join(destDir, header.Name)

		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}

		// Create file
		file, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create file: %w", err)
		}

		// Copy file content
		if _, err := io.Copy(file, tarReader); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}

		file.Close()
		extractedFiles = append(extractedFiles, header.Name)
	}

	return extractedFiles, nil
}

// extractZip extracts files from a zip archive
func (s *UploadService) extractZip(ctx context.Context, fileData []byte, destDir string) ([]string, error) {
	reader := strings.NewReader(string(fileData))
	zipReader, err := zip.NewReader(reader, int64(len(fileData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	var extractedFiles []string

	for _, file := range zipReader.File {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Skip directories
		if file.FileInfo().IsDir() {
			continue
		}

		// Create file path
		filePath := filepath.Join(destDir, file.Name)

		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory: %w", err)
		}

		// Open file in zip
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to open file in zip: %w", err)
		}

		// Create destination file
		destFile, err := os.Create(filePath)
		if err != nil {
			rc.Close()
			return nil, fmt.Errorf("failed to create file: %w", err)
		}

		// Copy file content
		if _, err := io.Copy(destFile, rc); err != nil {
			rc.Close()
			destFile.Close()
			return nil, fmt.Errorf("failed to copy file content: %w", err)
		}

		rc.Close()
		destFile.Close()
		extractedFiles = append(extractedFiles, file.Name)
	}

	return extractedFiles, nil
}

// extractTarToMemory extracts files from a tar archive to memory
func (s *UploadService) extractTarToMemory(ctx context.Context, fileData []byte) ([]string, map[string][]byte, error) {
	var extractedFiles []string
	fileContents := make(map[string][]byte)

	reader := strings.NewReader(string(fileData))
	tarReader := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Read file content
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file content: %w", err)
		}

		fileContents[header.Name] = content
		extractedFiles = append(extractedFiles, header.Name)
	}

	return extractedFiles, fileContents, nil
}

// extractTarGzToMemory extracts files from a gzipped tar archive to memory
func (s *UploadService) extractTarGzToMemory(ctx context.Context, fileData []byte) ([]string, map[string][]byte, error) {
	reader := strings.NewReader(string(fileData))
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var extractedFiles []string
	fileContents := make(map[string][]byte)
	tarReader := tar.NewReader(gzReader)

	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Read file content
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file content: %w", err)
		}

		fileContents[header.Name] = content
		extractedFiles = append(extractedFiles, header.Name)
	}

	return extractedFiles, fileContents, nil
}

// extractZipToMemory extracts files from a zip archive to memory
func (s *UploadService) extractZipToMemory(ctx context.Context, fileData []byte) ([]string, map[string][]byte, error) {
	reader := strings.NewReader(string(fileData))
	zipReader, err := zip.NewReader(reader, int64(len(fileData)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	var extractedFiles []string
	fileContents := make(map[string][]byte)

	for _, file := range zipReader.File {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		// Skip directories
		if file.FileInfo().IsDir() {
			continue
		}

		// Open file in zip
		rc, err := file.Open()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open file in zip: %w", err)
		}

		// Read file content
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read file content: %w", err)
		}

		fileContents[file.Name] = content
		extractedFiles = append(extractedFiles, file.Name)
	}

	return extractedFiles, fileContents, nil
}

// validateExtractedFiles validates that extracted files are safe and contain expected web files
func (s *UploadService) validateExtractedFiles(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("no files extracted")
	}

	// Check for common web files
	hasIndex := false

	for _, file := range files {
		// Check for index.html
		if file == "index.html" || strings.HasSuffix(file, "/index.html") {
			hasIndex = true
		}

		// Check for public directory (validation only)
		_ = strings.HasPrefix(file, "public/")

		// Check for dangerous files
		if strings.Contains(file, "..") || strings.Contains(file, "~") {
			return fmt.Errorf("dangerous file path detected: %s", file)
		}
	}

	// Warn if no index.html found
	if !hasIndex {
		s.logger.Warn("No index.html found in uploaded project")
	}

	return nil
}

// generatePassword generates a random access password
func generatePassword() string {
	return uuid.New().String()[:8]
}

// generateUniqueSubdomain generates a unique subdomain that doesn't exist in the database
func (s *UploadService) generateUniqueSubdomain() string {
	maxAttempts := 10

	for i := 0; i < maxAttempts; i++ {
		subdomain := s.validator.GenerateSubdomain()
		fullDomain := subdomain + "." + domain.MainDomain

		// Check if domain already exists
		_, err := s.database.GetProjectByDomain(context.Background(), fullDomain)
		if err != nil {
			// Domain doesn't exist, we can use it
			return subdomain
		}
	}

	// Fallback to UUID-based subdomain if we can't generate a meaningful one
	return "project-" + uuid.New().String()[:8]
}
