package storage

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
)

// MinIOStorage implements object storage using MinIO
type MinIOStorage struct {
	client     *minio.Client
	bucketName string
	logger     *logrus.Logger
	config     *config.Config
}

// NewMinIOStorage creates a new MinIO storage instance
func NewMinIOStorage(cfg *config.Config, logger *logrus.Logger) (*MinIOStorage, error) {
	// Initialize MinIO client
	client, err := minio.New(cfg.Storage.MinIO.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.Storage.MinIO.AccessKey, cfg.Storage.MinIO.SecretKey, ""),
		Secure: cfg.Storage.MinIO.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create MinIO client: %w", err)
	}

	storage := &MinIOStorage{
		client:     client,
		bucketName: cfg.Storage.MinIO.BucketName,
		logger:     logger,
		config:     cfg,
	}

	// Ensure bucket exists
	if err := storage.ensureBucket(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to ensure bucket exists: %w", err)
	}

	return storage, nil
}

// ensureBucket creates the bucket if it doesn't exist
func (s *MinIOStorage) ensureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucketName)
	if err != nil {
		return fmt.Errorf("failed to check if bucket exists: %w", err)
	}

	if !exists {
		err = s.client.MakeBucket(ctx, s.bucketName, minio.MakeBucketOptions{})
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		s.logger.WithField("bucket", s.bucketName).Info("Created MinIO bucket")
	}

	return nil
}

// UploadProject uploads project files to object storage
func (s *MinIOStorage) UploadProject(ctx context.Context, projectID string, files map[string][]byte) error {
	for filePath, content := range files {
		objectName := s.getObjectName(projectID, filePath)

		_, err := s.client.PutObject(ctx, s.bucketName, objectName, strings.NewReader(string(content)), int64(len(content)), minio.PutObjectOptions{
			ContentType: s.getContentType(filePath),
		})
		if err != nil {
			return fmt.Errorf("failed to upload file %s: %w", filePath, err)
		}

		s.logger.WithFields(logrus.Fields{
			"project_id":  projectID,
			"file_path":   filePath,
			"object_name": objectName,
			"size":        len(content),
		}).Debug("Uploaded file to object storage")
	}

	return nil
}

// GetProjectFile retrieves a specific file from object storage
func (s *MinIOStorage) GetProjectFile(ctx context.Context, projectID, filePath string) ([]byte, error) {
	objectName := s.getObjectName(projectID, filePath)

	object, err := s.client.GetObject(ctx, s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	defer object.Close()

	content, err := io.ReadAll(object)
	if err != nil {
		return nil, fmt.Errorf("failed to read object content: %w", err)
	}

	return content, nil
}

// ListProjectFiles lists all files for a project
func (s *MinIOStorage) ListProjectFiles(ctx context.Context, projectID string) ([]string, error) {
	var files []string

	objectCh := s.client.ListObjects(ctx, s.bucketName, minio.ListObjectsOptions{
		Prefix:    s.getProjectPrefix(projectID),
		Recursive: true,
	})

	for object := range objectCh {
		if object.Err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", object.Err)
		}

		// Remove project prefix to get relative file path
		relativePath := strings.TrimPrefix(object.Key, s.getProjectPrefix(projectID))
		if relativePath != "" {
			files = append(files, relativePath)
		}
	}

	return files, nil
}

// DeleteProject deletes all files for a project
func (s *MinIOStorage) DeleteProject(ctx context.Context, projectID string) error {
	objectsCh := make(chan minio.ObjectInfo)

	go func() {
		defer close(objectsCh)
		for object := range s.client.ListObjects(ctx, s.bucketName, minio.ListObjectsOptions{
			Prefix:    s.getProjectPrefix(projectID),
			Recursive: true,
		}) {
			objectsCh <- object
		}
	}()

	opts := minio.RemoveObjectsOptions{
		GovernanceBypass: true,
	}

	errorCh := s.client.RemoveObjects(ctx, s.bucketName, objectsCh, opts)

	// Check for errors
	for err := range errorCh {
		if err.Err != nil {
			return fmt.Errorf("failed to delete object %s: %w", err.ObjectName, err.Err)
		}
	}

	s.logger.WithField("project_id", projectID).Info("Deleted project files from object storage")
	return nil
}

// GetProjectFileStream returns a stream for reading a project file
func (s *MinIOStorage) GetProjectFileStream(ctx context.Context, projectID, filePath string) (io.ReadCloser, error) {
	objectName := s.getObjectName(projectID, filePath)

	object, err := s.client.GetObject(ctx, s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object stream: %w", err)
	}

	return object, nil
}

// getObjectName generates the object name for a file
func (s *MinIOStorage) getObjectName(projectID, filePath string) string {
	// Clean the file path and ensure it starts with project ID
	cleanPath := strings.TrimPrefix(filepath.Clean(filePath), "/")
	return fmt.Sprintf("projects/%s/%s", projectID, cleanPath)
}

// getProjectPrefix returns the prefix for all objects in a project
func (s *MinIOStorage) getProjectPrefix(projectID string) string {
	return fmt.Sprintf("projects/%s/", projectID)
}

// getContentType determines the content type based on file extension
func (s *MinIOStorage) getContentType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	contentTypes := map[string]string{
		".html":  "text/html",
		".htm":   "text/html",
		".css":   "text/css",
		".js":    "application/javascript",
		".json":  "application/json",
		".xml":   "application/xml",
		".txt":   "text/plain",
		".png":   "image/png",
		".jpg":   "image/jpeg",
		".jpeg":  "image/jpeg",
		".gif":   "image/gif",
		".svg":   "image/svg+xml",
		".ico":   "image/x-icon",
		".woff":  "font/woff",
		".woff2": "font/woff2",
		".ttf":   "font/ttf",
		".eot":   "application/vnd.ms-fontobject",
		".pdf":   "application/pdf",
		".zip":   "application/zip",
		".tar":   "application/x-tar",
		".gz":    "application/gzip",
	}

	if contentType, exists := contentTypes[ext]; exists {
		return contentType
	}

	return "application/octet-stream"
}

// Health checks if the storage is healthy
func (s *MinIOStorage) Health(ctx context.Context) error {
	_, err := s.client.ListBuckets(ctx)
	if err != nil {
		return fmt.Errorf("storage health check failed: %w", err)
	}
	return nil
}

// Close closes the storage connection
func (s *MinIOStorage) Close() error {
	// MinIO client doesn't need explicit closing
	return nil
}
