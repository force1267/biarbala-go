package server

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/metrics"
	"github.com/force1267/biarbala-go/pkg/storage"
	"github.com/force1267/biarbala-go/pkg/upload"
	"github.com/force1267/biarbala-go/protos/gen"
)

// BiarbalaServiceImpl implements the BiarbalaService gRPC interface
type BiarbalaServiceImpl struct {
	gen.UnimplementedBiarbalaServiceServer
	config        *config.Config
	logger        *logrus.Logger
	storage       *storage.MongoDBStorage
	uploadService *upload.UploadService
	metrics       *metrics.Metrics
}

// NewBiarbalaService creates a new BiarbalaService implementation
func NewBiarbalaService(cfg *config.Config, logger *logrus.Logger, storage *storage.MongoDBStorage, uploadService *upload.UploadService, m *metrics.Metrics) *BiarbalaServiceImpl {
	return &BiarbalaServiceImpl{
		config:        cfg,
		logger:        logger,
		storage:       storage,
		uploadService: uploadService,
		metrics:       m,
	}
}

// UploadProject uploads a compressed file containing static website files
func (s *BiarbalaServiceImpl) UploadProject(ctx context.Context, req *gen.UploadProjectRequest) (*gen.UploadProjectResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"project_name": req.ProjectName,
		"file_format":  req.FileFormat,
		"file_size":    len(req.FileData),
		"user_id":      req.UserId,
	}).Info("Upload project request received")

	// Validate request
	if req.ProjectName == "" {
		return nil, status.Error(codes.InvalidArgument, "project name is required")
	}
	if len(req.FileData) == 0 {
		return nil, status.Error(codes.InvalidArgument, "file data is required")
	}
	if req.FileFormat == "" {
		return nil, status.Error(codes.InvalidArgument, "file format is required")
	}

	// Check file format
	allowedFormats := s.config.Upload.AllowedFormats
	formatValid := false
	for _, format := range allowedFormats {
		if req.FileFormat == format {
			formatValid = true
			break
		}
	}
	if !formatValid {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported file format: %s", req.FileFormat))
	}

	// Upload the project
	result, err := s.uploadService.UploadProject(ctx, req.ProjectName, req.UserId, req.FileData, req.FileFormat)
	if err != nil {
		s.logger.WithError(err).Error("Failed to upload project")
		return nil, status.Error(codes.Internal, "failed to upload project")
	}

	// Record metrics
	s.metrics.RecordFileUpload(req.FileFormat, "success", result.FileSize)

	response := &gen.UploadProjectResponse{
		ProjectId:      result.ProjectID,
		AccessPassword: result.AccessPassword,
		ProjectUrl:     result.ProjectURL,
		CreatedAt:      timestamppb.New(time.Now()),
		Status:         gen.ProjectStatus_PROJECT_STATUS_ACTIVE,
	}

	s.logger.WithField("project_id", result.ProjectID).Info("Project uploaded successfully")
	return response, nil
}

// GetProject retrieves project information
func (s *BiarbalaServiceImpl) GetProject(ctx context.Context, req *gen.GetProjectRequest) (*gen.GetProjectResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Get project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.storage.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password for public projects
	if project.UserID == "" && req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Convert to protobuf
	pbProject := s.convertProjectToProto(project)

	response := &gen.GetProjectResponse{
		Project: pbProject,
	}

	return response, nil
}

// UpdateProject updates project settings
func (s *BiarbalaServiceImpl) UpdateProject(ctx context.Context, req *gen.UpdateProjectRequest) (*gen.UpdateProjectResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Update project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.storage.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Prepare updates
	updates := make(map[string]interface{})
	if req.ProjectName != "" {
		updates["project_name"] = req.ProjectName
	}
	if req.Settings != nil {
		updates["settings"] = req.Settings
	}

	// Update project
	if err := s.storage.UpdateProject(ctx, req.ProjectId, updates); err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to update project")
		return nil, status.Error(codes.Internal, "failed to update project")
	}

	// Get updated project
	updatedProject, err := s.storage.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get updated project")
		return nil, status.Error(codes.Internal, "failed to get updated project")
	}

	// Convert to protobuf
	pbProject := s.convertProjectToProto(updatedProject)

	response := &gen.UpdateProjectResponse{
		Project: pbProject,
	}

	s.logger.WithField("project_id", req.ProjectId).Info("Project updated successfully")
	return response, nil
}

// DeleteProject deletes a project
func (s *BiarbalaServiceImpl) DeleteProject(ctx context.Context, req *gen.DeleteProjectRequest) (*emptypb.Empty, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Delete project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.storage.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Delete project
	if err := s.storage.DeleteProject(ctx, req.ProjectId); err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to delete project")
		return nil, status.Error(codes.Internal, "failed to delete project")
	}

	s.logger.WithField("project_id", req.ProjectId).Info("Project deleted successfully")
	return &emptypb.Empty{}, nil
}

// ListProjects lists user's projects
func (s *BiarbalaServiceImpl) ListProjects(ctx context.Context, req *gen.ListProjectsRequest) (*gen.ListProjectsResponse, error) {
	s.logger.WithField("user_id", req.UserId).Info("List projects request received")

	// Validate request
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user ID is required")
	}

	// Set default pagination
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}

	// Get projects from storage
	projects, totalCount, err := s.storage.ListProjects(ctx, req.UserId, int(page), int(pageSize))
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to list projects")
		return nil, status.Error(codes.Internal, "failed to list projects")
	}

	// Convert to protobuf
	var pbProjects []*gen.Project
	for _, project := range projects {
		pbProjects = append(pbProjects, s.convertProjectToProto(project))
	}

	response := &gen.ListProjectsResponse{
		Projects:   pbProjects,
		TotalCount: int32(totalCount),
		Page:       page,
		PageSize:   pageSize,
	}

	return response, nil
}

// GetProjectMetrics retrieves project usage metrics
func (s *BiarbalaServiceImpl) GetProjectMetrics(ctx context.Context, req *gen.GetProjectMetricsRequest) (*gen.GetProjectMetricsResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Get project metrics request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.storage.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Get metrics from storage
	metrics, err := s.storage.GetProjectMetrics(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project metrics")
		return nil, status.Error(codes.Internal, "failed to get project metrics")
	}

	// Convert to protobuf
	pbMetrics := s.convertMetricsToProto(metrics)

	response := &gen.GetProjectMetricsResponse{
		Metrics: pbMetrics,
	}

	return response, nil
}

// HealthCheck provides health status
func (s *BiarbalaServiceImpl) HealthCheck(ctx context.Context, req *emptypb.Empty) (*gen.HealthCheckResponse, error) {
	response := &gen.HealthCheckResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Timestamp: timestamppb.New(time.Now()),
	}

	return response, nil
}

// convertProjectToProto converts a storage.Project to protobuf Project
func (s *BiarbalaServiceImpl) convertProjectToProto(project *storage.Project) *gen.Project {
	status := gen.ProjectStatus_PROJECT_STATUS_UNSPECIFIED
	switch project.Status {
	case "active":
		status = gen.ProjectStatus_PROJECT_STATUS_ACTIVE
	case "uploading":
		status = gen.ProjectStatus_PROJECT_STATUS_UPLOADING
	case "processing":
		status = gen.ProjectStatus_PROJECT_STATUS_PROCESSING
	case "error":
		status = gen.ProjectStatus_PROJECT_STATUS_ERROR
	case "deleted":
		status = gen.ProjectStatus_PROJECT_STATUS_DELETED
	}

	return &gen.Project{
		ProjectId:   project.ProjectID,
		ProjectName: project.ProjectName,
		UserId:      project.UserID,
		ProjectUrl:  project.ProjectURL,
		Status:      status,
		CreatedAt:   timestamppb.New(project.CreatedAt),
		UpdatedAt:   timestamppb.New(project.UpdatedAt),
		FileSize:    project.FileSize,
		FileFormat:  project.FileFormat,
		Settings:    project.Settings,
	}
}

// convertMetricsToProto converts storage.ProjectMetrics to protobuf ProjectMetrics
func (s *BiarbalaServiceImpl) convertMetricsToProto(metrics *storage.ProjectMetrics) *gen.ProjectMetrics {
	var dailyMetrics []*gen.DailyMetrics
	for _, dm := range metrics.DailyMetrics {
		dailyMetrics = append(dailyMetrics, &gen.DailyMetrics{
			Date:           timestamppb.New(dm.Date),
			Requests:       dm.Requests,
			BandwidthBytes: dm.BandwidthBytes,
			UniqueVisitors: dm.UniqueVisitors,
		})
	}

	return &gen.ProjectMetrics{
		ProjectId:           metrics.ProjectID,
		TotalRequests:       metrics.TotalRequests,
		TotalBandwidthBytes: metrics.TotalBandwidth,
		UniqueVisitors:      metrics.UniqueVisitors,
		LastAccessed:        timestamppb.New(metrics.LastAccessed),
		DailyMetrics:        dailyMetrics,
	}
}
