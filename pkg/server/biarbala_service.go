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
	"github.com/force1267/biarbala-go/pkg/database"
	"github.com/force1267/biarbala-go/pkg/domain"
	"github.com/force1267/biarbala-go/pkg/metrics"
	"github.com/force1267/biarbala-go/pkg/ssl"
	"github.com/force1267/biarbala-go/pkg/upload"
	protos "github.com/force1267/biarbala-go/protos/gen"
)

// BiarbalaServiceImpl implements the BiarbalaService gRPC interface
type BiarbalaServiceImpl struct {
	protos.UnimplementedBiarbalaServiceServer
	config             *config.Config
	logger             *logrus.Logger
	database           *database.MongoDBStorage
	uploadService      *upload.UploadService
	metrics            *metrics.Metrics
	domainValidator    *domain.SubdomainValidator
	domainVerifier     *domain.DomainVerifier
	certificateManager *ssl.CertificateManager
}

// NewBiarbalaService creates a new BiarbalaService implementation
func NewBiarbalaService(cfg *config.Config, logger *logrus.Logger, db *database.MongoDBStorage, uploadService *upload.UploadService, m *metrics.Metrics) *BiarbalaServiceImpl {
	// Initialize domain services
	domainValidator := domain.NewSubdomainValidator()
	domainVerifier := domain.NewDomainVerifier(logger)

	// Initialize SSL certificate manager with Let's Encrypt provider
	letsEncryptProvider := ssl.NewLetsEncryptProvider(logger)
	certificateManager := ssl.NewCertificateManager(logger, letsEncryptProvider)

	return &BiarbalaServiceImpl{
		config:             cfg,
		logger:             logger,
		database:           db,
		uploadService:      uploadService,
		metrics:            m,
		domainValidator:    domainValidator,
		domainVerifier:     domainVerifier,
		certificateManager: certificateManager,
	}
}

// UploadProject uploads a compressed file containing static website files
func (s *BiarbalaServiceImpl) UploadProject(ctx context.Context, req *protos.UploadProjectRequest) (*protos.UploadProjectResponse, error) {
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

	response := &protos.UploadProjectResponse{
		ProjectId:      result.ProjectID,
		AccessPassword: result.AccessPassword,
		ProjectUrl:     result.ProjectURL,
		CreatedAt:      timestamppb.New(time.Now()),
		Status:         protos.ProjectStatus_PROJECT_STATUS_ACTIVE,
	}

	s.logger.WithField("project_id", result.ProjectID).Info("Project uploaded successfully")
	return response, nil
}

// GetProject retrieves project information
func (s *BiarbalaServiceImpl) GetProject(ctx context.Context, req *protos.GetProjectRequest) (*protos.GetProjectResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Get project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
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

	response := &protos.GetProjectResponse{
		Project: pbProject,
	}

	return response, nil
}

// UpdateProject updates project settings
func (s *BiarbalaServiceImpl) UpdateProject(ctx context.Context, req *protos.UpdateProjectRequest) (*protos.UpdateProjectResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Update project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
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
	if err := s.database.UpdateProject(ctx, req.ProjectId, updates); err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to update project")
		return nil, status.Error(codes.Internal, "failed to update project")
	}

	// Get updated project
	updatedProject, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get updated project")
		return nil, status.Error(codes.Internal, "failed to get updated project")
	}

	// Convert to protobuf
	pbProject := s.convertProjectToProto(updatedProject)

	response := &protos.UpdateProjectResponse{
		Project: pbProject,
	}

	s.logger.WithField("project_id", req.ProjectId).Info("Project updated successfully")
	return response, nil
}

// DeleteProject deletes a project
func (s *BiarbalaServiceImpl) DeleteProject(ctx context.Context, req *protos.DeleteProjectRequest) (*emptypb.Empty, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Delete project request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Delete project
	if err := s.database.DeleteProject(ctx, req.ProjectId); err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to delete project")
		return nil, status.Error(codes.Internal, "failed to delete project")
	}

	s.logger.WithField("project_id", req.ProjectId).Info("Project deleted successfully")
	return &emptypb.Empty{}, nil
}

// ListProjects lists user's projects
func (s *BiarbalaServiceImpl) ListProjects(ctx context.Context, req *protos.ListProjectsRequest) (*protos.ListProjectsResponse, error) {
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
	projects, totalCount, err := s.database.ListProjects(ctx, req.UserId, int(page), int(pageSize))
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to list projects")
		return nil, status.Error(codes.Internal, "failed to list projects")
	}

	// Convert to protobuf
	var pbProjects []*protos.Project
	for _, project := range projects {
		pbProjects = append(pbProjects, s.convertProjectToProto(project))
	}

	response := &protos.ListProjectsResponse{
		Projects:   pbProjects,
		TotalCount: int32(totalCount),
		Page:       page,
		PageSize:   pageSize,
	}

	return response, nil
}

// GetProjectMetrics retrieves project usage metrics
func (s *BiarbalaServiceImpl) GetProjectMetrics(ctx context.Context, req *protos.GetProjectMetricsRequest) (*protos.GetProjectMetricsResponse, error) {
	s.logger.WithField("project_id", req.ProjectId).Info("Get project metrics request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Get metrics from storage
	metrics, err := s.database.GetProjectMetrics(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project metrics")
		return nil, status.Error(codes.Internal, "failed to get project metrics")
	}

	// Convert to protobuf
	pbMetrics := s.convertMetricsToProto(metrics)

	response := &protos.GetProjectMetricsResponse{
		Metrics: pbMetrics,
	}

	return response, nil
}

// SetProjectDomain sets the domain for a project
func (s *BiarbalaServiceImpl) SetProjectDomain(ctx context.Context, req *protos.SetProjectDomainRequest) (*protos.SetProjectDomainResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"project_id":       req.ProjectId,
		"domain":           req.Domain,
		"is_custom_domain": req.IsCustomDomain,
	}).Info("Set project domain request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	// Get project from database
	project, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Validate domain
	if req.IsCustomDomain {
		if err := s.domainValidator.ValidateCustomDomain(req.Domain); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid custom domain: %s", err.Error()))
		}
	} else {
		// Validate subdomain
		subdomain := s.domainValidator.ExtractSubdomainFromDomain(req.Domain)
		if subdomain == "" {
			return nil, status.Error(codes.InvalidArgument, "invalid subdomain format")
		}
		if err := s.domainValidator.ValidateSubdomain(subdomain); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("invalid subdomain: %s", err.Error()))
		}
	}

	// Check if domain is already in use
	existingProject, err := s.database.GetProjectByDomain(ctx, req.Domain)
	if err == nil && existingProject.ProjectID != req.ProjectId {
		return nil, status.Error(codes.AlreadyExists, "domain is already in use by another project")
	}

	// Set domain in database
	if err := s.database.SetProjectDomain(ctx, req.ProjectId, req.Domain, req.IsCustomDomain); err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to set project domain")
		return nil, status.Error(codes.Internal, "failed to set project domain")
	}

	response := &protos.SetProjectDomainResponse{
		Domain:               req.Domain,
		RequiresVerification: req.IsCustomDomain,
	}

	// If it's a custom domain, create verification challenge
	if req.IsCustomDomain {
		challenge, err := s.domainVerifier.CreateChallenge(req.Domain)
		if err != nil {
			s.logger.WithError(err).Error("Failed to create domain verification challenge")
			return nil, status.Error(codes.Internal, "failed to create verification challenge")
		}

		// Store verification challenge
		verification := &database.DomainVerification{
			ProjectID: req.ProjectId,
			Domain:    req.Domain,
			TXTRecord: challenge.TXTRecord,
			Verified:  false,
			CreatedAt: challenge.CreatedAt,
			ExpiresAt: challenge.ExpiresAt,
		}

		if err := s.database.CreateDomainVerification(ctx, verification); err != nil {
			s.logger.WithError(err).Error("Failed to store domain verification challenge")
			return nil, status.Error(codes.Internal, "failed to store verification challenge")
		}

		response.VerificationInstructions = s.domainVerifier.GetVerificationInstructions(challenge)
		response.TxtRecord = challenge.TXTRecord
	}

	s.logger.WithField("project_id", req.ProjectId).Info("Project domain set successfully")
	return response, nil
}

// VerifyDomain verifies domain ownership
func (s *BiarbalaServiceImpl) VerifyDomain(ctx context.Context, req *protos.VerifyDomainRequest) (*protos.VerifyDomainResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"project_id": req.ProjectId,
		"domain":     req.Domain,
	}).Info("Verify domain request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Get verification challenge
	verification, err := s.database.GetDomainVerification(ctx, req.ProjectId, req.Domain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get domain verification challenge")
		return nil, status.Error(codes.NotFound, "verification challenge not found")
	}

	// Create challenge object for verification
	challenge := &domain.VerificationChallenge{
		Domain:    verification.Domain,
		TXTRecord: verification.TXTRecord,
		CreatedAt: verification.CreatedAt,
		ExpiresAt: verification.ExpiresAt,
		Verified:  verification.Verified,
	}

	// Verify domain
	verified, err := s.domainVerifier.VerifyChallenge(ctx, challenge)
	if err != nil {
		s.logger.WithError(err).Error("Domain verification failed")
		return &protos.VerifyDomainResponse{
			Verified: false,
			Message:  fmt.Sprintf("Verification failed: %s", err.Error()),
		}, nil
	}

	if verified {
		// Update verification status
		now := time.Now()
		updates := map[string]interface{}{
			"verified":    true,
			"verified_at": now,
		}

		if err := s.database.UpdateDomainVerification(ctx, req.ProjectId, req.Domain, updates); err != nil {
			s.logger.WithError(err).Error("Failed to update domain verification status")
			return nil, status.Error(codes.Internal, "failed to update verification status")
		}

		// Mark project domain as verified
		if err := s.database.VerifyProjectDomain(ctx, req.ProjectId); err != nil {
			s.logger.WithError(err).Error("Failed to verify project domain")
			return nil, status.Error(codes.Internal, "failed to verify project domain")
		}

		// Request SSL certificate
		if _, err := s.certificateManager.RequestCertificate(ctx, req.Domain); err != nil {
			s.logger.WithError(err).Warn("Failed to request SSL certificate")
			// Don't fail the verification if SSL certificate request fails
		}

		s.logger.WithField("domain", req.Domain).Info("Domain verification successful")
		return &protos.VerifyDomainResponse{
			Verified:   true,
			Message:    "Domain verification successful",
			VerifiedAt: timestamppb.New(now),
		}, nil
	}

	return &protos.VerifyDomainResponse{
		Verified: false,
		Message:  "Domain verification failed - TXT record not found or does not match",
	}, nil
}

// GetDomainVerificationStatus gets the verification status of a domain
func (s *BiarbalaServiceImpl) GetDomainVerificationStatus(ctx context.Context, req *protos.GetDomainVerificationStatusRequest) (*protos.GetDomainVerificationStatusResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"project_id": req.ProjectId,
		"domain":     req.Domain,
	}).Info("Get domain verification status request received")

	// Validate request
	if req.ProjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "project ID is required")
	}
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	// Get project from storage
	project, err := s.database.GetProject(ctx, req.ProjectId)
	if err != nil {
		s.logger.WithError(err).WithField("project_id", req.ProjectId).Error("Failed to get project")
		return nil, status.Error(codes.NotFound, "project not found")
	}

	// Check access password
	if req.AccessPassword != project.AccessPassword {
		return nil, status.Error(codes.PermissionDenied, "invalid access password")
	}

	// Get verification challenge
	verification, err := s.database.GetDomainVerification(ctx, req.ProjectId, req.Domain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get domain verification challenge")
		return nil, status.Error(codes.NotFound, "verification challenge not found")
	}

	status := "pending"
	if verification.Verified {
		status = "verified"
	} else if time.Now().After(verification.ExpiresAt) {
		status = "expired"
	}

	response := &protos.GetDomainVerificationStatusResponse{
		Domain:    req.Domain,
		Verified:  verification.Verified,
		Status:    status,
		TxtRecord: verification.TXTRecord,
		ExpiresAt: timestamppb.New(verification.ExpiresAt),
	}

	// Add verification instructions if not verified
	if !verification.Verified {
		challenge := &domain.VerificationChallenge{
			Domain:    verification.Domain,
			TXTRecord: verification.TXTRecord,
			CreatedAt: verification.CreatedAt,
			ExpiresAt: verification.ExpiresAt,
			Verified:  verification.Verified,
		}
		response.VerificationInstructions = s.domainVerifier.GetVerificationInstructions(challenge)
	}

	return response, nil
}

// HealthCheck provides health status
func (s *BiarbalaServiceImpl) HealthCheck(ctx context.Context, req *emptypb.Empty) (*protos.HealthCheckResponse, error) {
	response := &protos.HealthCheckResponse{
		Status:    "healthy",
		Version:   "1.0.0",
		Timestamp: timestamppb.New(time.Now()),
	}

	return response, nil
}

// convertProjectToProto converts a storage.Project to protobuf Project
func (s *BiarbalaServiceImpl) convertProjectToProto(project *database.Project) *protos.Project {
	status := protos.ProjectStatus_PROJECT_STATUS_UNSPECIFIED
	switch project.Status {
	case "active":
		status = protos.ProjectStatus_PROJECT_STATUS_ACTIVE
	case "uploading":
		status = protos.ProjectStatus_PROJECT_STATUS_UPLOADING
	case "processing":
		status = protos.ProjectStatus_PROJECT_STATUS_PROCESSING
	case "error":
		status = protos.ProjectStatus_PROJECT_STATUS_ERROR
	case "deleted":
		status = protos.ProjectStatus_PROJECT_STATUS_DELETED
	}

	return &protos.Project{
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
func (s *BiarbalaServiceImpl) convertMetricsToProto(metrics *database.ProjectMetrics) *protos.ProjectMetrics {
	var dailyMetrics []*protos.DailyMetrics
	for _, dm := range metrics.DailyMetrics {
		dailyMetrics = append(dailyMetrics, &protos.DailyMetrics{
			Date:           timestamppb.New(dm.Date),
			Requests:       dm.Requests,
			BandwidthBytes: dm.BandwidthBytes,
			UniqueVisitors: dm.UniqueVisitors,
		})
	}

	return &protos.ProjectMetrics{
		ProjectId:           metrics.ProjectID,
		TotalRequests:       metrics.TotalRequests,
		TotalBandwidthBytes: metrics.TotalBandwidth,
		UniqueVisitors:      metrics.UniqueVisitors,
		LastAccessed:        timestamppb.New(metrics.LastAccessed),
		DailyMetrics:        dailyMetrics,
	}
}
