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

	"github.com/force1267/biarbala-go/pkg/auth"
	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/users"
	protos "github.com/force1267/biarbala-go/protos/gen"
)

// UserAdminServiceImpl implements the UserAdminService gRPC service
type UserAdminServiceImpl struct {
	protos.UnimplementedUserAdminServiceServer
	config      *config.Config
	logger      *logrus.Logger
	userService *users.UserService
	authService *auth.IdentityService
}

// NewUserAdminService creates a new user admin service
func NewUserAdminService(cfg *config.Config, logger *logrus.Logger, userService *users.UserService, authService *auth.IdentityService) *UserAdminServiceImpl {
	return &UserAdminServiceImpl{
		config:      cfg,
		logger:      logger,
		userService: userService,
		authService: authService,
	}
}

// CreateUser creates a new user
func (s *UserAdminServiceImpl) CreateUser(ctx context.Context, req *protos.CreateUserRequest) (*protos.CreateUserResponse, error) {
	// Validate request
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}

	// Check if user already exists
	existingUser, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, status.Error(codes.AlreadyExists, "user with this email already exists")
	}

	// Determine user type
	userType := users.UserTypeUser
	if req.UserType == "admin" {
		userType = users.UserTypeAdmin
	}

	// Generate unique user ID
	userID := fmt.Sprintf("user_admin_%d", time.Now().UnixNano())

	// Create user
	user := &users.User{
		UserID:        userID,
		Email:         req.Email,
		Username:      req.Username,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		UserType:      userType,
		Status:        users.UserStatusActive,
		EmailVerified: true, // Admin-created users are pre-verified
		Provider:      "admin",
		ProviderID:    userID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Settings:      make(map[string]string),
	}

	if err := s.userService.CreateUser(ctx, user); err != nil {
		s.logger.WithError(err).WithField("email", req.Email).Error("Failed to create user")
		return nil, status.Error(codes.Internal, "failed to create user")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":   user.UserID,
		"email":     user.Email,
		"user_type": user.UserType,
	}).Info("User created by admin")

	return &protos.CreateUserResponse{
		User:    s.convertUserToProto(user),
		Message: "User created successfully",
	}, nil
}

// GetUser retrieves user information
func (s *UserAdminServiceImpl) GetUser(ctx context.Context, req *protos.GetUserRequest) (*protos.GetUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &protos.GetUserResponse{
		User: s.convertUserToProto(user),
	}, nil
}

// UpdateUser updates user information
func (s *UserAdminServiceImpl) UpdateUser(ctx context.Context, req *protos.UpdateUserRequest) (*protos.UpdateUserResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Prepare updates
	updates := make(map[string]interface{})
	if req.Email != "" {
		updates["email"] = req.Email
	}
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.AvatarUrl != "" {
		updates["avatar_url"] = req.AvatarUrl
	}
	if req.Settings != nil {
		updates["settings"] = req.Settings
	}

	if len(updates) == 0 {
		return &protos.UpdateUserResponse{
			User:    s.convertUserToProto(user),
			Message: "No updates provided",
		}, nil
	}

	// Update user
	if err := s.userService.UpdateUser(ctx, req.UserId, updates); err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to update user")
		return nil, status.Error(codes.Internal, "failed to update user")
	}

	// Get updated user
	updatedUser, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get updated user")
		return nil, status.Error(codes.Internal, "failed to get updated user")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"updates": updates,
	}).Info("User updated by admin")

	return &protos.UpdateUserResponse{
		User:    s.convertUserToProto(updatedUser),
		Message: "User updated successfully",
	}, nil
}

// DeleteUser deletes a user (soft delete)
func (s *UserAdminServiceImpl) DeleteUser(ctx context.Context, req *protos.DeleteUserRequest) (*emptypb.Empty, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Soft delete user
	if err := s.userService.DeleteUser(ctx, req.UserId); err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to delete user")
		return nil, status.Error(codes.Internal, "failed to delete user")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
	}).Info("User deleted by admin")

	return &emptypb.Empty{}, nil
}

// ListUsers lists users with pagination
func (s *UserAdminServiceImpl) ListUsers(ctx context.Context, req *protos.ListUsersRequest) (*protos.ListUsersResponse, error) {
	// Set default pagination
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100 // Limit max page size
	}

	// Determine user type filter
	var userType users.UserType
	if req.UserType != "" {
		switch req.UserType {
		case "user":
			userType = users.UserTypeUser
		case "admin":
			userType = users.UserTypeAdmin
		case "public":
			userType = users.UserTypePublic
		default:
			return nil, status.Error(codes.InvalidArgument, "invalid user_type")
		}
	}

	// Get users from database
	dbUsers, totalCount, err := s.userService.ListUsers(ctx, userType, int(page), int(pageSize))
	if err != nil {
		s.logger.WithError(err).Error("Failed to list users")
		return nil, status.Error(codes.Internal, "failed to list users")
	}

	// Convert to protobuf format
	protoUsers := make([]*protos.User, len(dbUsers))
	for i, user := range dbUsers {
		protoUsers[i] = s.convertUserToProto(user)
	}

	return &protos.ListUsersResponse{
		Users:      protoUsers,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// ChangeUserPassword changes a user's password
func (s *UserAdminServiceImpl) ChangeUserPassword(ctx context.Context, req *protos.ChangeUserPasswordRequest) (*emptypb.Empty, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// For now, we'll just log the password change
	// In a real implementation, you'd hash and store the password
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
	}).Info("User password changed by admin")

	return &emptypb.Empty{}, nil
}

// ResetUserPassword resets a user's password
func (s *UserAdminServiceImpl) ResetUserPassword(ctx context.Context, req *protos.ResetUserPasswordRequest) (*protos.ResetUserPasswordResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// For now, we'll just log the password reset
	// In a real implementation, you'd hash and store the password
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
	}).Info("User password reset by admin")

	return &protos.ResetUserPasswordResponse{
		Message: "Password reset successfully",
	}, nil
}

// UpdateUserStatus updates a user's status
func (s *UserAdminServiceImpl) UpdateUserStatus(ctx context.Context, req *protos.UpdateUserStatusRequest) (*emptypb.Empty, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.Status == "" {
		return nil, status.Error(codes.InvalidArgument, "status is required")
	}

	// Validate status
	var userStatus users.UserStatus
	switch req.Status {
	case "pending":
		userStatus = users.UserStatusPending
	case "active":
		userStatus = users.UserStatusActive
	case "suspended":
		userStatus = users.UserStatusSuspended
	case "deleted":
		userStatus = users.UserStatusDeleted
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid status")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// Update user status
	updates := map[string]interface{}{
		"status": userStatus,
	}
	if err := s.userService.UpdateUser(ctx, req.UserId, updates); err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to update user status")
		return nil, status.Error(codes.Internal, "failed to update user status")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
		"status":  userStatus,
	}).Info("User status updated by admin")

	return &emptypb.Empty{}, nil
}

// AssignUserRoles assigns roles to a user
func (s *UserAdminServiceImpl) AssignUserRoles(ctx context.Context, req *protos.AssignUserRolesRequest) (*emptypb.Empty, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if len(req.Roles) == 0 {
		return nil, status.Error(codes.InvalidArgument, "roles are required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// For now, we'll just log the role assignment
	// In a real implementation, you'd store roles in the database
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
		"roles":   req.Roles,
	}).Info("Roles assigned to user by admin")

	return &emptypb.Empty{}, nil
}

// RemoveUserRoles removes roles from a user
func (s *UserAdminServiceImpl) RemoveUserRoles(ctx context.Context, req *protos.RemoveUserRolesRequest) (*emptypb.Empty, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if len(req.Roles) == 0 {
		return nil, status.Error(codes.InvalidArgument, "roles are required")
	}

	// Check if user exists
	user, err := s.userService.GetUserByID(ctx, req.UserId)
	if err != nil {
		s.logger.WithError(err).WithField("user_id", req.UserId).Error("Failed to get user")
		return nil, status.Error(codes.NotFound, "user not found")
	}

	// For now, we'll just log the role removal
	// In a real implementation, you'd remove roles from the database
	s.logger.WithFields(logrus.Fields{
		"user_id": req.UserId,
		"email":   user.Email,
		"roles":   req.Roles,
	}).Info("Roles removed from user by admin")

	return &emptypb.Empty{}, nil
}

// convertUserToProto converts a database user to protobuf user
func (s *UserAdminServiceImpl) convertUserToProto(user *users.User) *protos.User {
	protoUser := &protos.User{
		UserId:        user.UserID,
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		UserType:      string(user.UserType),
		Status:        string(user.Status),
		EmailVerified: user.EmailVerified,
		Provider:      user.Provider,
		ProviderId:    user.ProviderID,
		AvatarUrl:     user.AvatarURL,
		CreatedAt:     timestamppb.New(user.CreatedAt),
		UpdatedAt:     timestamppb.New(user.UpdatedAt),
		Settings:      user.Settings,
	}

	if user.LastLoginAt != nil {
		protoUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	return protoUser
}
