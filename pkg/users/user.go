package users

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
)

// UserType represents the type of user
type UserType string

const (
	UserTypePublic UserType = "public"
	UserTypeUser   UserType = "user"
	UserTypeAdmin  UserType = "admin"
)

// UserStatus represents the status of a user
type UserStatus string

const (
	UserStatusPending   UserStatus = "pending"
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

// User represents a user in the system (Keycloak-based)
type User struct {
	ID            string              `json:"id"`
	UserID        string              `json:"user_id"`
	Email         string              `json:"email"`
	Username      string              `json:"username"`
	FirstName     string              `json:"firstName,omitempty"`
	LastName      string              `json:"lastName,omitempty"`
	UserType      UserType            `json:"user_type"`
	Status        UserStatus          `json:"status"`
	EmailVerified bool                `json:"emailVerified"`
	Enabled       bool                `json:"enabled"`
	KeycloakID    string              `json:"keycloak_id,omitempty"`
	Provider      string              `json:"provider,omitempty"` // "keycloak", "github", "google", "email"
	ProviderID    string              `json:"provider_id,omitempty"`
	AvatarURL     string              `json:"avatar_url,omitempty"`
	CreatedAt     time.Time           `json:"createdTimestamp"`
	UpdatedAt     time.Time           `json:"updatedTimestamp"`
	LastLoginAt   *time.Time          `json:"lastLoginTimestamp,omitempty"`
	Attributes    map[string]string   `json:"attributes,omitempty"`
	RealmRoles    []string            `json:"realmRoles,omitempty"`
	ClientRoles   map[string][]string `json:"clientRoles,omitempty"`
	Settings      map[string]string   `json:"settings,omitempty"`
}

// EmailVerification represents an email verification record (stored in Keycloak attributes)
type EmailVerification struct {
	UserID     string     `json:"user_id"`
	Email      string     `json:"email"`
	Code       string     `json:"code"`
	Verified   bool       `json:"verified"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// OTPRecord represents an OTP (One-Time Password) record (stored in Keycloak attributes)
type OTPRecord struct {
	UserID    string     `json:"user_id"`
	Email     string     `json:"email"`
	Code      string     `json:"code"`
	Purpose   string     `json:"purpose"` // "email_verification", "password_reset", "login"
	Used      bool       `json:"used"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// PasswordReset represents a password reset record (stored in Keycloak attributes)
type PasswordReset struct {
	UserID    string     `json:"user_id"`
	Email     string     `json:"email"`
	Token     string     `json:"token"`
	Used      bool       `json:"used"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// UserService handles user-related operations using Keycloak Admin API
type UserService struct {
	config      *config.KeycloakConfig
	logger      *logrus.Logger
	httpClient  *http.Client
	adminToken  string
	tokenExpiry time.Time
}

// NewUserService creates a new user service
func NewUserService(cfg *config.KeycloakConfig, logger *logrus.Logger) *UserService {
	return &UserService{
		config: cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getAdminToken gets or refreshes the admin access token
func (s *UserService) getAdminToken(ctx context.Context) (string, error) {
	// Check if we have a valid token
	if s.adminToken != "" && time.Now().Before(s.tokenExpiry) {
		return s.adminToken, nil
	}

	// Get new token
	tokenURL := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", s.config.ServerURL)

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "admin-cli")
	data.Set("username", s.config.AdminUsername)
	data.Set("password", s.config.AdminPassword)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get admin token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get admin token, status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	s.adminToken = tokenResp.AccessToken
	s.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second) // Refresh 60s before expiry

	return s.adminToken, nil
}

// makeAdminRequest makes an authenticated request to Keycloak Admin API
func (s *UserService) makeAdminRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	token, err := s.getAdminToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin token: %w", err)
	}

	url := fmt.Sprintf("%s/admin/realms/%s%s", s.config.ServerURL, s.config.Realm, endpoint)

	var reqBody *strings.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = strings.NewReader(string(jsonBody))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	return s.httpClient.Do(req)
}

// CreateUser creates a new user in Keycloak
func (s *UserService) CreateUser(ctx context.Context, user *User) error {
	keycloakUser := map[string]interface{}{
		"username":      user.Username,
		"email":         user.Email,
		"firstName":     user.FirstName,
		"lastName":      user.LastName,
		"enabled":       user.Status == UserStatusActive,
		"emailVerified": user.EmailVerified,
		"attributes": map[string][]string{
			"user_type": {string(user.UserType)},
			"status":    {string(user.Status)},
		},
	}

	resp, err := s.makeAdminRequest(ctx, "POST", "/users", keycloakUser)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create user, status: %d", resp.StatusCode)
	}

	return nil
}

// GetUserByID retrieves a user by ID from Keycloak
func (s *UserService) GetUserByID(ctx context.Context, userID string) (*User, error) {
	resp, err := s.makeAdminRequest(ctx, "GET", "/users/"+userID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("user not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user, status: %d", resp.StatusCode)
	}

	var keycloakUser map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&keycloakUser); err != nil {
		return nil, fmt.Errorf("failed to decode user: %w", err)
	}

	return s.convertKeycloakUser(keycloakUser), nil
}

// GetUserByEmail retrieves a user by email from Keycloak
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	resp, err := s.makeAdminRequest(ctx, "GET", "/users?email="+url.QueryEscape(email), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user, status: %d", resp.StatusCode)
	}

	var users []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode users: %w", err)
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("user not found")
	}

	return s.convertKeycloakUser(users[0]), nil
}

// GetUserByKeycloakID retrieves a user by Keycloak ID (same as GetUserByID)
func (s *UserService) GetUserByKeycloakID(ctx context.Context, keycloakID string) (*User, error) {
	return s.GetUserByID(ctx, keycloakID)
}

// convertKeycloakUser converts a Keycloak user to our User struct
func (s *UserService) convertKeycloakUser(keycloakUser map[string]interface{}) *User {
	user := &User{
		ID:            getString(keycloakUser, "id"),
		UserID:        getString(keycloakUser, "id"),
		Email:         getString(keycloakUser, "email"),
		Username:      getString(keycloakUser, "username"),
		FirstName:     getString(keycloakUser, "firstName"),
		LastName:      getString(keycloakUser, "lastName"),
		EmailVerified: getBool(keycloakUser, "emailVerified"),
		Enabled:       getBool(keycloakUser, "enabled"),
		KeycloakID:    getString(keycloakUser, "id"),
		Provider:      "keycloak",
		ProviderID:    getString(keycloakUser, "id"),
		AvatarURL:     getString(keycloakUser, "picture"),
		Attributes:    make(map[string]string),
		RealmRoles:    getStringSlice(keycloakUser, "realmRoles"),
		ClientRoles:   getStringMapSlice(keycloakUser, "clientRoles"),
		Settings:      make(map[string]string),
	}

	// Convert timestamps
	if createdTimestamp, ok := keycloakUser["createdTimestamp"].(float64); ok {
		user.CreatedAt = time.Unix(int64(createdTimestamp)/1000, 0)
	}
	if updatedTimestamp, ok := keycloakUser["updatedTimestamp"].(float64); ok {
		user.UpdatedAt = time.Unix(int64(updatedTimestamp)/1000, 0)
	}
	if lastLoginTimestamp, ok := keycloakUser["lastLoginTimestamp"].(float64); ok {
		t := time.Unix(int64(lastLoginTimestamp)/1000, 0)
		user.LastLoginAt = &t
	}

	// Extract custom attributes
	if attributes, ok := keycloakUser["attributes"].(map[string]interface{}); ok {
		if userType, exists := attributes["user_type"]; exists {
			if userTypeSlice, ok := userType.([]interface{}); ok && len(userTypeSlice) > 0 {
				user.UserType = UserType(userTypeSlice[0].(string))
			}
		}
		if status, exists := attributes["status"]; exists {
			if statusSlice, ok := status.([]interface{}); ok && len(statusSlice) > 0 {
				user.Status = UserStatus(statusSlice[0].(string))
			}
		}
	}

	// Set default values if not set
	if user.UserType == "" {
		user.UserType = UserTypeUser
	}
	if user.Status == "" {
		if user.Enabled {
			user.Status = UserStatusActive
		} else {
			user.Status = UserStatusSuspended
		}
	}

	return user
}

// Helper functions for type conversion
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}

func getStringSlice(m map[string]interface{}, key string) []string {
	if val, ok := m[key].([]interface{}); ok {
		result := make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return nil
}

func getStringMapSlice(m map[string]interface{}, key string) map[string][]string {
	if val, ok := m[key].(map[string]interface{}); ok {
		result := make(map[string][]string)
		for k, v := range val {
			if slice, ok := v.([]interface{}); ok {
				strSlice := make([]string, len(slice))
				for i, item := range slice {
					if str, ok := item.(string); ok {
						strSlice[i] = str
					}
				}
				result[k] = strSlice
			}
		}
		return result
	}
	return nil
}

// UpdateUser updates a user in Keycloak
func (s *UserService) UpdateUser(ctx context.Context, userID string, updates map[string]interface{}) error {
	// Convert our updates to Keycloak format
	keycloakUpdates := make(map[string]interface{})

	for key, value := range updates {
		switch key {
		case "email":
			keycloakUpdates["email"] = value
		case "username":
			keycloakUpdates["username"] = value
		case "first_name":
			keycloakUpdates["firstName"] = value
		case "last_name":
			keycloakUpdates["lastName"] = value
		case "email_verified":
			keycloakUpdates["emailVerified"] = value
		case "status":
			// Convert status to enabled field
			if status, ok := value.(UserStatus); ok {
				keycloakUpdates["enabled"] = status == UserStatusActive
			}
		case "user_type", "last_login_at":
			// These are stored in attributes
			if keycloakUpdates["attributes"] == nil {
				keycloakUpdates["attributes"] = make(map[string][]string)
			}
			attrs := keycloakUpdates["attributes"].(map[string][]string)
			attrs[key] = []string{fmt.Sprintf("%v", value)}
		}
	}

	resp, err := s.makeAdminRequest(ctx, "PUT", "/users/"+userID, keycloakUpdates)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to update user, status: %d", resp.StatusCode)
	}

	return nil
}

// DeleteUser soft deletes a user (disables them in Keycloak)
func (s *UserService) DeleteUser(ctx context.Context, userID string) error {
	updates := map[string]interface{}{
		"enabled": false,
		"attributes": map[string][]string{
			"status": {string(UserStatusDeleted)},
		},
	}

	resp, err := s.makeAdminRequest(ctx, "PUT", "/users/"+userID, updates)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to delete user, status: %d", resp.StatusCode)
	}

	return nil
}

// ListUsers lists users with pagination from Keycloak
func (s *UserService) ListUsers(ctx context.Context, userType UserType, page, pageSize int) ([]*User, int64, error) {
	// Calculate pagination parameters
	first := (page - 1) * pageSize
	max := pageSize

	endpoint := fmt.Sprintf("/users?first=%d&max=%d", first, max)

	resp, err := s.makeAdminRequest(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("failed to list users, status: %d", resp.StatusCode)
	}

	var keycloakUsers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&keycloakUsers); err != nil {
		return nil, 0, fmt.Errorf("failed to decode users: %w", err)
	}

	// Convert to our User structs
	users := make([]*User, 0, len(keycloakUsers))
	for _, keycloakUser := range keycloakUsers {
		user := s.convertKeycloakUser(keycloakUser)

		// Filter by user type if specified
		if userType == "" || user.UserType == userType {
			users = append(users, user)
		}
	}

	// Note: Keycloak doesn't provide total count in the same request
	// For now, we'll return the count of filtered results
	// In production, you might want to make a separate count request
	totalCount := int64(len(users))

	return users, totalCount, nil
}

// CreateEmailVerification creates an email verification record (stored as user attribute)
func (s *UserService) CreateEmailVerification(ctx context.Context, verification *EmailVerification) error {
	// Store verification data as user attributes
	verificationData := map[string]interface{}{
		"code":       verification.Code,
		"verified":   verification.Verified,
		"created_at": verification.CreatedAt.Format(time.RFC3339),
		"expires_at": verification.ExpiresAt.Format(time.RFC3339),
	}

	verificationJSON, err := json.Marshal(verificationData)
	if err != nil {
		return fmt.Errorf("failed to marshal verification data: %w", err)
	}

	updates := map[string]interface{}{
		"attributes": map[string][]string{
			"email_verification": {string(verificationJSON)},
		},
	}

	resp, err := s.makeAdminRequest(ctx, "PUT", "/users/"+verification.UserID, updates)
	if err != nil {
		return fmt.Errorf("failed to create email verification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to create email verification, status: %d", resp.StatusCode)
	}

	return nil
}

// GetEmailVerification retrieves an email verification record from user attributes
func (s *UserService) GetEmailVerification(ctx context.Context, code string) (*EmailVerification, error) {
	// This is a simplified implementation - in practice, you'd need to search through users
	// For now, we'll return an error indicating this needs to be implemented differently
	return nil, fmt.Errorf("email verification lookup by code not implemented - use user ID instead")
}

// VerifyEmail marks an email as verified
func (s *UserService) VerifyEmail(ctx context.Context, code string) error {
	// This would need to be implemented by finding the user with the verification code
	// For now, we'll return an error indicating this needs to be implemented differently
	return fmt.Errorf("email verification by code not implemented - use user ID instead")
}

// CreateOTPRecord creates an OTP record (stored as user attribute)
func (s *UserService) CreateOTPRecord(ctx context.Context, otp *OTPRecord) error {
	// Store OTP data as user attributes
	otpData := map[string]interface{}{
		"code":       otp.Code,
		"purpose":    otp.Purpose,
		"used":       otp.Used,
		"created_at": otp.CreatedAt.Format(time.RFC3339),
		"expires_at": otp.ExpiresAt.Format(time.RFC3339),
	}

	otpJSON, err := json.Marshal(otpData)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP data: %w", err)
	}

	updates := map[string]interface{}{
		"attributes": map[string][]string{
			"otp_record": {string(otpJSON)},
		},
	}

	resp, err := s.makeAdminRequest(ctx, "PUT", "/users/"+otp.UserID, updates)
	if err != nil {
		return fmt.Errorf("failed to create OTP record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to create OTP record, status: %d", resp.StatusCode)
	}

	return nil
}

// GetOTPRecord retrieves an OTP record from user attributes
func (s *UserService) GetOTPRecord(ctx context.Context, code string) (*OTPRecord, error) {
	// This is a simplified implementation - in practice, you'd need to search through users
	// For now, we'll return an error indicating this needs to be implemented differently
	return nil, fmt.Errorf("OTP record lookup by code not implemented - use user ID instead")
}

// UseOTPRecord marks an OTP as used
func (s *UserService) UseOTPRecord(ctx context.Context, code string) error {
	// This would need to be implemented by finding the user with the OTP code
	// For now, we'll return an error indicating this needs to be implemented differently
	return fmt.Errorf("OTP usage by code not implemented - use user ID instead")
}

// CreatePasswordReset creates a password reset record (stored as user attribute)
func (s *UserService) CreatePasswordReset(ctx context.Context, reset *PasswordReset) error {
	// Store password reset data as user attributes
	resetData := map[string]interface{}{
		"token":      reset.Token,
		"used":       reset.Used,
		"created_at": reset.CreatedAt.Format(time.RFC3339),
		"expires_at": reset.ExpiresAt.Format(time.RFC3339),
	}

	resetJSON, err := json.Marshal(resetData)
	if err != nil {
		return fmt.Errorf("failed to marshal password reset data: %w", err)
	}

	updates := map[string]interface{}{
		"attributes": map[string][]string{
			"password_reset": {string(resetJSON)},
		},
	}

	resp, err := s.makeAdminRequest(ctx, "PUT", "/users/"+reset.UserID, updates)
	if err != nil {
		return fmt.Errorf("failed to create password reset: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("failed to create password reset, status: %d", resp.StatusCode)
	}

	return nil
}

// GetPasswordReset retrieves a password reset record from user attributes
func (s *UserService) GetPasswordReset(ctx context.Context, token string) (*PasswordReset, error) {
	// This is a simplified implementation - in practice, you'd need to search through users
	// For now, we'll return an error indicating this needs to be implemented differently
	return nil, fmt.Errorf("password reset lookup by token not implemented - use user ID instead")
}

// UsePasswordReset marks a password reset as used
func (s *UserService) UsePasswordReset(ctx context.Context, token string) error {
	// This would need to be implemented by finding the user with the reset token
	// For now, we'll return an error indicating this needs to be implemented differently
	return fmt.Errorf("password reset usage by token not implemented - use user ID instead")
}

// UpdateLastLogin updates the user's last login time
func (s *UserService) UpdateLastLogin(ctx context.Context, userID string) error {
	now := time.Now()
	updates := map[string]interface{}{
		"last_login_at": now.Format(time.RFC3339),
	}

	return s.UpdateUser(ctx, userID, updates)
}

// IsAdmin checks if a user is an admin
func (s *UserService) IsAdmin(ctx context.Context, userID string) (bool, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}

	return user.UserType == UserTypeAdmin, nil
}

// Close closes the service (no-op for Keycloak)
func (s *UserService) Close(ctx context.Context) error {
	// No connection to close for Keycloak HTTP client
	return nil
}
