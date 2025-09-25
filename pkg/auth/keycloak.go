package auth

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
	"github.com/force1267/biarbala-go/pkg/users"
)

// KeycloakService handles Keycloak authentication
type KeycloakService struct {
	config      *config.KeycloakConfig
	logger      *logrus.Logger
	userService *users.UserService
	httpClient  *http.Client
}

// KeycloakTokenResponse represents the token response from Keycloak
type KeycloakTokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}

// KeycloakUserInfo represents user information from Keycloak
type KeycloakUserInfo struct {
	Sub               string              `json:"sub"`
	Email             string              `json:"email"`
	EmailVerified     bool                `json:"email_verified"`
	PreferredUsername string              `json:"preferred_username"`
	GivenName         string              `json:"given_name"`
	FamilyName        string              `json:"family_name"`
	Name              string              `json:"name"`
	Picture           string              `json:"picture"`
	RealmRoles        []string            `json:"realm_roles"`
	ClientRoles       map[string][]string `json:"client_roles"`
}

// NewKeycloakService creates a new Keycloak service
func NewKeycloakService(cfg *config.KeycloakConfig, logger *logrus.Logger, userService *users.UserService) *KeycloakService {
	return &KeycloakService{
		config:      cfg,
		logger:      logger,
		userService: userService,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetName returns the provider name
func (s *KeycloakService) GetName() string {
	return "keycloak"
}

// GetAuthURL generates the authorization URL for Keycloak
func (s *KeycloakService) GetAuthURL(state string) string {
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", s.config.ServerURL, s.config.Realm)

	params := url.Values{}
	params.Set("client_id", s.config.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("redirect_uri", s.config.RedirectURL)
	params.Set("state", state)

	return authURL + "?" + params.Encode()
}

// GetAuthURLWithProvider generates the authorization URL for Keycloak with a specific identity provider
func (s *KeycloakService) GetAuthURLWithProvider(state, provider string) string {
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", s.config.ServerURL, s.config.Realm)

	params := url.Values{}
	params.Set("client_id", s.config.ClientID)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("redirect_uri", s.config.RedirectURL)
	params.Set("state", state)
	params.Set("kc_idp_hint", provider) // This tells Keycloak to use the specific identity provider

	return authURL + "?" + params.Encode()
}

// ExchangeCodeForToken exchanges authorization code for access token
func (s *KeycloakService) ExchangeCodeForToken(ctx context.Context, code string) (*TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.config.ServerURL, s.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", s.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    int64(tokenResp.ExpiresIn),
	}, nil
}

// RefreshToken refreshes an access token using refresh token
func (s *KeycloakService) RefreshToken(ctx context.Context, refreshToken string) (*KeycloakTokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.config.ServerURL, s.config.Realm)

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	return &tokenResp, nil
}

// GetUserInfo retrieves user information from Keycloak
func (s *KeycloakService) GetUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", s.config.ServerURL, s.config.Realm)

	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status: %d", resp.StatusCode)
	}

	var userInfo KeycloakUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode userinfo response: %w", err)
	}

	return &ProviderUserInfo{
		ID:            userInfo.Sub,
		Email:         userInfo.Email,
		Username:      userInfo.PreferredUsername,
		FirstName:     userInfo.GivenName,
		LastName:      userInfo.FamilyName,
		AvatarURL:     userInfo.Picture,
		EmailVerified: userInfo.EmailVerified,
		Provider:      "keycloak",
	}, nil
}

// Logout logs out a user from Keycloak
func (s *KeycloakService) Logout(ctx context.Context, refreshToken string) error {
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", s.config.ServerURL, s.config.Realm)

	data := url.Values{}
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, "POST", logoutURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("logout failed with status: %d", resp.StatusCode)
	}

	return nil
}

// SyncUser syncs user information from Keycloak to local database
func (s *KeycloakService) SyncUser(ctx context.Context, keycloakUser *KeycloakUserInfo) (*users.User, error) {
	// Check if user exists by Keycloak ID
	user, err := s.userService.GetUserByKeycloakID(ctx, keycloakUser.Sub)
	if err != nil {
		// User doesn't exist, create new user
		return s.createUserFromKeycloak(ctx, keycloakUser)
	}

	// User exists, update information
	return s.updateUserFromKeycloak(ctx, user, keycloakUser)
}

// createUserFromKeycloak creates a new user from Keycloak information
func (s *KeycloakService) createUserFromKeycloak(ctx context.Context, keycloakUser *KeycloakUserInfo) (*users.User, error) {
	// Determine user type based on roles
	userType := users.UserTypeUser
	if s.isAdmin(keycloakUser) {
		userType = users.UserTypeAdmin
	}

	// Generate unique user ID
	userID := fmt.Sprintf("user_%s", keycloakUser.Sub)

	user := &users.User{
		UserID:        userID,
		Email:         keycloakUser.Email,
		Username:      keycloakUser.PreferredUsername,
		FirstName:     keycloakUser.GivenName,
		LastName:      keycloakUser.FamilyName,
		UserType:      userType,
		Status:        users.UserStatusActive,
		EmailVerified: keycloakUser.EmailVerified,
		KeycloakID:    keycloakUser.Sub,
		Provider:      "keycloak",
		ProviderID:    keycloakUser.Sub,
		AvatarURL:     keycloakUser.Picture,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Settings:      make(map[string]string),
	}

	if err := s.userService.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":     user.UserID,
		"email":       user.Email,
		"user_type":   user.UserType,
		"keycloak_id": user.KeycloakID,
	}).Info("Created new user from Keycloak")

	return user, nil
}

// updateUserFromKeycloak updates existing user with Keycloak information
func (s *KeycloakService) updateUserFromKeycloak(ctx context.Context, user *users.User, keycloakUser *KeycloakUserInfo) (*users.User, error) {
	// Determine user type based on roles
	userType := users.UserTypeUser
	if s.isAdmin(keycloakUser) {
		userType = users.UserTypeAdmin
	}

	updates := map[string]interface{}{
		"email":          keycloakUser.Email,
		"username":       keycloakUser.PreferredUsername,
		"first_name":     keycloakUser.GivenName,
		"last_name":      keycloakUser.FamilyName,
		"user_type":      userType,
		"email_verified": keycloakUser.EmailVerified,
		"avatar_url":     keycloakUser.Picture,
		"updated_at":     time.Now(),
	}

	if err := s.userService.UpdateUser(ctx, user.UserID, updates); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Update last login
	if err := s.userService.UpdateLastLogin(ctx, user.UserID); err != nil {
		s.logger.WithError(err).Warn("Failed to update last login time")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":   user.UserID,
		"email":     keycloakUser.Email,
		"user_type": userType,
	}).Info("Updated user from Keycloak")

	// Return updated user
	return s.userService.GetUserByID(ctx, user.UserID)
}

// isAdmin checks if the Keycloak user has admin privileges
func (s *KeycloakService) isAdmin(keycloakUser *KeycloakUserInfo) bool {
	// Check realm roles
	for _, role := range keycloakUser.RealmRoles {
		if role == "admin" || role == "realm-admin" {
			return true
		}
	}

	// Check client roles
	if clientRoles, exists := keycloakUser.ClientRoles[s.config.ClientID]; exists {
		for _, role := range clientRoles {
			if role == "admin" {
				return true
			}
		}
	}

	return false
}

// ValidateToken validates a JWT token with Keycloak
func (s *KeycloakService) ValidateToken(ctx context.Context, token string) (*KeycloakUserInfo, error) {
	// For now, we'll use the userinfo endpoint to validate the token
	// In production, you might want to use proper JWT validation
	providerUserInfo, err := s.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// Convert ProviderUserInfo to KeycloakUserInfo
	return &KeycloakUserInfo{
		Sub:               providerUserInfo.ID,
		Email:             providerUserInfo.Email,
		EmailVerified:     providerUserInfo.EmailVerified,
		PreferredUsername: providerUserInfo.Username,
		GivenName:         providerUserInfo.FirstName,
		FamilyName:        providerUserInfo.LastName,
		Name:              providerUserInfo.FirstName + " " + providerUserInfo.LastName,
		Picture:           providerUserInfo.AvatarURL,
	}, nil
}

// GetLogoutURL generates the logout URL for Keycloak
func (s *KeycloakService) GetLogoutURL() string {
	logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", s.config.ServerURL, s.config.Realm)

	params := url.Values{}
	params.Set("client_id", s.config.ClientID)
	params.Set("post_logout_redirect_uri", s.config.LogoutURL)

	return logoutURL + "?" + params.Encode()
}
