package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/email"
	"github.com/force1267/biarbala-go/pkg/users"
)

// IdentityProvider represents an identity provider
type IdentityProvider interface {
	GetAuthURL(state string) string
	ExchangeCodeForToken(ctx context.Context, code string) (*TokenResponse, error)
	GetUserInfo(ctx context.Context, accessToken string) (*ProviderUserInfo, error)
	GetName() string
}

// ProviderUserInfo represents user information from an identity provider
type ProviderUserInfo struct {
	ID            string
	Email         string
	Username      string
	FirstName     string
	LastName      string
	AvatarURL     string
	EmailVerified bool
	Provider      string
}

// IdentityService manages multiple identity providers
type IdentityService struct {
	providers       map[string]IdentityProvider
	userService     *users.UserService
	emailService    *email.EmailService
	jwtService      *JWTService
	logger          *logrus.Logger
	keycloakService *KeycloakService
}

// NewIdentityService creates a new identity service
func NewIdentityService(
	userService *users.UserService,
	emailService *email.EmailService,
	jwtService *JWTService,
	logger *logrus.Logger,
) *IdentityService {
	return &IdentityService{
		providers:    make(map[string]IdentityProvider),
		userService:  userService,
		emailService: emailService,
		jwtService:   jwtService,
		logger:       logger,
	}
}

// RegisterProvider registers an identity provider
func (s *IdentityService) RegisterProvider(name string, provider IdentityProvider) {
	s.providers[name] = provider
	s.logger.WithField("provider", name).Info("Registered identity provider")
}

// SetKeycloakService sets the Keycloak service
func (s *IdentityService) SetKeycloakService(keycloakService *KeycloakService) {
	s.keycloakService = keycloakService
}

// GetKeycloakService returns the Keycloak service
func (s *IdentityService) GetKeycloakService() *KeycloakService {
	return s.keycloakService
}

// GetProvider returns an identity provider by name
func (s *IdentityService) GetProvider(name string) (IdentityProvider, error) {
	provider, exists := s.providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found", name)
	}
	return provider, nil
}

// GetAuthURL gets the authorization URL for a provider
func (s *IdentityService) GetAuthURL(providerName, state string) (string, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	return provider.GetAuthURL(state), nil
}

// HandleCallback handles the OAuth callback
func (s *IdentityService) HandleCallback(ctx context.Context, providerName, code, state string) (*TokenResponse, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Exchange code for token
	tokenResp, err := provider.ExchangeCodeForToken(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from provider
	userInfo, err := provider.GetUserInfo(ctx, tokenResp.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Sync user with database
	user, err := s.syncUserFromProvider(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to sync user: %w", err)
	}

	// Generate JWT tokens
	jwtResp, err := s.jwtService.CreateTokenResponse(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	return jwtResp, nil
}

// syncUserFromProvider syncs user information from provider to database
func (s *IdentityService) syncUserFromProvider(ctx context.Context, providerUser *ProviderUserInfo) (*users.User, error) {
	// Check if user exists by provider ID
	user, err := s.userService.GetUserByEmail(ctx, providerUser.Email)
	if err != nil {
		// User doesn't exist, create new user
		return s.createUserFromProvider(ctx, providerUser)
	}

	// User exists, update information
	return s.updateUserFromProvider(ctx, user, providerUser)
}

// createUserFromProvider creates a new user from provider information
func (s *IdentityService) createUserFromProvider(ctx context.Context, providerUser *ProviderUserInfo) (*users.User, error) {
	// Generate unique user ID
	userID := fmt.Sprintf("user_%s_%s", providerUser.Provider, providerUser.ID)

	user := &users.User{
		UserID:        userID,
		Email:         providerUser.Email,
		Username:      providerUser.Username,
		FirstName:     providerUser.FirstName,
		LastName:      providerUser.LastName,
		UserType:      users.UserTypeUser, // Default to regular user
		Status:        users.UserStatusActive,
		EmailVerified: providerUser.EmailVerified,
		Provider:      providerUser.Provider,
		ProviderID:    providerUser.ID,
		AvatarURL:     providerUser.AvatarURL,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Settings:      make(map[string]string),
	}

	if err := s.userService.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":  user.UserID,
		"email":    user.Email,
		"provider": user.Provider,
	}).Info("Created new user from provider")

	return user, nil
}

// updateUserFromProvider updates existing user with provider information
func (s *IdentityService) updateUserFromProvider(ctx context.Context, user *users.User, providerUser *ProviderUserInfo) (*users.User, error) {
	updates := map[string]interface{}{
		"email":          providerUser.Email,
		"username":       providerUser.Username,
		"first_name":     providerUser.FirstName,
		"last_name":      providerUser.LastName,
		"email_verified": providerUser.EmailVerified,
		"avatar_url":     providerUser.AvatarURL,
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
		"user_id":  user.UserID,
		"email":    providerUser.Email,
		"provider": providerUser.Provider,
	}).Info("Updated user from provider")

	// Return updated user
	return s.userService.GetUserByID(ctx, user.UserID)
}

// RegisterWithEmail registers a user with email and password
func (s *IdentityService) RegisterWithEmail(ctx context.Context, email, password, firstName, lastName string) (*TokenResponse, error) {
	// Check if user already exists
	existingUser, err := s.userService.GetUserByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", email)
	}

	// Generate unique user ID
	userID := fmt.Sprintf("user_email_%d", time.Now().UnixNano())

	user := &users.User{
		UserID:        userID,
		Email:         email,
		Username:      email, // Use email as username for email registration
		FirstName:     firstName,
		LastName:      lastName,
		UserType:      users.UserTypeUser,
		Status:        users.UserStatusPending, // Require email verification
		EmailVerified: false,
		Provider:      "email",
		ProviderID:    userID,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Settings:      make(map[string]string),
	}

	if err := s.userService.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Send email verification
	verificationCode := s.generateVerificationCode()
	verification := &users.EmailVerification{
		UserID:    user.UserID,
		Email:     user.Email,
		Code:      verificationCode,
		Verified:  false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.userService.CreateEmailVerification(ctx, verification); err != nil {
		s.logger.WithError(err).Warn("Failed to create email verification")
	}

	if err := s.emailService.SendVerificationEmail(user.Email, verificationCode); err != nil {
		s.logger.WithError(err).Warn("Failed to send verification email")
	}

	s.logger.WithFields(logrus.Fields{
		"user_id": user.UserID,
		"email":   user.Email,
	}).Info("Created new user with email registration")

	// Generate JWT tokens (user will need to verify email)
	jwtResp, err := s.jwtService.CreateTokenResponse(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	return jwtResp, nil
}

// LoginWithEmail logs in a user with email and password
func (s *IdentityService) LoginWithEmail(ctx context.Context, email, password string) (*TokenResponse, error) {
	// Get user by email
	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if user.Status != users.UserStatusActive {
		return nil, fmt.Errorf("account is not active")
	}

	// For email provider, we would validate the password here
	// For now, we'll assume password validation is handled elsewhere
	// In a real implementation, you'd hash and compare passwords

	// Update last login
	if err := s.userService.UpdateLastLogin(ctx, user.UserID); err != nil {
		s.logger.WithError(err).Warn("Failed to update last login time")
	}

	// Generate JWT tokens
	jwtResp, err := s.jwtService.CreateTokenResponse(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	return jwtResp, nil
}

// SendOTP sends an OTP to the user's email
func (s *IdentityService) SendOTP(ctx context.Context, email, purpose string) error {
	// Generate OTP code
	otpCode := s.generateOTPCode()

	// Create OTP record
	otpRecord := &users.OTPRecord{
		UserID:    "", // Will be set when user is found
		Email:     email,
		Code:      otpCode,
		Purpose:   purpose,
		Used:      false,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute), // OTP expires in 10 minutes
	}

	// If user exists, set user ID
	if user, err := s.userService.GetUserByEmail(ctx, email); err == nil {
		otpRecord.UserID = user.UserID
	}

	if err := s.userService.CreateOTPRecord(ctx, otpRecord); err != nil {
		return fmt.Errorf("failed to create OTP record: %w", err)
	}

	// Send OTP email
	if err := s.emailService.SendOTPEmail(email, otpCode); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}

	s.logger.WithFields(logrus.Fields{
		"email":   email,
		"purpose": purpose,
	}).Info("OTP sent successfully")

	return nil
}

// VerifyOTP verifies an OTP code
func (s *IdentityService) VerifyOTP(ctx context.Context, email, code, purpose string) (*TokenResponse, error) {
	// Get OTP record
	otpRecord, err := s.userService.GetOTPRecord(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP code")
	}

	// Check if OTP is expired
	if otpRecord.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("OTP code has expired")
	}

	// Check if OTP is already used
	if otpRecord.Used {
		return nil, fmt.Errorf("OTP code has already been used")
	}

	// Check email matches
	if otpRecord.Email != email {
		return nil, fmt.Errorf("invalid OTP code")
	}

	// Check purpose matches
	if otpRecord.Purpose != purpose {
		return nil, fmt.Errorf("invalid OTP purpose")
	}

	// Mark OTP as used
	if err := s.userService.UseOTPRecord(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to use OTP record: %w", err)
	}

	// Get user
	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Update user status if needed
	if purpose == "email_verification" && user.Status == users.UserStatusPending {
		updates := map[string]interface{}{
			"status":         users.UserStatusActive,
			"email_verified": true,
			"updated_at":     time.Now(),
		}
		if err := s.userService.UpdateUser(ctx, user.UserID, updates); err != nil {
			s.logger.WithError(err).Warn("Failed to update user status")
		}
	}

	// Generate JWT tokens
	jwtResp, err := s.jwtService.CreateTokenResponse(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT tokens: %w", err)
	}

	return jwtResp, nil
}

// generateVerificationCode generates a random verification code
func (s *IdentityService) generateVerificationCode() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateOTPCode generates a random OTP code
func (s *IdentityService) generateOTPCode() string {
	bytes := make([]byte, 3)
	rand.Read(bytes)
	return fmt.Sprintf("%06d", int(bytes[0])<<16|int(bytes[1])<<8|int(bytes[2]))
}
