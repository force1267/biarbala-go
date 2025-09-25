package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/config"
	"github.com/force1267/biarbala-go/pkg/users"
)

// JWTService handles JWT token operations
type JWTService struct {
	config      *config.JWTConfig
	logger      *logrus.Logger
	userService *users.UserService
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID     string         `json:"user_id"`
	Email      string         `json:"email"`
	UserType   users.UserType `json:"user_type"`
	Provider   string         `json:"provider"`
	KeycloakID string         `json:"keycloak_id,omitempty"`
	jwt.RegisteredClaims
}

// NewJWTService creates a new JWT service
func NewJWTService(cfg *config.JWTConfig, logger *logrus.Logger, userService *users.UserService) *JWTService {
	return &JWTService{
		config:      cfg,
		logger:      logger,
		userService: userService,
	}
}

// GenerateToken generates a JWT token for a user
func (s *JWTService) GenerateToken(user *users.User) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.Expiration)

	claims := JWTClaims{
		UserID:     user.UserID,
		Email:      user.Email,
		UserType:   user.UserType,
		Provider:   user.Provider,
		KeycloakID: user.KeycloakID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "biarbala",
			Subject:   user.UserID,
			Audience:  []string{"biarbala-api"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.SecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateRefreshToken generates a refresh token for a user
func (s *JWTService) GenerateRefreshToken(user *users.User) (string, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.RefreshExpiration)

	claims := JWTClaims{
		UserID:     user.UserID,
		Email:      user.Email,
		UserType:   user.UserType,
		Provider:   user.Provider,
		KeycloakID: user.KeycloakID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "biarbala",
			Subject:   user.UserID,
			Audience:  []string{"biarbala-refresh"},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.SecretKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("token has expired")
	}

	return claims, nil
}

// RefreshToken validates a refresh token and generates a new access token
func (s *JWTService) RefreshToken(refreshTokenString string) (string, error) {
	claims, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %w", err)
	}

	// Check if this is a refresh token (audience should be biarbala-refresh)
	if len(claims.Audience) == 0 || claims.Audience[0] != "biarbala-refresh" {
		return "", errors.New("invalid refresh token audience")
	}

	// Get user from database to ensure they still exist and are active
	user, err := s.userService.GetUserByID(nil, claims.UserID)
	if err != nil {
		return "", fmt.Errorf("user not found: %w", err)
	}

	if user.Status != users.UserStatusActive {
		return "", errors.New("user account is not active")
	}

	// Generate new access token
	newToken, err := s.GenerateToken(user)
	if err != nil {
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}

	return newToken, nil
}

// GetUserFromToken extracts user information from a JWT token
func (s *JWTService) GetUserFromToken(tokenString string) (*users.User, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	// Get user from database to ensure they still exist and are active
	user, err := s.userService.GetUserByID(nil, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if user.Status != users.UserStatusActive {
		return nil, errors.New("user account is not active")
	}

	return user, nil
}

// IsAdmin checks if the token belongs to an admin user
func (s *JWTService) IsAdmin(tokenString string) (bool, error) {
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		return false, err
	}

	return claims.UserType == users.UserTypeAdmin, nil
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func (s *JWTService) ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is missing")
	}

	// Check if header starts with "Bearer "
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", errors.New("invalid authorization header format")
	}

	token := authHeader[7:]
	if token == "" {
		return "", errors.New("token is empty")
	}

	return token, nil
}

// GenerateTokenPair generates both access and refresh tokens
func (s *JWTService) GenerateTokenPair(user *users.User) (string, string, error) {
	accessToken, err := s.GenerateToken(user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.GenerateRefreshToken(user)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

// TokenResponse represents the response containing tokens
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// CreateTokenResponse creates a token response
func (s *JWTService) CreateTokenResponse(user *users.User) (*TokenResponse, error) {
	accessToken, refreshToken, err := s.GenerateTokenPair(user)
	if err != nil {
		return nil, err
	}

	expiresIn := int64(s.config.Expiration.Seconds())

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
	}, nil
}
