package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/force1267/biarbala-go/pkg/users"
)

// AccessLevel represents the required access level for an endpoint
type AccessLevel string

const (
	AccessLevelPublic AccessLevel = "public"
	AccessLevelUser   AccessLevel = "user"
	AccessLevelAdmin  AccessLevel = "admin"
)

// AuthMiddleware handles authentication and authorization
type AuthMiddleware struct {
	jwtService      *JWTService
	keycloakService *KeycloakService
	logger          *logrus.Logger
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(jwtService *JWTService, keycloakService *KeycloakService, logger *logrus.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService:      jwtService,
		keycloakService: keycloakService,
		logger:          logger,
	}
}

// RequireAuth creates middleware that requires authentication
func (m *AuthMiddleware) RequireAuth(accessLevel AccessLevel) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			token, err := m.jwtService.ExtractTokenFromHeader(authHeader)
			if err != nil {
				m.logger.WithError(err).Debug("Failed to extract token from header")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Validate token and get user
			user, err := m.jwtService.GetUserFromToken(token)
			if err != nil {
				m.logger.WithError(err).Debug("Failed to validate token")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check access level
			if !m.hasAccess(user, accessLevel) {
				m.logger.WithFields(logrus.Fields{
					"user_id":      user.UserID,
					"user_type":    user.UserType,
					"access_level": accessLevel,
				}).Warn("Access denied")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), "user", user)
			ctx = context.WithValue(ctx, "user_id", user.UserID)
			ctx = context.WithValue(ctx, "user_type", user.UserType)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth creates middleware that optionally authenticates users
func (m *AuthMiddleware) OptionalAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				token, err := m.jwtService.ExtractTokenFromHeader(authHeader)
				if err == nil {
					// Validate token and get user
					user, err := m.jwtService.GetUserFromToken(token)
					if err == nil {
						// Add user to context
						ctx := context.WithValue(r.Context(), "user", user)
						ctx = context.WithValue(ctx, "user_id", user.UserID)
						ctx = context.WithValue(ctx, "user_type", user.UserType)
						r = r.WithContext(ctx)
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin creates middleware that requires admin access
func (m *AuthMiddleware) RequireAdmin() func(http.Handler) http.Handler {
	return m.RequireAuth(AccessLevelAdmin)
}

// RequireUser creates middleware that requires user access
func (m *AuthMiddleware) RequireUser() func(http.Handler) http.Handler {
	return m.RequireAuth(AccessLevelUser)
}

// RequirePublic creates middleware that allows public access
func (m *AuthMiddleware) RequirePublic() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}

// hasAccess checks if a user has the required access level
func (m *AuthMiddleware) hasAccess(user *users.User, requiredLevel AccessLevel) bool {
	switch requiredLevel {
	case AccessLevelPublic:
		return true
	case AccessLevelUser:
		return user.UserType == users.UserTypeUser || user.UserType == users.UserTypeAdmin
	case AccessLevelAdmin:
		return user.UserType == users.UserTypeAdmin
	default:
		return false
	}
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) (*users.User, bool) {
	user, ok := ctx.Value("user").(*users.User)
	return user, ok
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value("user_id").(string)
	return userID, ok
}

// GetUserTypeFromContext extracts user type from request context
func GetUserTypeFromContext(ctx context.Context) (users.UserType, bool) {
	userType, ok := ctx.Value("user_type").(users.UserType)
	return userType, ok
}

// IsAdmin checks if the current user is an admin
func IsAdmin(ctx context.Context) bool {
	userType, ok := GetUserTypeFromContext(ctx)
	return ok && userType == users.UserTypeAdmin
}

// IsAuthenticated checks if the current user is authenticated
func IsAuthenticated(ctx context.Context) bool {
	_, ok := GetUserFromContext(ctx)
	return ok
}

// RequireAuthGRPC creates gRPC interceptor for authentication
func (m *AuthMiddleware) RequireAuthGRPC(accessLevel AccessLevel) func(ctx context.Context, req interface{}, info interface{}, handler interface{}) (interface{}, error) {
	return func(ctx context.Context, req interface{}, info interface{}, handler interface{}) (interface{}, error) {
		// Extract token from metadata (this would need to be implemented based on your gRPC setup)
		// For now, we'll return an error indicating authentication is required
		return nil, fmt.Errorf("gRPC authentication not implemented yet")
	}
}

// CORSHandler handles CORS for authentication endpoints
func (m *AuthMiddleware) CORSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuthError represents an authentication error
type AuthError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// WriteAuthError writes an authentication error response
func WriteAuthError(w http.ResponseWriter, statusCode int, message string, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	authError := AuthError{
		Code:    statusCode,
		Message: message,
	}

	if err != nil {
		authError.Error = err.Error()
	}

	json.NewEncoder(w).Encode(authError)
}
