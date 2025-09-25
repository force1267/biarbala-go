package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Storage  StorageConfig  `mapstructure:"storage"`
	Cache    CacheConfig    `mapstructure:"cache"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Upload   UploadConfig   `mapstructure:"upload"`
	Security SecurityConfig `mapstructure:"security"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Email    EmailConfig    `mapstructure:"email"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	GRPC   GRPCConfig   `mapstructure:"grpc"`
	HTTP   HTTPConfig   `mapstructure:"http"`
	Static StaticConfig `mapstructure:"static"`
}

// GRPCConfig holds gRPC server configuration
type GRPCConfig struct {
	Port             int    `mapstructure:"port"`
	Host             string `mapstructure:"host"`
	EnableReflection bool   `mapstructure:"enable_reflection"`
	EnableWebGRPC    bool   `mapstructure:"enable_web_grpc"`
}

// HTTPConfig holds HTTP server configuration
type HTTPConfig struct {
	Port int    `mapstructure:"port"`
	Host string `mapstructure:"host"`
}

// StaticConfig holds static file serving configuration
type StaticConfig struct {
	UploadDir string `mapstructure:"upload_dir"`
	ServeDir  string `mapstructure:"serve_dir"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	MongoDB    MongoDBConfig    `mapstructure:"mongodb"`
	PostgreSQL PostgreSQLConfig `mapstructure:"postgresql"`
}

// StorageConfig holds object storage configuration
type StorageConfig struct {
	MinIO MinIOConfig `mapstructure:"minio"`
}

// MinIOConfig holds MinIO configuration
type MinIOConfig struct {
	Endpoint   string `mapstructure:"endpoint"`
	AccessKey  string `mapstructure:"access_key"`
	SecretKey  string `mapstructure:"secret_key"`
	UseSSL     bool   `mapstructure:"use_ssl"`
	BucketName string `mapstructure:"bucket_name"`
}

// MongoDBConfig holds MongoDB configuration
type MongoDBConfig struct {
	URI      string        `mapstructure:"uri"`
	Database string        `mapstructure:"database"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// PostgreSQLConfig holds PostgreSQL configuration
type PostgreSQLConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Redis RedisConfig `mapstructure:"redis"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Addr     string        `mapstructure:"addr"`
	Password string        `mapstructure:"password"`
	DB       int           `mapstructure:"db"`
	Timeout  time.Duration `mapstructure:"timeout"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Prometheus PrometheusConfig `mapstructure:"prometheus"`
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    int    `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

// UploadConfig holds file upload configuration
type UploadConfig struct {
	MaxFileSize    string   `mapstructure:"max_file_size"`
	AllowedFormats []string `mapstructure:"allowed_formats"`
	TempDir        string   `mapstructure:"temp_dir"`
}

// SecurityConfig holds security configuration
type SecurityConfig struct {
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RequestsPerMinute int  `mapstructure:"requests_per_minute"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Keycloak KeycloakConfig `mapstructure:"keycloak"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	// GitHub and Google OAuth are now configured in Keycloak as identity providers
}

// KeycloakConfig holds Keycloak configuration
type KeycloakConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	ServerURL     string `mapstructure:"server_url"`
	Realm         string `mapstructure:"realm"`
	ClientID      string `mapstructure:"client_id"`
	ClientSecret  string `mapstructure:"client_secret"`
	AdminUsername string `mapstructure:"admin_username"`
	AdminPassword string `mapstructure:"admin_password"`
	RedirectURL   string `mapstructure:"redirect_url"`
	LogoutURL     string `mapstructure:"logout_url"`
	Database      string `mapstructure:"database"` // dev-file, dev-mem, postgres
	DBURL         string `mapstructure:"db_url"`   // Database connection URL
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey         string        `mapstructure:"secret_key"`
	Expiration        time.Duration `mapstructure:"expiration"`
	RefreshExpiration time.Duration `mapstructure:"refresh_expiration"`
}

// GitHub and Google OAuth configurations are now handled in Keycloak as identity providers

// EmailConfig holds email configuration
type EmailConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`
	UseTLS       bool   `mapstructure:"use_tls"`
	FromEmail    string `mapstructure:"from_email"`
	FromName     string `mapstructure:"from_name"`
	BaseURL      string `mapstructure:"base_url"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Set default values
	setDefaults()

	// Enable reading from environment variables
	viper.AutomaticEnv()

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	viper.SetDefault("server.grpc.port", 8080)
	viper.SetDefault("server.grpc.host", "0.0.0.0")
	viper.SetDefault("server.grpc.enable_reflection", true)
	viper.SetDefault("server.grpc.enable_web_grpc", true)
	viper.SetDefault("server.http.port", 8081)
	viper.SetDefault("server.http.host", "0.0.0.0")
	viper.SetDefault("server.static.upload_dir", "./uploads")
	viper.SetDefault("server.static.serve_dir", "./served")

	viper.SetDefault("database.mongodb.uri", "mongodb://localhost:27017")
	viper.SetDefault("database.mongodb.database", "biarbala")
	viper.SetDefault("database.mongodb.timeout", "30s")

	viper.SetDefault("database.postgresql.host", "localhost")
	viper.SetDefault("database.postgresql.port", 5432)
	viper.SetDefault("database.postgresql.database", "keycloak")
	viper.SetDefault("database.postgresql.username", "keycloak")
	viper.SetDefault("database.postgresql.password", "keycloak")
	viper.SetDefault("database.postgresql.ssl_mode", "disable")

	viper.SetDefault("storage.minio.endpoint", "localhost:9000")
	viper.SetDefault("storage.minio.access_key", "minioadmin")
	viper.SetDefault("storage.minio.secret_key", "minioadmin")
	viper.SetDefault("storage.minio.use_ssl", false)
	viper.SetDefault("storage.minio.bucket_name", "biarbala")

	viper.SetDefault("cache.redis.addr", "localhost:6379")
	viper.SetDefault("cache.redis.password", "")
	viper.SetDefault("cache.redis.db", 0)
	viper.SetDefault("cache.redis.timeout", "30s")

	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.output", "stdout")

	viper.SetDefault("metrics.prometheus.enabled", true)
	viper.SetDefault("metrics.prometheus.port", 9090)
	viper.SetDefault("metrics.prometheus.path", "/metrics")

	viper.SetDefault("upload.max_file_size", "100MB")
	viper.SetDefault("upload.allowed_formats", []string{"tar", "gz", "zip"})
	viper.SetDefault("upload.temp_dir", "./temp")

	viper.SetDefault("security.rate_limit.enabled", true)
	viper.SetDefault("security.rate_limit.requests_per_minute", 60)

	viper.SetDefault("auth.keycloak.enabled", true)
	viper.SetDefault("auth.keycloak.server_url", "http://localhost:8082")
	viper.SetDefault("auth.keycloak.realm", "biarbala")
	viper.SetDefault("auth.keycloak.client_id", "biarbala-client")
	viper.SetDefault("auth.keycloak.client_secret", "biarbala-secret")
	viper.SetDefault("auth.keycloak.admin_username", "admin")
	viper.SetDefault("auth.keycloak.admin_password", "admin123")
	viper.SetDefault("auth.keycloak.redirect_url", "http://localhost:8081/auth/callback")
	viper.SetDefault("auth.keycloak.logout_url", "http://localhost:8081/auth/logout")
	viper.SetDefault("auth.keycloak.database", "dev-file") // dev-file, dev-mem, postgres
	viper.SetDefault("auth.keycloak.db_url", "jdbc:postgresql://localhost:5432/keycloak")

	viper.SetDefault("auth.jwt.secret_key", "biarbala-jwt-secret-key-change-in-production")
	viper.SetDefault("auth.jwt.expiration", "24h")
	viper.SetDefault("auth.jwt.refresh_expiration", "168h") // 7 days
	// GitHub and Google OAuth configurations are now handled in Keycloak

	viper.SetDefault("email.enabled", false)
	viper.SetDefault("email.smtp_host", "localhost")
	viper.SetDefault("email.smtp_port", 587)
	viper.SetDefault("email.smtp_username", "")
	viper.SetDefault("email.smtp_password", "")
	viper.SetDefault("email.use_tls", true)
	viper.SetDefault("email.from_email", "noreply@biarbala.ir")
	viper.SetDefault("email.from_name", "Biarbala")
	viper.SetDefault("email.base_url", "http://localhost:8081")
}
