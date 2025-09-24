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
	Cache    CacheConfig    `mapstructure:"cache"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Upload   UploadConfig   `mapstructure:"upload"`
	Security SecurityConfig `mapstructure:"security"`
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
	MongoDB MongoDBConfig `mapstructure:"mongodb"`
}

// MongoDBConfig holds MongoDB configuration
type MongoDBConfig struct {
	URI      string        `mapstructure:"uri"`
	Database string        `mapstructure:"database"`
	Timeout  time.Duration `mapstructure:"timeout"`
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
}
