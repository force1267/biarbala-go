package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all application metrics
type Metrics struct {
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	GRPCRequestsTotal   *prometheus.CounterVec
	GRPCRequestDuration *prometheus.HistogramVec
	FileUploadsTotal    *prometheus.CounterVec
	FileUploadSize      *prometheus.HistogramVec
	ActiveProjects      prometheus.Gauge
	StorageUsed         prometheus.Gauge
	CacheHits           *prometheus.CounterVec
	CacheMisses         *prometheus.CounterVec
	DatabaseConnections prometheus.Gauge
	RedisConnections    prometheus.Gauge
}

// New creates a new metrics instance
func New() *Metrics {
	return &Metrics{
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "biarbala_http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "endpoint", "status_code"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "biarbala_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "endpoint"},
		),
		GRPCRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "biarbala_grpc_requests_total",
				Help: "Total number of gRPC requests",
			},
			[]string{"method", "status"},
		),
		GRPCRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "biarbala_grpc_request_duration_seconds",
				Help:    "gRPC request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method"},
		),
		FileUploadsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "biarbala_file_uploads_total",
				Help: "Total number of file uploads",
			},
			[]string{"format", "status"},
		),
		FileUploadSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "biarbala_file_upload_size_bytes",
				Help:    "File upload size in bytes",
				Buckets: prometheus.ExponentialBuckets(1024, 2, 20), // 1KB to 1GB
			},
			[]string{"format"},
		),
		ActiveProjects: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "biarbala_active_projects",
				Help: "Number of active projects",
			},
		),
		StorageUsed: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "biarbala_storage_used_bytes",
				Help: "Total storage used in bytes",
			},
		),
		CacheHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "biarbala_cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"cache_type"},
		),
		CacheMisses: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "biarbala_cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"cache_type"},
		),
		DatabaseConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "biarbala_database_connections",
				Help: "Number of active database connections",
			},
		),
		RedisConnections: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "biarbala_redis_connections",
				Help: "Number of active Redis connections",
			},
		),
	}
}

// StartHTTPServer starts the Prometheus metrics HTTP server
func (m *Metrics) StartHTTPServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return server
}

// RecordHTTPRequest records an HTTP request metric
func (m *Metrics) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration) {
	m.HTTPRequestsTotal.WithLabelValues(method, endpoint, statusCode).Inc()
	m.HTTPRequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordGRPCRequest records a gRPC request metric
func (m *Metrics) RecordGRPCRequest(method, status string, duration time.Duration) {
	m.GRPCRequestsTotal.WithLabelValues(method, status).Inc()
	m.GRPCRequestDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordFileUpload records a file upload metric
func (m *Metrics) RecordFileUpload(format, status string, size int64) {
	m.FileUploadsTotal.WithLabelValues(format, status).Inc()
	m.FileUploadSize.WithLabelValues(format).Observe(float64(size))
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit(cacheType string) {
	m.CacheHits.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss(cacheType string) {
	m.CacheMisses.WithLabelValues(cacheType).Inc()
}

// SetActiveProjects sets the number of active projects
func (m *Metrics) SetActiveProjects(count int) {
	m.ActiveProjects.Set(float64(count))
}

// SetStorageUsed sets the total storage used
func (m *Metrics) SetStorageUsed(bytes int64) {
	m.StorageUsed.Set(float64(bytes))
}

// SetDatabaseConnections sets the number of database connections
func (m *Metrics) SetDatabaseConnections(count int) {
	m.DatabaseConnections.Set(float64(count))
}

// SetRedisConnections sets the number of Redis connections
func (m *Metrics) SetRedisConnections(count int) {
	m.RedisConnections.Set(float64(count))
}
