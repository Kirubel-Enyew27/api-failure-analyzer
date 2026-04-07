package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	APILatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "api_latency",
		Help:    "Latency of API requests in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"service", "method", "path", "status"})

	ErrorRateByService = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "error_rate_by_service",
		Help: "Number of error responses by service and status class",
	}, []string{"service", "status_class"})

	FailureFrequency = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "failure_frequency",
		Help: "Count of failures by service and kind",
	}, []string{"service", "kind"})

	AnomalyCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "anomaly_count",
		Help: "Count of detected anomalies by service and severity",
	}, []string{"service", "severity"})

	ProcessedLogs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "api_failure_analyzer_logs_processed_total",
		Help: "Total number of logs processed",
	})

	ErrorCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "api_failure_analyzer_errors_total",
		Help: "Total number of errors by type",
	}, []string{"error_type"})

	ClusterCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "api_failure_analyzer_clusters_total",
		Help: "Total number of unique error clusters",
	})

	ProcessingDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "api_failure_analyzer_processing_duration_seconds",
		Help:    "Time spent processing logs",
		Buckets: prometheus.DefBuckets,
	})
)
