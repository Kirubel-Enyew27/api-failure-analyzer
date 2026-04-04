package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
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
