package service

import (
	"api-failure-analyzer/internal/analyzer"
	"api-failure-analyzer/internal/metrics"
	"api-failure-analyzer/internal/repository"
	"context"
	"time"
)

type LogService struct {
	repo *repository.LogRepository
}

func NewLogService(repo *repository.LogRepository) *LogService {
	return &LogService{
		repo: repo,
	}
}

func (s *LogService) ProcessLog(ctx context.Context, raw string) error {
	start := time.Now()
	res := analyzer.AnalyzeLog(raw)
	err := s.repo.ProcessLogWithTx(ctx, raw, res.ErrorMessage, res.ErrorType, res.Fingerprint)

	metrics.ProcessedLogs.Inc()
	if res.ErrorType != "" {
		metrics.ErrorCount.WithLabelValues(res.ErrorType).Inc()
	}

	count, _ := s.repo.GetClusterCount(ctx)
	metrics.ClusterCount.Set(float64(count))

	metrics.ProcessingDuration.Observe(time.Since(start).Seconds())

	return err
}

func (s *LogService) GetErrorSummaryByTime(ctx context.Context, start, end string) (map[string]int, error) {
	return s.repo.GetErrorSummaryWithTime(ctx, start, end)
}

func (s *LogService) GetTopErrorsWithLimit(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	return s.repo.GetTopErrorsWithLimit(ctx, limit)
}

func (s *LogService) GetErrorDetailsByFingerprint(ctx context.Context, fingerprint string) ([]map[string]interface{}, error) {
	return s.repo.GetErrorDetailsByFingerprint(ctx, fingerprint)
}
