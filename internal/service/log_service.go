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

	count, _ := s.repo.GetClusterCount(ctx)
	res := analyzer.AnalyzeLog(raw, count)
	err := s.repo.ProcessLogWithTx(ctx, raw, res.ErrorMessage, res.ErrorType, res.Fingerprint, string(res.Severity))

	metrics.ProcessedLogs.Inc()
	if res.ErrorType != "" {
		metrics.ErrorCount.WithLabelValues(res.ErrorType).Inc()
		s.repo.UpdateErrorTrends(ctx, res.ErrorType)
	}

	metrics.ClusterCount.Set(float64(count + 1))

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

func (s *LogService) GetErrorTrends(ctx context.Context, errorType string, intervalType string, hours int) ([]repository.TrendData, error) {
	return s.repo.GetErrorTrends(ctx, errorType, intervalType, hours)
}

func (s *LogService) GetAllErrorTrends(ctx context.Context, intervalType string, hours int) ([]map[string]interface{}, error) {
	return s.repo.GetAllErrorTrends(ctx, intervalType, hours)
}

func (s *LogService) GetErrorsBySeverity(ctx context.Context, severity string) ([]map[string]interface{}, error) {
	return s.repo.GetErrorsBySeverity(ctx, severity)
}

func (s *LogService) GetAllErrorsGroupedBySeverity(ctx context.Context) (map[string][]map[string]interface{}, error) {
	return s.repo.GetAllErrorsGroupedBySeverity(ctx)
}
