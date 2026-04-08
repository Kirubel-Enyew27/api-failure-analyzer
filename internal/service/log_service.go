package service

import (
	"api-failure-analyzer/internal/analyzer"
	"api-failure-analyzer/internal/metrics"
	"api-failure-analyzer/internal/observability"
	"api-failure-analyzer/internal/repository"
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type LogService struct {
	repo *repository.LogRepository
}

func NewLogService(repo *repository.LogRepository) *LogService {
	return &LogService{
		repo: repo,
	}
}

func (s *LogService) ProcessLog(ctx context.Context, appID, raw string) error {
	ctx, span := observability.StartSpan(ctx, "log-service", "service.process_log",
		attribute.String("app_id", appID),
	)
	defer span.End()

	start := time.Now()

	count, _ := s.repo.GetClusterCount(ctx, appID)
	res := analyzer.AnalyzeLog(raw, count)
	err := s.repo.ProcessLogWithTx(ctx, appID, raw, res.ErrorMessage, res.ErrorType, res.Fingerprint, string(res.Severity))

	metrics.ProcessedLogs.Inc()
	if res.ErrorType != "" {
		metrics.ErrorCount.WithLabelValues(res.ErrorType).Inc()
		if trendErr := s.repo.UpdateErrorTrends(ctx, appID, res.ErrorType); trendErr != nil {
			observability.MarkSpanError(span, trendErr)
		}
	}

	if res.Severity == analyzer.SeverityHigh || res.Severity == analyzer.SeverityCritical {
		metrics.AnomalyCount.WithLabelValues("api-failure-analyzer", string(res.Severity)).Inc()
	}

	metrics.ClusterCount.Set(float64(count + 1))

	metrics.ProcessingDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		metrics.FailureFrequency.WithLabelValues("api_failure_analyzer", "process_log").Inc()
		observability.MarkSpanError(span, err)
	}

	return err
}

func (s *LogService) GetErrorSummaryByTime(ctx context.Context, appID, start, end string) (map[string]int, error) {
	return s.repo.GetErrorSummaryWithTime(ctx, appID, start, end)
}

func (s *LogService) GetTopErrorsWithLimit(ctx context.Context, appID string, limit int) ([]map[string]interface{}, error) {
	return s.repo.GetTopErrorsWithLimit(ctx, appID, limit)
}

func (s *LogService) GetErrorDetailsByFingerprint(ctx context.Context, appID, fingerprint string) ([]map[string]interface{}, error) {
	return s.repo.GetErrorDetailsByFingerprint(ctx, appID, fingerprint)
}

func (s *LogService) GetErrorTrends(ctx context.Context, appID, errorType, intervalType string, hours int) ([]repository.TrendData, error) {
	return s.repo.GetErrorTrends(ctx, appID, errorType, intervalType, hours)
}

func (s *LogService) GetAllErrorTrends(ctx context.Context, appID, intervalType string, hours int) ([]map[string]interface{}, error) {
	return s.repo.GetAllErrorTrends(ctx, appID, intervalType, hours)
}

func (s *LogService) GetErrorsBySeverity(ctx context.Context, appID, severity string) ([]map[string]interface{}, error) {
	return s.repo.GetErrorsBySeverity(ctx, appID, severity)
}

func (s *LogService) GetAllErrorsGroupedBySeverity(ctx context.Context, appID string) (map[string][]map[string]interface{}, error) {
	return s.repo.GetAllErrorsGroupedBySeverity(ctx, appID)
}

func (s *LogService) GetIntelligentFailureAnalysis(ctx context.Context, appID string, hours, limit int, deployAt *time.Time) (analyzer.IntelligentAnalysis, error) {
	if hours <= 0 {
		hours = 168
	}
	if limit <= 0 {
		limit = 1000
	}

	events, err := s.repo.GetRecentErrorEvents(ctx, appID, hours, limit)
	if err != nil {
		return analyzer.IntelligentAnalysis{}, err
	}

	trendPoints, err := s.repo.GetHourlyTrendPoints(ctx, appID, hours)
	if err != nil {
		return analyzer.IntelligentAnalysis{}, err
	}

	beforeCounts := map[string]int{}
	afterCounts := map[string]int{}
	if deployAt != nil {
		deployTS := deployAt.UTC()
		windowStart := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		if deployTS.Before(windowStart) {
			deployTS = windowStart
		}
		if deployTS.Before(time.Now().UTC()) {
			beforeWindow := deployTS.Sub(windowStart)
			if beforeWindow > 0 {
				beforeStart := deployTS.Add(-beforeWindow)
				beforeCounts, err = s.repo.GetErrorCountsInRange(ctx, appID, beforeStart, deployTS)
				if err != nil {
					return analyzer.IntelligentAnalysis{}, err
				}
				afterCounts, err = s.repo.GetErrorCountsInRange(ctx, appID, deployTS, deployTS.Add(beforeWindow))
				if err != nil {
					return analyzer.IntelligentAnalysis{}, err
				}
			}
		}
	}

	result := analyzer.AnalyzeFailuresIntelligently(events, trendPoints, beforeCounts, afterCounts, analyzer.AnalysisOptions{
		WindowHours: hours,
		DeployAt:    deployAt,
	})
	return result, nil
}
