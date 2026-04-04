package service

import (
	"api-failure-analyzer/internal/analyzer"
	"api-failure-analyzer/internal/repository"
)

type LogService struct {
	repo *repository.LogRepository
}

func NewLogService(repo *repository.LogRepository) *LogService {
	return &LogService{
		repo: repo,
	}
}

func (s *LogService) ProcessLog(raw string) error {
	res := analyzer.AnalyzeLog(raw)

	logID, err := s.repo.SaveLog(raw)
	if err != nil {
		return err
	}

	err = s.repo.SaveError(logID, res.ErrorMessage, res.ErrorType, res.Fingerprint)
	if err != nil {
		return err
	}

	return s.repo.UpsertCluster(res.Fingerprint, res.ErrorType)

}

func (s *LogService) GetErrorSummaryByTime(start, end string) (map[string]int, error) {
	return s.repo.GetErrorSummaryWithTime(start, end)
}

func (s *LogService) GetTopErrorsWithLimit(limit int) ([]map[string]interface{}, error) {
	return s.repo.GetTopErrorsWithLimit(limit)
}

func (s *LogService) GetErrorDetailsByFingerprint(fingerprint string) ([]map[string]interface{}, error) {
	return s.repo.GetErrorDetailsByFingerprint(fingerprint)
}