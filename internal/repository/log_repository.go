package repository

import (
	"api-failure-analyzer/internal/db"
	"context"
	"time"
)

type LogRepository struct{}

func NewLogRepository() *LogRepository {
	return &LogRepository{}
}

func (r *LogRepository) GetClusterCount(ctx context.Context) (int, error) {
	var count int
	err := db.DB.QueryRow(ctx, "SELECT COUNT(*) FROM clusters").Scan(&count)
	return count, err
}

func (r *LogRepository) ProcessLogWithTx(ctx context.Context, raw, msg, typ, fp, severity string) error {
	tx, err := db.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var logID string
	err = tx.QueryRow(ctx, "INSERT INTO logs (raw_text) VALUES ($1) RETURNING id", raw).Scan(&logID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, "INSERT INTO errors (log_id, error_message, error_type, fingerprint) VALUES ($1, $2, $3, $4)", logID, msg, typ, fp)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO clusters (fingerprint, error_type, count, severity)
		VALUES ($1, $2, 1, $3)
		ON CONFLICT (fingerprint) DO UPDATE SET count = clusters.count + 1, last_seen = NOW(), severity = $3
	`, fp, typ, severity)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *LogRepository) GetErrorSummaryWithTime(ctx context.Context, start, end string) (map[string]int, error) {
	query := `
	SELECT error_type, COUNT(*) 
	FROM errors
	WHERE created_at >= $1 AND created_at <= $2
	GROUP BY error_type
	`

	rows, err := db.DB.Query(ctx, query, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summary := make(map[string]int)
	for rows.Next() {
		var typ string
		var count int
		if err := rows.Scan(&typ, &count); err != nil {
			return nil, err
		}
		summary[typ] = count
	}
	return summary, nil
}

func (r *LogRepository) GetTopErrorsWithLimit(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	rows, err := db.DB.Query(ctx, `	
	SELECT fingerprint, error_type, count, last_seen
	FROM clusters
	ORDER BY count DESC
	LIMIT $1
	`, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var fp, typ string
		var count int
		var lastSeen time.Time
		if err := rows.Scan(&fp, &typ, &count, &lastSeen); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"fingerprint": fp,
			"error_type":  typ,
			"count":       count,
			"last_seen":   lastSeen,
		})
	}
	return results, nil
}

func (r *LogRepository) GetErrorsBySeverity(ctx context.Context, severity string) ([]map[string]interface{}, error) {
	rows, err := db.DB.Query(ctx, `
		SELECT fingerprint, error_type, count, last_seen, severity
		FROM clusters
		WHERE severity = $1
		ORDER BY count DESC
	`, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var fp, typ, sev string
		var count int
		var lastSeen time.Time
		if err := rows.Scan(&fp, &typ, &count, &lastSeen, &sev); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"fingerprint": fp,
			"error_type":  typ,
			"count":       count,
			"last_seen":   lastSeen,
			"severity":    sev,
		})
	}
	return results, nil
}

func (r *LogRepository) GetAllErrorsGroupedBySeverity(ctx context.Context) (map[string][]map[string]interface{}, error) {
	rows, err := db.DB.Query(ctx, `
		SELECT fingerprint, error_type, count, last_seen, severity
		FROM clusters
		ORDER BY severity DESC, count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[string][]map[string]interface{}{
		"critical": {},
		"high":     {},
		"medium":   {},
		"low":      {},
	}

	for rows.Next() {
		var fp, typ, sev string
		var count int
		var lastSeen time.Time
		if err := rows.Scan(&fp, &typ, &count, &lastSeen, &sev); err != nil {
			return nil, err
		}
		result[sev] = append(result[sev], map[string]interface{}{
			"fingerprint": fp,
			"error_type":  typ,
			"count":       count,
			"last_seen":   lastSeen,
			"severity":    sev,
		})
	}
	return result, nil
}

func (r *LogRepository) GetErrorDetailsByFingerprint(ctx context.Context, fingerprint string) ([]map[string]interface{}, error) {
	rows, err := db.DB.Query(ctx, `
	SELECT log_id, error_message, error_type, created_at
	FROM errors
	WHERE fingerprint = $1
	ORDER BY created_at DESC
	`, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var details []map[string]interface{}
	for rows.Next() {
		var logID, msg, typ string
		var createdAt time.Time
		if err := rows.Scan(&logID, &msg, &typ, &createdAt); err != nil {
			return nil, err
		}
		details = append(details, map[string]interface{}{
			"log_id":        logID,
			"error_message": msg,
			"error_type":    typ,
			"created_at":    createdAt,
		})
	}
	return details, nil
}

func (r *LogRepository) UpdateErrorTrends(ctx context.Context, errorType string) error {
	now := time.Now()
	hourStart := now.Truncate(time.Hour)
	dayStart := now.Truncate(24 * time.Hour)

	_, err := db.DB.Exec(ctx, `
		INSERT INTO error_trends (error_type, interval_start, interval_type, count)
		VALUES ($1, $2, 'hourly', 1)
		ON CONFLICT (error_type, interval_start, interval_type) 
		DO UPDATE SET count = error_trends.count + 1
	`, errorType, hourStart)
	if err != nil {
		return err
	}

	_, err = db.DB.Exec(ctx, `
		INSERT INTO error_trends (error_type, interval_start, interval_type, count)
		VALUES ($1, $2, 'daily', 1)
		ON CONFLICT (error_type, interval_start, interval_type) 
		DO UPDATE SET count = error_trends.count + 1
	`, errorType, dayStart)
	return err
}

type TrendData struct {
	IntervalStart time.Time `json:"interval_start"`
	Count         int       `json:"count"`
}

func (r *LogRepository) GetErrorTrends(ctx context.Context, errorType string, intervalType string, hours int) ([]TrendData, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := db.DB.Query(ctx, `
		SELECT interval_start, count
		FROM error_trends
		WHERE error_type = $1 AND interval_type = $2 AND interval_start >= $3
		ORDER BY interval_start ASC
	`, errorType, intervalType, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var trends []TrendData
	for rows.Next() {
		var td TrendData
		if err := rows.Scan(&td.IntervalStart, &td.Count); err != nil {
			return nil, err
		}
		trends = append(trends, td)
	}
	return trends, nil
}

func (r *LogRepository) GetAllErrorTrends(ctx context.Context, intervalType string, hours int) ([]map[string]interface{}, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := db.DB.Query(ctx, `
		SELECT error_type, interval_start, count
		FROM error_trends
		WHERE interval_type = $1 AND interval_start >= $2
		ORDER BY error_type, interval_start ASC
	`, intervalType, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]map[string]interface{}, 0)
	for rows.Next() {
		var typ string
		var td TrendData
		if err := rows.Scan(&typ, &td.IntervalStart, &td.Count); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"error_type":     typ,
			"interval_start": td.IntervalStart,
			"count":          td.Count,
		})
	}
	return results, nil
}
