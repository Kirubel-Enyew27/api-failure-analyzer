package repository

import (
	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/observability"
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

type LogRepository struct{}

func NewLogRepository() *LogRepository {
	return &LogRepository{}
}

func (r *LogRepository) GetClusterCount(ctx context.Context, appID string) (int, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_cluster_count",
		attribute.String("app.id", appID),
	)
	defer span.End()

	var count int
	err := db.DB.QueryRow(ctx, "SELECT COUNT(*) FROM clusters WHERE app_id = $1", appID).Scan(&count)
	observability.MarkSpanError(span, err)
	return count, err
}

func (r *LogRepository) ProcessLogWithTx(ctx context.Context, appID, raw, msg, typ, fp, severity string) error {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.process_log_tx",
		attribute.String("app.id", appID),
		attribute.String("error.type", typ),
		attribute.String("error.severity", severity),
	)
	defer span.End()

	tx, err := db.DB.Begin(ctx)
	if err != nil {
		observability.MarkSpanError(span, err)
		return err
	}
	defer tx.Rollback(ctx)

	var logID string
	err = tx.QueryRow(ctx, "INSERT INTO logs (app_id, raw_text) VALUES ($1, $2) RETURNING id", appID, raw).Scan(&logID)
	if err != nil {
		observability.MarkSpanError(span, err)
		return err
	}

	_, err = tx.Exec(ctx, "INSERT INTO errors (log_id, app_id, error_message, error_type, fingerprint) VALUES ($1, $2, $3, $4, $5)", logID, appID, msg, typ, fp)
	if err != nil {
		observability.MarkSpanError(span, err)
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO clusters (app_id, fingerprint, error_type, count, severity)
		VALUES ($1, $2, $3, 1, $4)
		ON CONFLICT (app_id, fingerprint) DO UPDATE SET count = clusters.count + 1, last_seen = NOW(), severity = $4
	`, appID, fp, typ, severity)
	if err != nil {
		observability.MarkSpanError(span, err)
		return err
	}

	err = tx.Commit(ctx)
	observability.MarkSpanError(span, err)
	return err
}

func (r *LogRepository) GetErrorSummaryWithTime(ctx context.Context, appID, start, end string) (map[string]int, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_error_summary_with_time",
		attribute.String("app.id", appID),
	)
	defer span.End()

	query := `
	SELECT error_type, COUNT(*) 
	FROM errors
	WHERE app_id = $1 AND created_at >= $2 AND created_at <= $3
	GROUP BY error_type
	`

	rows, err := db.DB.Query(ctx, query, appID, start, end)
	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	summary := make(map[string]int)
	for rows.Next() {
		var typ string
		var count int
		if err := rows.Scan(&typ, &count); err != nil {
			observability.MarkSpanError(span, err)
			return nil, err
		}
		summary[typ] = count
	}
	return summary, nil
}

func (r *LogRepository) GetTopErrorsWithLimit(ctx context.Context, appID string, limit int) ([]map[string]interface{}, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_top_errors_with_limit",
		attribute.String("app.id", appID),
	)
	defer span.End()

	rows, err := db.DB.Query(ctx, `
		SELECT fingerprint, error_type, count, last_seen
		FROM clusters
		WHERE app_id = $1
		ORDER BY count DESC
		LIMIT $2
	`, appID, limit)

	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var fp, typ string
		var count int
		var lastSeen time.Time
		if err := rows.Scan(&fp, &typ, &count, &lastSeen); err != nil {
			observability.MarkSpanError(span, err)
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

func (r *LogRepository) GetErrorsBySeverity(ctx context.Context, appID, severity string) ([]map[string]interface{}, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_errors_by_severity",
		attribute.String("app.id", appID),
		attribute.String("error.severity", severity),
	)
	defer span.End()

	rows, err := db.DB.Query(ctx, `
		SELECT fingerprint, error_type, count, last_seen, severity
		FROM clusters
		WHERE app_id = $1 AND severity = $2
		ORDER BY count DESC
	`, appID, severity)
	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var fp, typ, sev string
		var count int
		var lastSeen time.Time
		if err := rows.Scan(&fp, &typ, &count, &lastSeen, &sev); err != nil {
			observability.MarkSpanError(span, err)
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

func (r *LogRepository) GetAllErrorsGroupedBySeverity(ctx context.Context, appID string) (map[string][]map[string]interface{}, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_all_errors_grouped_by_severity",
		attribute.String("app.id", appID),
	)
	defer span.End()

	rows, err := db.DB.Query(ctx, `
		SELECT fingerprint, error_type, count, last_seen, severity
		FROM clusters
		WHERE app_id = $1
		ORDER BY severity DESC, count DESC
	`, appID)
	if err != nil {
		observability.MarkSpanError(span, err)
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
			observability.MarkSpanError(span, err)
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

func (r *LogRepository) GetErrorDetailsByFingerprint(ctx context.Context, appID, fingerprint string) ([]map[string]interface{}, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_error_details_by_fingerprint",
		attribute.String("app.id", appID),
		attribute.String("error.fingerprint", fingerprint),
	)
	defer span.End()

	rows, err := db.DB.Query(ctx, `
		SELECT log_id, error_message, error_type, created_at
		FROM errors
		WHERE app_id = $1 AND fingerprint = $2
		ORDER BY created_at DESC
	`, appID, fingerprint)
	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	var details []map[string]interface{}
	for rows.Next() {
		var logID, msg, typ string
		var createdAt time.Time
		if err := rows.Scan(&logID, &msg, &typ, &createdAt); err != nil {
			observability.MarkSpanError(span, err)
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

func (r *LogRepository) UpdateErrorTrends(ctx context.Context, appID, errorType string) error {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.update_error_trends",
		attribute.String("app.id", appID),
		attribute.String("error.type", errorType),
	)
	defer span.End()

	now := time.Now()
	hourStart := now.Truncate(time.Hour)
	dayStart := now.Truncate(24 * time.Hour)

	_, err := db.DB.Exec(ctx, `
		INSERT INTO error_trends (app_id, error_type, interval_start, interval_type, count)
		VALUES ($1, $2, $3, 'hourly', 1)
		ON CONFLICT (app_id, error_type, interval_start, interval_type) 
		DO UPDATE SET count = error_trends.count + 1
	`, appID, errorType, hourStart)
	if err != nil {
		observability.MarkSpanError(span, err)
		return err
	}

	_, err = db.DB.Exec(ctx, `
		INSERT INTO error_trends (app_id, error_type, interval_start, interval_type, count)
		VALUES ($1, $2, $3, 'daily', 1)
		ON CONFLICT (app_id, error_type, interval_start, interval_type) 
		DO UPDATE SET count = error_trends.count + 1
	`, appID, errorType, dayStart)
	observability.MarkSpanError(span, err)
	return err
}

type TrendData struct {
	IntervalStart time.Time `json:"interval_start"`
	Count         int       `json:"count"`
}

func (r *LogRepository) GetErrorTrends(ctx context.Context, appID, errorType, intervalType string, hours int) ([]TrendData, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_error_trends",
		attribute.String("app.id", appID),
		attribute.String("error.type", errorType),
		attribute.String("interval.type", intervalType),
	)
	defer span.End()

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := db.DB.Query(ctx, `
		SELECT interval_start, count
		FROM error_trends
		WHERE app_id = $1 AND error_type = $2 AND interval_type = $3 AND interval_start >= $4
		ORDER BY interval_start ASC
	`, appID, errorType, intervalType, since)
	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	var trends []TrendData
	for rows.Next() {
		var td TrendData
		if err := rows.Scan(&td.IntervalStart, &td.Count); err != nil {
			observability.MarkSpanError(span, err)
			return nil, err
		}
		trends = append(trends, td)
	}
	return trends, nil
}

func (r *LogRepository) GetAllErrorTrends(ctx context.Context, appID, intervalType string, hours int) ([]map[string]interface{}, error) {
	ctx, span := observability.StartSpan(ctx, "log-repository", "db.get_all_error_trends",
		attribute.String("app.id", appID),
		attribute.String("interval.type", intervalType),
	)
	defer span.End()

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	rows, err := db.DB.Query(ctx, `
		SELECT error_type, interval_start, count
		FROM error_trends
		WHERE app_id = $1 AND interval_type = $2 AND interval_start >= $3
		ORDER BY error_type, interval_start ASC
	`, appID, intervalType, since)
	if err != nil {
		observability.MarkSpanError(span, err)
		return nil, err
	}
	defer rows.Close()

	results := make([]map[string]interface{}, 0)
	for rows.Next() {
		var typ string
		var td TrendData
		if err := rows.Scan(&typ, &td.IntervalStart, &td.Count); err != nil {
			observability.MarkSpanError(span, err)
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
