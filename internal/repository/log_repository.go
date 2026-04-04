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

func (r *LogRepository) ProcessLogWithTx(ctx context.Context, raw, msg, typ, fp string) error {
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
		INSERT INTO clusters (fingerprint, error_type, count)
		VALUES ($1, $2, 1)
		ON CONFLICT (fingerprint) DO UPDATE SET count = clusters.count + 1, last_seen = NOW()
	`, fp, typ)
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
			"log_id": logID,
			"error_message": msg,
			"error_type": typ,
			"created_at": createdAt,
		})
	}
	return details, nil
}