package repository

import (
	"api-failure-analyzer/internal/db"
	"context"
)

type LogRepository struct{}

func NewLogRepository() *LogRepository {
	return &LogRepository{}
}

func (r *LogRepository) SaveLog(raw string) (string, error) {
	var id string
	err := db.DB.QueryRow(context.Background(),
		"INSERT INTO logs (raw_text) VALUES ($1) RETURNING id", raw).Scan(&id)
	return id, err
}

func (r *LogRepository) SaveError(logID, msg, typ, fp string) error {
	_, err := db.DB.Exec(context.Background(),
		"INSERT INTO errors (log_id, error_message, error_type, fingerprint) VALUES ($1, $2, $3, $4)",
		logID, msg, typ, fp)
	return err
}

func (r *LogRepository) UpsertCluster(fp, typ string) error {
	_, err := db.DB.Exec(context.Background(), `
		INSERT INTO clusters (fingerprint, error_type, count)
		VALUES ($1, $2, 1)
		ON CONFLICT (fingerprint) DO UPDATE SET count = clusters.count + 1, last_seen = NOW()
	`, fp, typ)
	return err
}
