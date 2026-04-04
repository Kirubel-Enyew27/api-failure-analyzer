package retention

import (
	"context"
	"time"

	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/logger"
)

type Config struct {
	LogRetentionDays     int
	ErrorRetentionDays   int
	ClusterRetentionDays int
	ArchiveEnabled       bool
	ArchiveBeforeDelete  bool
}

var DefaultConfig = Config{
	LogRetentionDays:     30,
	ErrorRetentionDays:   90,
	ClusterRetentionDays: 180,
	ArchiveEnabled:       true,
	ArchiveBeforeDelete:  true,
}

func RunRetentionPolicy(ctx context.Context, cfg Config) error {
	log := logger.Get()
	log.Info("Starting retention policy")

	if cfg.ArchiveEnabled && cfg.ArchiveBeforeDelete {
		if err := archiveOldData(ctx); err != nil {
			log.Errorw("archive failed", "error", err)
		}
	}

	if err := deleteOldLogs(ctx, cfg.LogRetentionDays); err != nil {
		log.Errorw("log deletion failed", "error", err)
	}

	if err := deleteOldErrors(ctx, cfg.ErrorRetentionDays); err != nil {
		log.Errorw("error deletion failed", "error", err)
	}

	if err := deleteOldClusters(ctx, cfg.ClusterRetentionDays); err != nil {
		log.Errorw("cluster deletion failed", "error", err)
	}

	log.Info("Retention policy completed")
	return nil
}

func archiveOldData(ctx context.Context) error {
	cutoff := time.Now().AddDate(0, -6, 0)

	_, err := db.DB.Exec(ctx, `
		INSERT INTO logs_archive (id, app_id, raw_text, created_at)
		SELECT id, app_id, raw_text, created_at
		FROM logs
		WHERE created_at < $1
		ON CONFLICT (id) DO NOTHING
	`, cutoff)
	if err != nil {
		return err
	}

	_, err = db.DB.Exec(ctx, `
		INSERT INTO errors_archive (id, log_id, app_id, error_message, error_type, fingerprint, created_at)
		SELECT id, log_id, app_id, error_message, error_type, fingerprint, created_at
		FROM errors
		WHERE created_at < $1
		ON CONFLICT (id) DO NOTHING
	`, cutoff)
	return err
}

func deleteOldLogs(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	_, err := db.DB.Exec(ctx, "DELETE FROM logs WHERE created_at < $1", cutoff)
	return err
}

func deleteOldErrors(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	_, err := db.DB.Exec(ctx, "DELETE FROM errors WHERE created_at < $1", cutoff)
	return err
}

func deleteOldClusters(ctx context.Context, days int) error {
	if days <= 0 {
		return nil
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	_, err := db.DB.Exec(ctx, "DELETE FROM clusters WHERE last_seen < $1", cutoff)
	return err
}

func StartRetentionScheduler(ctx context.Context, cfg Config, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		RunRetentionPolicy(ctx, cfg)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				RunRetentionPolicy(ctx, cfg)
			}
		}
	}()
}
