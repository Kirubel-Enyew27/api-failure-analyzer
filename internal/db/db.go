package db

import (
	"api-failure-analyzer/internal/logger"
	"context"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

var DB *pgxpool.Pool

func InitDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Get().Fatal("DATABASE_URL is not set")
	}

	var err error
	DB, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		logger.Get().Fatalw("Failed to connect to DB", "error", err)
	}
}
