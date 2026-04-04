package main

import (
	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/handler"
	"api-failure-analyzer/internal/logger"
	"api-failure-analyzer/internal/middleware"
	"api-failure-analyzer/internal/repository"
	"api-failure-analyzer/internal/service"
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log := logger.Get()
	defer logger.Sync()

	log.Info("Starting server")

	repo := repository.NewLogRepository()
	logService := service.NewLogService(repo)
	logHandler := handler.NewHandler(logService)

	rateLimiter := middleware.NewRateLimiter(100, 200, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/logs", logHandler.SubmitLog)
	mux.HandleFunc("/errors/summary-time", logHandler.GetErrorSummaryByTime)
	mux.HandleFunc("/errors/top-limit", logHandler.GetTopErrorsWithLimit)
	mux.HandleFunc("/errors/details-fp", logHandler.GetErrorDetailsByFingerprint)

	handler := middleware.RateLimiterMiddleware(rateLimiter)(mux)
	handler = middleware.LoggingMiddleware(handler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: handler,
	}

	go func() {
		log.Info("Server running on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalw("listen failed", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalw("Server forced to shutdown", "error", err)
	}

	log.Info("Closing database connections...")
	if db.DB != nil {
		db.DB.Close()
	}

	log.Info("Server exiting")
}
