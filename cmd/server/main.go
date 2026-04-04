package main

import (
	"api-failure-analyzer/internal/alert"
	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/handler"
	"api-failure-analyzer/internal/logger"
	"api-failure-analyzer/internal/middleware"
	"api-failure-analyzer/internal/repository"
	"api-failure-analyzer/internal/service"
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	log := logger.Get()
	defer logger.Sync()

	log.Info("Starting server")

	repo := repository.NewLogRepository()
	logService := service.NewLogService(repo)
	logHandler := handler.NewHandler(logService)

	alertCfg := alert.Config{
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     mustGetInt("SMTP_PORT", 587),
		SMTPUser:     os.Getenv("SMTP_USER"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		FromEmail:    os.Getenv("ALERT_FROM_EMAIL"),
		ToEmails:     parseEmails(os.Getenv("ALERT_TO_EMAILS")),
		Enabled:      os.Getenv("ALERT_ENABLED") == "true",
	}
	notifier := alert.NewNotifier(alertCfg)
	notifier.Start(context.Background())

	rateLimiter := middleware.NewRateLimiter(100, 200, time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/apps", logHandler.CreateApp)
	mux.HandleFunc("/apps/list", logHandler.ListApps)
	mux.HandleFunc("/logs", logHandler.SubmitLog)
	mux.HandleFunc("/errors/summary-time", logHandler.GetErrorSummaryByTime)
	mux.HandleFunc("/errors/top-limit", logHandler.GetTopErrorsWithLimit)
	mux.HandleFunc("/errors/details-fp", logHandler.GetErrorDetailsByFingerprint)
	mux.HandleFunc("/errors/trends", logHandler.GetErrorTrends)
	mux.HandleFunc("/errors/severity", logHandler.GetErrorsBySeverity)
	mux.HandleFunc("/errors/severity/all", logHandler.GetAllErrorsGroupedBySeverity)
	mux.Handle("/metrics", promhttp.Handler())

	handler := middleware.APIKeyMiddleware(mux)
	handler = middleware.RateLimiterMiddleware(rateLimiter)(handler)
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

func mustGetInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func parseEmails(s string) []string {
	if s == "" {
		return nil
	}
	var emails []string
	for _, e := range splitAndTrim(s, ",") {
		if e != "" {
			emails = append(emails, e)
		}
	}
	return emails
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		result = append(result, strings.TrimSpace(part))
	}
	return result
}
