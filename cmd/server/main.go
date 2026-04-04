package main

import (
	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/handler"
	"api-failure-analyzer/internal/middleware"
	"api-failure-analyzer/internal/repository"
	"api-failure-analyzer/internal/service"
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	db.InitDB()

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
		log.Println("Server running on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Closing database connections...")
	if db.DB != nil {
		db.DB.Close()
	}

	log.Println("Server exiting")
}
