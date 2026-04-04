package main

import (
	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/handler"
	"api-failure-analyzer/internal/repository"
	"api-failure-analyzer/internal/service"
	"log"
	"net/http"
)

func main() {
	db.InitDB()

	repo := repository.NewLogRepository()
	logService := service.NewLogService(repo)
	logHandler := handler.NewHandler(logService)

	http.HandleFunc("/logs", logHandler.SubmitLog)

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
