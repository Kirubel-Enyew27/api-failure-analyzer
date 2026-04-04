package handler

import (
	"api-failure-analyzer/internal/service"
	"encoding/json"
	"net/http"
)

type Handler struct {
	service *service.LogService
}

func NewHandler(s *service.LogService) *Handler {
	return &Handler{service: s}
}

type Request struct {
	Log string `json:"log"`
}

func (h *Handler) SubmitLog(w http.ResponseWriter, r *http.Request) {
	var req Request

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.service.ProcessLog(req.Log)
	if err != nil {
		http.Error(w, "failed to process log", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "processed",
	})
}
