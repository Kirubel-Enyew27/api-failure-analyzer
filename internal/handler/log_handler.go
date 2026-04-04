package handler

import (
	"api-failure-analyzer/internal/service"
	"encoding/json"
	"net/http"
	"strconv"
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

	err := h.service.ProcessLog(r.Context(), req.Log)
	if err != nil {
		http.Error(w, "failed to process log", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "processed",
	})
}

func (h *Handler) GetErrorSummaryByTime(w http.ResponseWriter, r *http.Request) {
	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	if start == "" || end == "" {
		http.Error(w, "missing start or end", http.StatusBadRequest)
		return
	}

	summary, err := h.service.GetErrorSummaryByTime(r.Context(), start, end)
	if err != nil {
		http.Error(w, "failed to get error summary", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func (h *Handler) GetTopErrorsWithLimit(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		http.Error(w, "invalid limit", http.StatusBadRequest)
		return
	}

	topErrors, err := h.service.GetTopErrorsWithLimit(r.Context(), limit)
	if err != nil {
		http.Error(w, "failed to get top errors", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topErrors)
}

func (h *Handler) GetErrorDetailsByFingerprint(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}

	details, err := h.service.GetErrorDetailsByFingerprint(r.Context(), fingerprint)
	if err != nil {
		http.Error(w, "failed to get error details", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}
