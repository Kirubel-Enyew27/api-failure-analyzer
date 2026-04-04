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

func (h *Handler) GetErrorTrends(w http.ResponseWriter, r *http.Request) {
	errorType := r.URL.Query().Get("error_type")
	intervalType := r.URL.Query().Get("interval")
	hoursStr := r.URL.Query().Get("hours")

	if intervalType == "" {
		intervalType = "daily"
	}
	if hoursStr == "" {
		hoursStr = "168"
	}

	hours, err := strconv.Atoi(hoursStr)
	if err != nil {
		http.Error(w, "invalid hours", http.StatusBadRequest)
		return
	}

	var trends interface{}
	if errorType == "" {
		trends, err = h.service.GetAllErrorTrends(r.Context(), intervalType, hours)
	} else {
		trends, err = h.service.GetErrorTrends(r.Context(), errorType, intervalType, hours)
	}
	if err != nil {
		http.Error(w, "failed to get error trends", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trends)
}

func (h *Handler) GetErrorsBySeverity(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	if severity == "" {
		http.Error(w, "missing severity", http.StatusBadRequest)
		return
	}

	errors, err := h.service.GetErrorsBySeverity(r.Context(), severity)
	if err != nil {
		http.Error(w, "failed to get errors by severity", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errors)
}

func (h *Handler) GetAllErrorsGroupedBySeverity(w http.ResponseWriter, r *http.Request) {
	errors, err := h.service.GetAllErrorsGroupedBySeverity(r.Context())
	if err != nil {
		http.Error(w, "failed to get errors grouped by severity", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errors)
}
