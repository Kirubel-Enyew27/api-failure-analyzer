package handler

import (
	"api-failure-analyzer/internal/app"
	"api-failure-analyzer/internal/service"
	"encoding/json"
	"net/http"
	"strconv"
	"time"
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
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	err := h.service.ProcessLog(r.Context(), appID.(string), req.Log)
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
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	start := r.URL.Query().Get("start")
	end := r.URL.Query().Get("end")

	if start == "" || end == "" {
		http.Error(w, "missing start or end", http.StatusBadRequest)
		return
	}

	summary, err := h.service.GetErrorSummaryByTime(r.Context(), appID.(string), start, end)
	if err != nil {
		http.Error(w, "failed to get error summary", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func (h *Handler) GetTopErrorsWithLimit(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		http.Error(w, "invalid limit", http.StatusBadRequest)
		return
	}

	topErrors, err := h.service.GetTopErrorsWithLimit(r.Context(), appID.(string), limit)
	if err != nil {
		http.Error(w, "failed to get top errors", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topErrors)
}

func (h *Handler) GetErrorDetailsByFingerprint(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		http.Error(w, "missing fingerprint", http.StatusBadRequest)
		return
	}

	details, err := h.service.GetErrorDetailsByFingerprint(r.Context(), appID.(string), fingerprint)
	if err != nil {
		http.Error(w, "failed to get error details", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

func (h *Handler) GetErrorTrends(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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
		trends, err = h.service.GetAllErrorTrends(r.Context(), appID.(string), intervalType, hours)
	} else {
		trends, err = h.service.GetErrorTrends(r.Context(), appID.(string), errorType, intervalType, hours)
	}
	if err != nil {
		http.Error(w, "failed to get error trends", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(trends)
}

func (h *Handler) GetErrorsBySeverity(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	severity := r.URL.Query().Get("severity")
	if severity == "" {
		http.Error(w, "missing severity", http.StatusBadRequest)
		return
	}

	errors, err := h.service.GetErrorsBySeverity(r.Context(), appID.(string), severity)
	if err != nil {
		http.Error(w, "failed to get errors by severity", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errors)
}

func (h *Handler) GetAllErrorsGroupedBySeverity(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	errors, err := h.service.GetAllErrorsGroupedBySeverity(r.Context(), appID.(string))
	if err != nil {
		http.Error(w, "failed to get errors grouped by severity", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(errors)
}

func (h *Handler) GetIntelligentFailureAnalysis(w http.ResponseWriter, r *http.Request) {
	appID := r.Context().Value("app_id")
	if appID == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hours := 168
	if hoursStr := r.URL.Query().Get("hours"); hoursStr != "" {
		parsed, err := strconv.Atoi(hoursStr)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid hours", http.StatusBadRequest)
			return
		}
		hours = parsed
	}
	limit := 1000
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err != nil || parsed <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	var deployAt *time.Time
	if deployAtStr := r.URL.Query().Get("deploy_at"); deployAtStr != "" {
		parsed, err := time.Parse(time.RFC3339, deployAtStr)
		if err != nil {
			http.Error(w, "invalid deploy_at; expected RFC3339", http.StatusBadRequest)
			return
		}
		deployAt = &parsed
	}
	result, err := h.service.GetIntelligentFailureAnalysis(r.Context(), appID.(string), hours, limit, deployAt)
	if err != nil {
		http.Error(w, "failed to get intelligent analysis", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

type CreateAppRequest struct {
	Name string `json:"name"`
}

func (h *Handler) CreateApp(w http.ResponseWriter, r *http.Request) {
	var req CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}

	app, err := app.CreateApp(r.Context(), req.Name)
	if err != nil {
		http.Error(w, "failed to create app", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":      app.ID,
		"name":    app.Name,
		"api_key": app.APIKey,
	})
}

func (h *Handler) ListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := app.ListApps(r.Context())
	if err != nil {
		http.Error(w, "failed to list apps", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(apps)
}
