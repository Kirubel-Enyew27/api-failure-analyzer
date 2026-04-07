package middleware

import (
	"api-failure-analyzer/internal/logger"
	"api-failure-analyzer/internal/metrics"
	"api-failure-analyzer/internal/observability"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

type contextKey string

const correlationIDKey contextKey = "correlation_id"
const serviceName = "api-failure-analyzer"
const correlationHeader = "X-Correlation-ID"

type RateLimiter struct {
	clients map[string]*clientLimit
	mu      sync.Mutex
	rate    int
	burst   int
	window  time.Duration
}

type clientLimit struct {
	count     int
	lastReset time.Time
}

func NewRateLimiter(rate int, burst int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*clientLimit),
		rate:    rate,
		burst:   burst,
		window:  window,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		expired := make([]string, 0)
		now := time.Now()
		for ip, cl := range rl.clients {
			if now.Sub(cl.lastReset) > rl.window*2 {
				expired = append(expired, ip)
			}
		}
		for _, ip := range expired {
			delete(rl.clients, ip)
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cl, exists := rl.clients[ip]

	if !exists {
		rl.clients[ip] = &clientLimit{count: 1, lastReset: now}
		return true
	}

	if now.Sub(cl.lastReset) >= rl.window {
		cl.count = 1
		cl.lastReset = now
		return true
	}

	if cl.count >= rl.burst {
		return false
	}

	cl.count++
	return true
}

func RateLimiterMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				ip = forwarded
			}

			if !rl.Allow(ip) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CorrelationIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corrID := r.Header.Get(correlationHeader)
		if corrID == "" {
			corrID = newCorrelationID()
		}
		ctx := context.WithValue(r.Context(), correlationIDKey, corrID)
		w.Header().Set(correlationHeader, corrID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func TracingMiddleware(next http.Handler) http.Handler {
	tracer := observability.Tracer("http-server")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := tracer.Start(r.Context(), r.Method+" "+r.URL.Path,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
			),
		)
		defer span.End()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		statusClass := statusCodeClass(wrapped.statusCode)
		corrID := CorrelationIDFromContext(r.Context())
		spanCtx := trace.SpanContextFromContext(r.Context())
		traceID := ""
		spanID := ""
		if spanCtx.IsValid() {
			traceID = spanCtx.TraceID().String()
			spanID = spanCtx.SpanID().String()
		}

		metrics.APILatency.WithLabelValues(serviceName, r.Method, r.URL.Path, statusClass).Observe(duration.Seconds())
		if wrapped.statusCode >= http.StatusBadRequest {
			metrics.ErrorRateByService.WithLabelValues(serviceName, statusClass).Inc()
			metrics.FailureFrequency.WithLabelValues(serviceName, "http_request").Inc()
			if span := trace.SpanFromContext(r.Context()); span != nil {
				span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
			}
		}
		logger.Get().Infow("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"status", wrapped.statusCode,
			"duration", duration,
			"correlation_id", corrID,
			"trace_id", traceID,
			"span_id", spanID,
		)
	})
}

func CorrelationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationIDKey).(string); ok {
		return v
	}
	return ""
}

func newCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func statusCodeClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
