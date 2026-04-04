package middleware

import (
	"api-failure-analyzer/internal/logger"
	"net/http"
	"sync"
	"time"
)

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

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		logger.Get().Infow("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"status", wrapped.statusCode,
			"duration", time.Since(start))
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
