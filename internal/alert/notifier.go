package alert

import (
	"api-failure-analyzer/internal/metrics"
	"api-failure-analyzer/internal/observability"
	"context"
	"strconv"
	"sync"
	"time"

	"api-failure-analyzer/internal/db"
	"api-failure-analyzer/internal/logger"

	"go.opentelemetry.io/otel/attribute"
	"gopkg.in/gomail.v2"
)

type Config struct {
	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	FromEmail    string
	ToEmails     []string
	Enabled      bool
}

type AlertRule struct {
	Severity  string
	Threshold int
	Window    time.Duration
	Cooldown  time.Duration
}

var (
	defaultRules = []AlertRule{
		{Severity: "critical", Threshold: 1, Window: 5 * time.Minute, Cooldown: 15 * time.Minute},
		{Severity: "high", Threshold: 10, Window: 10 * time.Minute, Cooldown: 30 * time.Minute},
		{Severity: "medium", Threshold: 50, Window: 30 * time.Minute, Cooldown: 1 * time.Hour},
	}
	alertState = &state{
		mu:        sync.Mutex{},
		lastAlert: make(map[string]time.Time),
	}
)

type state struct {
	mu        sync.Mutex
	lastAlert map[string]time.Time
}

type Notifier struct {
	cfg     Config
	rules   []AlertRule
	enabled bool
}

func NewNotifier(cfg Config) *Notifier {
	if !cfg.Enabled {
		logger.Get().Info("Alerts disabled")
		return &Notifier{cfg: cfg, enabled: false}
	}
	return &Notifier{
		cfg:     cfg,
		rules:   defaultRules,
		enabled: true,
	}
}

func (n *Notifier) Start(ctx context.Context) {
	if !n.enabled {
		return
	}
	go n.runChecker(ctx)
}

func (n *Notifier) runChecker(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.checkAlerts(ctx)
		}
	}
}

func (n *Notifier) checkAlerts(ctx context.Context) {
	for _, rule := range n.rules {
		count, err := n.getErrorCountSince(ctx, rule.Severity, rule.Window)
		if err != nil {
			logger.Get().Errorw("failed to get error count", "error", err, "severity", rule.Severity)
			continue
		}

		if count >= rule.Threshold && n.shouldRecordAndAlert(rule.Severity, rule.Cooldown) {
			n.sendAlert(ctx, rule.Severity, count, rule.Window)
		}
	}
}

func (n *Notifier) getErrorCountSince(ctx context.Context, severity string, window time.Duration) (int, error) {
	ctx, span := observability.StartSpan(ctx, "alert-notifier", "db.get_error_count_since",
		attribute.String("error.severity", severity),
	)
	defer span.End()

	since := time.Now().Add(-window)
	var count int
	err := db.DB.QueryRow(ctx, `
		SELECT COALESCE(SUM(count), 0)
		FROM clusters
		WHERE severity = $1 AND last_seen >= $2
	`, severity, since).Scan(&count)
	observability.MarkSpanError(span, err)
	return count, err
}

func (n *Notifier) canAlert(severity string, cooldown time.Duration) bool {
	alertState.mu.Lock()
	defer alertState.mu.Unlock()

	last, ok := alertState.lastAlert[severity]
	if !ok {
		return true
	}
	return time.Since(last) >= cooldown
}

func (n *Notifier) recordAlert(severity string) {
	alertState.mu.Lock()
	defer alertState.mu.Unlock()
	alertState.lastAlert[severity] = time.Now()
}

func (n *Notifier) shouldRecordAndAlert(severity string, cooldown time.Duration) bool {
	alertState.mu.Lock()
	defer alertState.mu.Unlock()

	now := time.Now()
	last, exists := alertState.lastAlert[severity]
	if exists && now.Sub(last) < cooldown {
		return false
	}
	alertState.lastAlert[severity] = now
	return true
}

func (n *Notifier) sendAlert(ctx context.Context, severity string, count int, window time.Duration) {
	ctx, span := observability.StartSpan(ctx, "alert-notifier", "external.smtp_send",
		attribute.String("external.system", "smtp"),
		attribute.String("error.severity", severity),
	)
	defer span.End()

	if len(n.cfg.ToEmails) == 0 {
		return
	}

	m := gomail.NewMessage()
	m.SetHeader("From", n.cfg.FromEmail)
	m.SetHeader("To", n.cfg.ToEmails...)
	m.SetHeader("Subject", "Alert: API Failure - "+severity+" ("+strconv.Itoa(count)+" errors)")

	body := "<html><body>" +
		"<h2>API Failure Alert</h2>" +
		"<p><strong>Severity:</strong> " + severity + "</p>" +
		"<p><strong>Error Count:</strong> " + strconv.Itoa(count) + " errors in last " + window.String() + "</p>" +
		"<p>Please investigate the errors in the dashboard.</p>" +
		"</body></html>"
	m.SetBody("text/html", body)

	d := gomail.NewDialer(n.cfg.SMTPHost, n.cfg.SMTPPort, n.cfg.SMTPUser, n.cfg.SMTPPassword)

	if err := d.DialAndSend(m); err != nil {
		observability.MarkSpanError(span, err)
		metrics.FailureFrequency.WithLabelValues("api-failure-analyzer", "external_call").Inc()
		logger.Get().Errorw("failed to send alert email", "error", err)
	} else {
		logger.Get().Infow("alert email sent", "severity", severity, "count", count)
	}
}
