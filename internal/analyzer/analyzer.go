package analyzer

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Result struct {
	ErrorMessage string
	ErrorType    string
	Fingerprint  string
	Severity     Severity
}

func AnalyzeLog(log string, count int) Result {
	msg := extractError(log)
	typ := classifyError(msg)
	fp := fingerprint(msg)

	sev := classifySeverity(typ, count)

	return Result{
		ErrorMessage: msg,
		ErrorType:    typ,
		Fingerprint:  fp,
		Severity:     sev,
	}
}

func classifySeverity(errorType string, count int) Severity {
	base := getBaseSeverity(errorType)

	switch {
	case count >= 100:
		if base < SeverityHigh {
			return SeverityHigh
		}
		return SeverityCritical
	case count >= 50:
		if base < SeverityMedium {
			return SeverityMedium
		}
		return SeverityHigh
	case count >= 10:
		if base == SeverityLow {
			return SeverityMedium
		}
		return base
	default:
		return base
	}
}

func getBaseSeverity(errorType string) Severity {
	switch errorType {
	case "timeout_error":
		return SeverityMedium
	case "connection_error":
		return SeverityMedium
	case "nil_pointer":
		return SeverityHigh
	case "auth_error":
		return SeverityHigh
	case "out_of_memory":
		return SeverityCritical
	case "disk_full":
		return SeverityCritical
	default:
		return SeverityLow
	}
}

func extractError(log string) string {
	lines := strings.Split(log, "\n")
	for _, l := range lines {
		if strings.Contains(strings.ToLower(l), "error") {
			return strings.TrimSpace(l)
		}
	}
	return "unknown error"
}

func classifyError(msg string) string {
	msg = strings.ToLower(msg)

	switch {
	case strings.Contains(msg, "timeout"):
		return "timeout_error"
	case strings.Contains(msg, "connection"):
		return "connection_error"
	case strings.Contains(msg, "nil pointer"):
		return "nil_pointer"
	case strings.Contains(msg, "unauthorized"):
		return "auth_error"
	default:
		return "unknown_error"
	}
}

func fingerprint(msg string) string {
	re := regexp.MustCompile(`\d+`)
	clean := re.ReplaceAllString(msg, "")
	hash := sha1.Sum([]byte(clean))
	return hex.EncodeToString(hash[:])
}
