package analyzer

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
)

type Result struct {
	ErrorMessage string
	ErrorType    string
	Fingerprint  string
}

func AnalyzeLog(log string) Result {
	msg := extractError(log)
	typ := classifyError(msg)
	fp := fingerprint(msg)

	return Result{
		ErrorMessage: msg,
		ErrorType:    typ,
		Fingerprint:  fp,
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
