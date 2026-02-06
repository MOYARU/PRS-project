package api

import (
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	msges "github.com/MOYARU/PRS-project/internal/messages"        // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckRateLimitAbsence checks for the absence of Rate Limit headers.
func CheckRateLimitAbsence(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Check only Passive as it inspects headers of the original response
	// Active rate limit bypass testing would be a much more complex check.

	// Check for Retry-After header absence
	if ctx.Response.Header.Get("Retry-After") == "" {
		msg := msges.GetMessage("RETRY_AFTER_HEADER_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "RETRY_AFTER_HEADER_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow, // Low risk as it's an absence of info, not a direct vulnerability
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	// Check for X-RateLimit-* headers absence
	xRateLimitFound := false
	for header := range ctx.Response.Header {
		if strings.HasPrefix(strings.ToLower(header), "x-ratelimit-") {
			xRateLimitFound = true
			break
		}
	}

	if !xRateLimitFound {
		msg := msges.GetMessage("X_RATELIMIT_HEADERS_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "X_RATELIMIT_HEADERS_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
