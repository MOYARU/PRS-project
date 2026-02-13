package api

import (
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

func CheckRateLimitAbsence(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response.Header.Get("Retry-After") == "" {
		msg := msges.GetMessage("RETRY_AFTER_HEADER_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "RETRY_AFTER_HEADER_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   "The 'Retry-After' header was not found in the response.",
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
			Evidence:                   "No 'X-RateLimit-*' headers were found in the response.",
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
