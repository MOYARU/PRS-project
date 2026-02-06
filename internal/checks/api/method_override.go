package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	msges "github.com/MOYARU/PRS-project/internal/messages"        // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckMethodOverride checks if HTTP Method Override is allowed.
func CheckMethodOverride(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil // Method Override check is active
	}

	// For Method Override, we send a POST request with X-HTTP-Method-Override header.
	// We'll primarily check for responses that indicate the override was processed.
	// We specifically avoid state-changing methods on known resources.
	// For now, we'll try overriding to DELETE on the current URL.
	// We only check allowance, not actual side effects.

	// 1. Send a normal POST request (baseline)
	normalPostReq, err := http.NewRequest("POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	normalPostResp, err := ctx.HTTPClient.Do(normalPostReq)
	if err != nil {
		return findings, err
	}
	defer normalPostResp.Body.Close()

	// 2. Send a POST request with Method Override (e.g., to DELETE)
	overrideMethod := "DELETE" // Try to override POST to DELETE
	overridePostReq, err := http.NewRequest("POST", ctx.FinalURL.String(), strings.NewReader(""))
	if err != nil {
		return findings, err
	}
	overridePostReq.Header.Set("X-HTTP-Method-Override", overrideMethod)
	overridePostResp, err := ctx.HTTPClient.Do(overridePostReq)
	if err != nil {
		return findings, err
	}
	defer overridePostResp.Body.Close()

	// Heuristic: If overriding POST to DELETE yields a different response than normal POST,
	// and especially if it's a 200 OK or 204 No Content for a DELETE that shouldn't succeed with POST.
	// Or if it reflects an error specific to the DELETE method.
	if normalPostResp.StatusCode != overridePostResp.StatusCode ||
		(overridePostResp.StatusCode == http.StatusOK || overridePostResp.StatusCode == http.StatusNoContent) {
		// Further checks needed to ensure it's not a generic error.
		// For simplicity, if status codes are different, or it's a successful override, report it.
		msg := msges.GetMessage("METHOD_OVERRIDE_ALLOWED")
		findings = append(findings, report.Finding{
			ID:                         "METHOD_OVERRIDE_ALLOWED",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityMedium,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, overrideMethod),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
