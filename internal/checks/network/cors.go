package network

import (
	"fmt"
	"net/http"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckCORSConfiguration checks for Cross-Origin Resource Sharing (CORS) configuration errors.
func CheckCORSConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Passive checks from original response
	// Check for 'Access-Control-Allow-Origin: *' (wildcard)
	if ctx.Response.Header.Get("Access-Control-Allow-Origin") == "*" {
		msg := msges.GetMessage("CORS_WILDCARD_ORIGIN")
		findings = append(findings, report.Finding{
			ID:         "CORS_WILDCARD_ORIGIN",
			Category:   string(checks.CategoryNetwork),
			Severity:   report.SeverityMedium,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	// Active checks for Origin reflection
	if ctx.Mode == ctxpkg.Active {
		testOrigin := "https://malicious.com"
		req, err := http.NewRequest("GET", ctx.FinalURL.String(), nil)
		if err != nil {
			return findings, err
		}
		req.Header.Set("Origin", testOrigin)

		client := engine.NewHTTPClient(false, nil)
		resp, err := client.Do(req)
		if err != nil {
			return findings, err
		}
		defer resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		if acao == testOrigin {
			msg := msges.GetMessage("CORS_ORIGIN_REFLECTION")
			findings = append(findings, report.Finding{
				ID:         "CORS_ORIGIN_REFLECTION",
				Category:   string(checks.CategoryNetwork),
				Severity:   report.SeverityHigh,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, testOrigin), // Use fmt.Sprintf for variable parts
				Fix:        msg.Fix,
			})
		}
	}

	return findings, nil
}
