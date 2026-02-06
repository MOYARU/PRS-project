package api

import (
	"bytes"
	"encoding/json"

	"net/http"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

func CheckContentTypeConfusion(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil // 엑티브 스캔에서만
	}

	if strings.Contains(ctx.Response.Header.Get("Content-Type"), "application/json") {
		dummyJSON := map[string]string{"test": "value"}
		jsonBody, _ := json.Marshal(dummyJSON)

		req, err := http.NewRequest("POST", ctx.FinalURL.String(), bytes.NewReader(jsonBody))
		if err != nil {
			return findings, err
		}
		req.Header.Set("Content-Type", "text/plain") // Send as text/plain
		req.Header.Set("Accept", "application/json") // Still prefer JSON in response

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			return findings, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			msg := msges.GetMessage("JSON_API_TEXT_PLAIN_ALLOWED")
			findings = append(findings, report.Finding{
				ID:                         "JSON_API_TEXT_PLAIN_ALLOWED",
				Category:                   string(checks.CategoryAPISecurity),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceMedium,
				Title:                      msg.Title,
				Message:                    msg.Message,
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	// Check 2: Accept header ignored
	req, err := http.NewRequest("GET", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings, err
	}
	req.Header.Set("Accept", "text/html") // Request HTML content

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") && !strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		msg := msges.GetMessage("ACCEPT_HEADER_IGNORED")
		findings = append(findings, report.Finding{
			ID:                         "ACCEPT_HEADER_IGNORED",
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
