package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	msges "github.com/MOYARU/PRS-project/internal/messages"        // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckJSONUnexpectedField checks for application behavior when unexpected fields are inserted into JSON requests.
func CheckJSONUnexpectedField(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil // This is an active check
	}

	// Only proceed if the original response indicates a JSON endpoint
	if !strings.Contains(ctx.Response.Header.Get("Content-Type"), "application/json") {
		return findings, nil
	}

	// Attempt to get a JSON body from the original response for modification
	var originalJSON map[string]interface{}
	err := json.Unmarshal(ctx.BodyBytes, &originalJSON)
	if err != nil {
		// If original body is not valid JSON, or empty, create a dummy one
		originalJSON = make(map[string]interface{})
	}

	// Add an unexpected field
	originalJSON["prs_unexpected_field"] = "prs_test_value"

	modifiedJSON, err := json.Marshal(originalJSON)
	if err != nil {
		return findings, fmt.Errorf("failed to marshal modified JSON: %w", err)
	}

	// Send the request with the modified JSON
	req, err := http.NewRequest("POST", ctx.FinalURL.String(), bytes.NewReader(modifiedJSON))
	if err != nil {
		return findings, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := ctx.HTTPClient.Do(req) // Use the shared client from the context
	if err != nil {
		return findings, err
	}
	defer resp.Body.Close()

	// Heuristic: If the response is 200 OK and doesn't explicitly reject the unexpected field, it's a finding.
	// A robust check would involve comparing against a "clean" request response.
	// For now, simple success without explicit error is a weak indicator.
	if resp.StatusCode == http.StatusOK {
		// Further analysis needed here to confirm if the field was actually processed or just ignored.
		// For simplicity, if it's 200 OK and not an obvious error response, we report.
		msg := msges.GetMessage("JSON_UNEXPECTED_FIELD_INSERTION")
		findings = append(findings, report.Finding{
			ID:                         "JSON_UNEXPECTED_FIELD_INSERTION",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow, // Low severity as it's often ignored by frameworks
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}
