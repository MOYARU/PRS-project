package info

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	"github.com/MOYARU/PRS-project/internal/checks/application"    // For IsErrorPage helper
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckInformationLeakage checks for various types of information leakage in the response body.
func CheckInformationLeakage(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	bodyString := string(ctx.BodyBytes) // Use ctx.BodyBytes

	// Define leakage patterns
	type leakagePattern struct {
		MsgID string // Changed to MsgID
		Match func(body string) bool
	}

	patterns := []leakagePattern{
		{
			MsgID: "INFORMATION_LEAKAGE_STACK_TRACE",
			Match: func(b string) bool {
				return strings.Contains(b, "stack trace") || strings.Contains(b, "Stack trace") ||
					(strings.Contains(b, "at ") && strings.Contains(b, "line ") && (strings.Contains(b, ".java") || strings.Contains(b, ".go"))) ||
					(strings.Contains(b, "at ") && strings.Contains(b, "in ") && strings.Contains(b, ".cs"))
			},
		},
		{
			MsgID: "INFORMATION_LEAKAGE_DB_ERROR",
			Match: func(b string) bool {
				return strings.Contains(b, "SQLSTATE") || strings.Contains(b, "ORA-") || strings.Contains(b, "SQL error") ||
					strings.Contains(b, "JDBC error") || strings.Contains(b, "PostgreSQL error") || strings.Contains(b, "MySQL error") || strings.Contains(b, "db error")
			},
		},
	}

	for _, p := range patterns {
		if p.Match(bodyString) {
			msg := msges.GetMessage(p.MsgID) // Retrieve message
			findings = append(findings, report.Finding{
				ID:         p.MsgID,
				Category:   string(checks.CategoryInformationLeakage),
				Severity:   report.SeverityMedium,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    msg.Message,
				Fix:        msg.Fix,
			})
		}
	}

	// Framework Signature (passive from response headers/body)
	// Some common headers indicating frameworks
	for headerName, headerValue := range ctx.Response.Header {
		lowerHeaderName := strings.ToLower(headerName)
		lowerHeaderValue := strings.ToLower(strings.Join(headerValue, " ")) // Join multiple values

		if lowerHeaderName == "x-powered-by" && lowerHeaderValue != "" {
			msg := msges.GetMessage("INFORMATION_LEAKAGE_X_POWERED_BY")
			findings = append(findings, report.Finding{
				ID:         "INFORMATION_LEAKAGE_X_POWERED_BY",
				Category:   string(checks.CategoryInformationLeakage),
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceMedium,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, lowerHeaderValue),
				Fix:        msg.Fix,
			})
		}
		if lowerHeaderName == "server" {
			// Exclude common CDNs/proxies, focusing on direct server technologies
			if !(strings.Contains(lowerHeaderValue, "cloudflare") || strings.Contains(lowerHeaderValue, "aws") || strings.Contains(lowerHeaderValue, "gcp") || strings.Contains(lowerHeaderValue, "akamai")) {
				if strings.Contains(lowerHeaderValue, "nginx") || strings.Contains(lowerHeaderValue, "apache") || strings.Contains(lowerHeaderValue, "iis") {
					msg := msges.GetMessage("INFORMATION_LEAKAGE_SERVER_HEADER")
					findings = append(findings, report.Finding{
						ID:         "INFORMATION_LEAKAGE_SERVER_HEADER",
						Category:   string(checks.CategoryInformationLeakage),
						Severity:   report.SeverityLow,
						Confidence: report.ConfidenceMedium,
						Title:      msg.Title,
						Message:    fmt.Sprintf(msg.Message, lowerHeaderValue),
						Fix:        msg.Fix,
					})
				}
			}
		}
	}

	// Framework Signature (passive from body)
	if strings.Contains(bodyString, "X-AspNet-Version") ||
		strings.Contains(bodyString, "X-Generator") ||
		strings.Contains(bodyString, "WordPress") ||
		strings.Contains(bodyString, "Joomla!") {
		msg := msges.GetMessage("INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE")
		findings = append(findings, report.Finding{
			ID:         "INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE",
			Category:   string(checks.CategoryInformationLeakage),
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceMedium,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	// Debug/Meta Endpoints (Active check)
	if ctx.Mode == ctxpkg.Active {
		// Common debug/meta endpoints to probe
		debugEndpoints := []string{
			"/.env", "/.git/config", "/.git/HEAD", "/debug", "/admin", "/phpinfo.php",
			"/server-status", "/~root", "/~admin", "/manager/html", "/jmx-console",
		}

		client := engine.NewHTTPClient(false, nil) // Reuse default client
		for _, endpoint := range debugEndpoints {
			endpointURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + endpoint
			req, err := http.NewRequest("GET", endpointURL, nil)
			if err != nil {
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				bodyBytes, _ := engine.DecodeResponseBody(resp)
				// Use IsErrorPage to filter out generic 404/error pages
				if !application.IsErrorPage(string(bodyBytes), resp.StatusCode) {
					msg := msges.GetMessage("INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT")
					findings = append(findings, report.Finding{
						ID:         "INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT",
						Category:   string(checks.CategoryInformationLeakage),
						Severity:   report.SeverityMedium,
						Confidence: report.ConfidenceMedium,
						Title:      msg.Title,
						Message:    fmt.Sprintf(msg.Message, endpoint),
						Fix:        msg.Fix,
					})
				}
			}
		}
	}

	return findings, nil
}
