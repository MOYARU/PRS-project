package components

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

var commentRegex = regexp.MustCompile(`<!--.*?v?(\d+\.\d+(\.\d+)?).*?-->`)

func CheckVulnerableComponents(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	headersToCheck := map[string]string{
		"Server":       ctx.Response.Header.Get("Server"),
		"X-Powered-By": ctx.Response.Header.Get("X-Powered-By"),
	}

	for header, value := range headersToCheck {
		if value != "" {
			if isOutdated(value) {
				findings = append(findings, createFinding(fmt.Sprintf("%s Header: %s", header, value)))
			}
		}
	}

	bodyString := string(ctx.BodyBytes)
	matches := commentRegex.FindAllStringSubmatch(bodyString, -1)

	for _, match := range matches {
		fullComment := match[0]

		if isOutdated(fullComment) {
			findings = append(findings, createFinding(fmt.Sprintf("HTML Comment: %s", fullComment)))
		}
	}

	return findings, nil
}

func isOutdated(versionStr string) bool {
	v := strings.ToLower(versionStr)

	if strings.Contains(v, "apache/2.2") || strings.Contains(v, "apache/2.0") {
		return true
	}
	if strings.Contains(v, "php/5.") || strings.Contains(v, "php/4.") {
		return true
	}
	if strings.Contains(v, "nginx/1.0") || strings.Contains(v, "nginx/0.") {
		return true
	}
	if strings.Contains(v, "jquery v1.") || strings.Contains(v, "jquery 1.") {
		return true
	}
	// Add more rules as needed
	return false
}

func createFinding(info string) report.Finding {
	msg := msges.GetMessage("COMPONENT_OUTDATED_DETECTED")
	return report.Finding{
		ID:                         "COMPONENT_OUTDATED_DETECTED",
		Category:                   string(checks.CategoryVulnerableComponents),
		Severity:                   report.SeverityMedium,
		Confidence:                 report.ConfidenceMedium,
		Title:                      msg.Title,
		Message:                    fmt.Sprintf(msg.Message, info),
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	}
}
