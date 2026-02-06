package deserialization

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckInsecureDeserialization checks for patterns indicating serialized data usage.
func CheckInsecureDeserialization(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// This check can be passive (inspecting values) or active (injecting).
	// We start with passive inspection of parameters and cookies.

	// 1. Inspect Query Parameters
	u, _ := url.Parse(ctx.FinalURL.String())
	for param, values := range u.Query() {
		for _, val := range values {
			if isSerializedData(val) {
				findings = append(findings, createFinding(param, "Query Parameter"))
			}
		}
	}

	// 2. Inspect Cookies
	if ctx.Response != nil {
		for _, cookie := range ctx.Response.Cookies() {
			if isSerializedData(cookie.Value) {
				findings = append(findings, createFinding(cookie.Name, "Cookie"))
			}
		}
	}

	return findings, nil
}

func isSerializedData(value string) bool {
	// 1. Check for Base64 encoding first
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil && len(decoded) > 4 {
		// Check for Java Serialization Magic Bytes (AC ED 00 05)
		if strings.HasPrefix(string(decoded), "\xac\xed\x00\x05") {
			return true
		}
		// Check for Python Pickle (simple heuristic: starts with ( and ends with .)
		// or specific opcodes like cos\nsystem
		if strings.Contains(string(decoded), "cos") && strings.Contains(string(decoded), "system") {
			return true
		}
	}

	// 2. Check for PHP Serialization (O:digit:"class_name"...)
	// Simple regex-like check: O:[0-9]+:
	if strings.HasPrefix(value, "O:") || strings.HasPrefix(value, "a:") {
		// Further validation could be done here
		return true
	}

	// 3. Check for Python Pickle (unencoded)
	if strings.HasPrefix(value, "(lp") || strings.HasPrefix(value, "gASV") { // gASV is base64 encoded pickle header often
		return true
	}

	return false
}

func createFinding(name, source string) report.Finding {
	msg := msges.GetMessage("INSECURE_DESERIALIZATION_SUSPECTED")
	return report.Finding{
		ID:                         "INSECURE_DESERIALIZATION_SUSPECTED",
		Category:                   string(checks.CategoryIntegrityFailures),
		Severity:                   report.SeverityHigh,
		Confidence:                 report.ConfidenceMedium,
		Title:                      msg.Title,
		Message:                    fmt.Sprintf(msg.Message, fmt.Sprintf("%s (%s)", name, source)),
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	}
}
