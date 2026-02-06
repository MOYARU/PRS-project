package headers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	msges "github.com/MOYARU/PRS-project/internal/messages"        // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

const hstsMaxAgeBaseline = 31536000

func CheckSecurityHeaders(ctx *ctxpkg.Context) ([]report.Finding, error) {
	if ctx.Response == nil {
		return nil, nil
	}

	headers := ctx.Response.Header
	var findings []report.Finding

	findings = append(findings, missingHeader(headers, "CONTENT_SECURITY_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityMedium)...)
	findings = append(findings, missingHeader(headers, "X_FRAME_OPTIONS_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "X_CONTENT_TYPE_OPTIONS_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "REFERRER_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "PERMISSIONS_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "CROSS_ORIGIN_OPENER_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "CROSS_ORIGIN_EMBEDDER_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)
	findings = append(findings, missingHeader(headers, "CROSS_ORIGIN_RESOURCE_POLICY_MISSING", checks.CategorySecurityHeaders, report.SeverityLow)...)

	findings = append(findings, checkHSTS(ctx, headers)...)
	findings = append(findings, checkCookieFlags(ctx.Response)...)
	findings = append(findings, checkInfoHeaders(headers)...)

	return findings, nil
}

// missingHeader checks for a missing header and returns a finding if it's absent.
// It now takes the message ID as a parameter.
func missingHeader(headers http.Header, msgID string, category checks.Category, severity report.Severity) []report.Finding {
	// Derive the actual header name from the message ID for checking presence.
	// This is a heuristic and might need refinement if IDs don't directly map to header names.
	// For example, "CONTENT_SECURITY_POLICY_MISSING" -> "Content-Security-Policy"
	headerName := strings.ReplaceAll(strings.ToLower(msgID), "_MISSING", "")
	headerName = strings.ReplaceAll(headerName, "_", "-")
	headerName = strings.Replace(headerName, "content-security-policy", "Content-Security-Policy", 1) // Specific capitalization
	headerName = strings.Replace(headerName, "x-frame-options", "X-Frame-Options", 1)
	headerName = strings.Replace(headerName, "x-content-type-options", "X-Content-Type-Options", 1)
	headerName = strings.Replace(headerName, "referrer-policy", "Referrer-Policy", 1)
	headerName = strings.Replace(headerName, "permissions-policy", "Permissions-Policy", 1)
	headerName = strings.Replace(headerName, "cross-origin-opener-policy", "Cross-Origin-Opener-Policy", 1)
	headerName = strings.Replace(headerName, "cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy", 1)
	headerName = strings.Replace(headerName, "cross-origin-resource-policy", "Cross-Origin-Resource-Policy", 1)

	if headers.Get(headerName) != "" {
		return nil
	}
	msg := msges.GetMessage(msgID)
	return []report.Finding{
		{
			ID:       msgID,
			Category: string(category),
			Severity: severity,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		},
	}
}

func checkHSTS(ctx *ctxpkg.Context, headers http.Header) []report.Finding {
	if ctx.FinalURL == nil || ctx.FinalURL.Scheme != "https" {
		return nil
	}

	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		msg := msges.GetMessage("HSTS_MISSING")
		return []report.Finding{
			{
				ID:       "HSTS_MISSING",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			},
		}
	}

	maxAge := parseHSTSMaxAge(hsts)
	if maxAge > 0 && maxAge < hstsMaxAgeBaseline {
		msg := msges.GetMessage("HSTS_MAXAGE_LOW")
		return []report.Finding{
			{
				ID:       "HSTS_MAXAGE_LOW",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			},
		}
	}

	return nil
}

func parseHSTSMaxAge(hsts string) int {
	parts := strings.Split(hsts, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			value := strings.TrimSpace(strings.SplitN(part, "=", 2)[1])
			parsed, err := strconv.Atoi(value)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func checkCookieFlags(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return nil
	}

	var insecureCookies []string
	var httpOnlyMissing []string
	var sameSiteMissing []string
	var sameSiteNoneInsecure []string

	for _, cookie := range cookies {
		if !cookie.Secure {
			insecureCookies = append(insecureCookies, cookie.Name)
		}
		if !cookie.HttpOnly {
			httpOnlyMissing = append(httpOnlyMissing, cookie.Name)
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			sameSiteMissing = append(sameSiteMissing, cookie.Name)
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			sameSiteNoneInsecure = append(sameSiteNoneInsecure, cookie.Name)
		}
	}

	var findings []report.Finding

	if len(insecureCookies) > 0 {
		msg := msges.GetMessage("COOKIE_SECURE_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SECURE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(insecureCookies, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(httpOnlyMissing) > 0 {
		msg := msges.GetMessage("COOKIE_HTTPONLY_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_HTTPONLY_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(httpOnlyMissing, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(sameSiteMissing) > 0 {
		msg := msges.GetMessage("COOKIE_SAMESITE_MISSING")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityLow,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(sameSiteMissing, ", ")),
			Fix:      msg.Fix,
		})
	}

	if len(sameSiteNoneInsecure) > 0 {
		msg := msges.GetMessage("COOKIE_SAMESITE_NONE_INSECURE")
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_NONE_INSECURE",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, strings.Join(sameSiteNoneInsecure, ", ")),
			Fix:      msg.Fix,
		})
	}

	return findings
}

func checkInfoHeaders(headers http.Header) []report.Finding {
	var findings []report.Finding

	if server := headers.Get("Server"); server != "" {
		msg := msges.GetMessage("SERVER_HEADER_EXPOSED")
		findings = append(findings, report.Finding{
			ID:       "SERVER_HEADER_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		msg := msges.GetMessage("X_POWERED_BY_EXPOSED")
		findings = append(findings, report.Finding{
			ID:       "X_POWERED_BY_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	return findings
}
