package authsession

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckAuthSessionHardening performs various checks related to authentication and session management hardening.
// This includes cookie attributes like Secure, HttpOnly, SameSite, and expiration.
func CheckAuthSessionHardening(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Check for login page HTTPS, which was part of the original AUTH_SESSION_CONFIGURATION
	loginPageURL := findLoginPage(ctx.InitialURL.String())
	if loginPageURL != "" {
		findings = append(findings, checkLoginPageHTTPS(ctx, loginPageURL)...)
	}

	// Check session cookie attributes and expiration
	findings = append(findings, checkCookieAttributes(ctx.Response)...)

	return findings, nil
}

// CheckSessionManagement performs active checks related to session management, like re-issuance.
// This check is highly dependent on the ability to perform authenticated requests.
func CheckSessionManagement(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil // Session Management typically requires active testing (login simulation)
	}

	// Actual implementation for 'Set-Cookie identical before/after login' and 'No session re-issuance'
	// would require:
	// 1. Identifying login endpoints (already have findLoginPage, but need more robust detection).
	// 2. Having a mechanism to provide credentials and perform login.
	// 3. Capturing pre-login cookies.
	// 4. Performing login and capturing post-login cookies.
	// 5. Comparing session IDs/cookies to detect re-issuance or changes.

	// This is a complex active check. For now, it remains a placeholder encouraging manual review or
	// a note for future advanced active scanning features.
	msg := msges.GetMessage("SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED")
	findings = append(findings, report.Finding{
		ID:                         "SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED",
		Category:                   string(checks.CategoryAuthSession),
		Severity:                   report.SeverityInfo,
		Confidence:                 report.ConfidenceLow,
		Title:                      msg.Title,
		Message:                    msg.Message,
		Fix:                        msg.Fix,
		IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
	})

	return findings, nil
}

// findLoginPage attempts to find a login page URL.
// This is a simplified placeholder; a real implementation would involve:
// - Analyzing HTML for links like /login, /signin, /account
// - Checking common login path patterns
// - Potentially using a wordlist
func findLoginPage(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	// Common login paths
	for _, path := range []string{"/login", "/signin", "/account/login", "/user/login", "/admin/login"} {
		testURL := u.Scheme + "://" + u.Host + path
		resp, err := engine.FetchWithTLSConfig(testURL, nil) // Use default client
		if err == nil && resp.Response != nil && resp.Response.StatusCode == http.StatusOK {
			resp.Response.Body.Close()
			return testURL
		}
		if resp != nil && resp.Response != nil {
			resp.Response.Body.Close()
		}
	}
	return ""
}

// checkLoginPageHTTPS checks if the login page is not using HTTPS.
func checkLoginPageHTTPS(ctx *ctxpkg.Context, loginPageURL string) []report.Finding {
	var findings []report.Finding
	u, err := url.Parse(loginPageURL)
	if err != nil {
		return findings
	}

	if u.Scheme != "https" {
		msg := msges.GetMessage("LOGIN_PAGE_HTTPS_MISSING")
		findings = append(findings, report.Finding{
			ID:                         "LOGIN_PAGE_HTTPS_MISSING",
			Category:                   string(checks.CategoryAuthSession),
			Severity:                   report.SeverityHigh,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, loginPageURL),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

// checkCookieAttributes checks for Secure, HttpOnly, SameSite=None + Secure, and session cookie expiration.
func checkCookieAttributes(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	var findings []report.Finding
	cookies := resp.Cookies()

	for _, cookie := range cookies {
		// Heuristic: identify potential session cookies.
		// This is a simplification; a more robust check would involve common session cookie names.
		// Or if there's no specific session cookie, any cookie without these flags is a risk.
		isPotentiallySessionRelated := strings.Contains(strings.ToLower(cookie.Name), "session") ||
			strings.Contains(strings.ToLower(cookie.Name), "jsessionid") ||
			strings.Contains(strings.ToLower(cookie.Name), "phpsessid") ||
			strings.Contains(strings.ToLower(cookie.Name), "aspsessionid") ||
			strings.Contains(strings.ToLower(cookie.Name), "auth") ||
			strings.Contains(strings.ToLower(cookie.Name), "id")

		// Secure Flag
		if !cookie.Secure && strings.HasPrefix(strings.ToLower(resp.Request.URL.Scheme), "https") {
			msg := msges.GetMessage("COOKIE_SECURE_FLAG_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "COOKIE_SECURE_FLAG_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}

		// HttpOnly Flag
		if !cookie.HttpOnly {
			msg := msges.GetMessage("COOKIE_HTTPONLY_FLAG_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "COOKIE_HTTPONLY_FLAG_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}

		// Session Cookie Expiration
		if isPotentiallySessionRelated && cookie.Expires.IsZero() {
			msg := msges.GetMessage("SESSION_COOKIE_NO_EXPIRATION")
			findings = append(findings, report.Finding{
				ID:                         "SESSION_COOKIE_NO_EXPIRATION",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookie.Name),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	// Check SameSite=None without Secure separately by inspecting raw headers
	// This avoids O(N*M) complexity and incorrect attribution in the loop above.
	for _, setCookieHeader := range resp.Header["Set-Cookie"] {
		if strings.Contains(setCookieHeader, "SameSite=None") && !strings.Contains(setCookieHeader, "Secure") {
			// Try to extract cookie name for better reporting
			cookieName := "Unknown"
			parts := strings.Split(setCookieHeader, ";")
			if len(parts) > 0 {
				kv := strings.SplitN(parts[0], "=", 2)
				if len(kv) > 0 {
					cookieName = strings.TrimSpace(kv[0])
				}
			}
			msg := msges.GetMessage("SAMESITE_NONE_SECURE_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "SAMESITE_NONE_SECURE_MISSING",
				Category:                   string(checks.CategoryAuthSession),
				Severity:                   report.SeverityHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, cookieName),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}
