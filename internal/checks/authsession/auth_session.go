package authsession

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

func CheckAuthSessionHardening(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	loginPageURL := findLoginPage(ctx.InitialURL.String())
	if loginPageURL != "" {
		findings = append(findings, checkLoginPageHTTPS(ctx, loginPageURL)...)
	}

	findings = append(findings, checkCookieAttributes(ctx.Response)...)

	return findings, nil
}

func CheckSessionManagement(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}
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

func checkCookieAttributes(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	var findings []report.Finding
	cookies := resp.Cookies()

	for _, cookie := range cookies {
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

	for _, setCookieHeader := range resp.Header["Set-Cookie"] {
		if strings.Contains(setCookieHeader, "SameSite=None") && !strings.Contains(setCookieHeader, "Secure") {
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
