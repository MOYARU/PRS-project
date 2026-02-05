package authsession

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

// CheckAuthSessionConfiguration performs various checks related to authentication and session management.
func CheckAuthSessionConfiguration(ctx *checks.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Placeholder for finding login page URL. For now, assume it's /login or similar.
	// In a real scenario, this would involve spidering or user input.
	loginPageURL := findLoginPage(ctx.InitialURL.String()) // This needs to be a real function

	if loginPageURL != "" {
		// 로그인 페이지 HTTPS 미사용
		findings = append(findings, checkLoginPageHTTPS(ctx, loginPageURL)...)
	}

	// 세션 쿠키 만료 없음
	findings = append(findings, checkSessionCookieExpiration(ctx.Response)...)

	// URL에 세션 노출 - This is hard to detect passively from a single response, requires analysis of subsequent requests.
	// Placeholder for now.

	// 로그아웃 후 세션 유지 가능성 - Requires simulating login/logout.
	// Placeholder for now.

	// 인증 실패 시 동일한 응답 여부 (계정 존재 노출) - Requires trying valid/invalid usernames.
	// Placeholder for now.

	// 다중 인증(MFA) 부재 (Info) - Not detectable passively without specific knowledge.
	// Placeholder for now.

	// 기본 계정 존재 가능성 - Requires trying common default credentials.
	// Placeholder for now.

	return findings, nil
}

// findLoginPage attempts to find a login page URL.
// This is a simplified placeholder. A real implementation would involve:
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
func checkLoginPageHTTPS(ctx *checks.Context, loginPageURL string) []report.Finding {
	var findings []report.Finding
	u, err := url.Parse(loginPageURL)
	if err != nil {
		return findings
	}

	if u.Scheme != "https" {
		findings = append(findings, report.Finding{
			ID:       "LOGIN_PAGE_HTTPS_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityHigh,
			Title:    "로그인 페이지 HTTPS 미사용",
			Message:  fmt.Sprintf("로그인 페이지 '%s'가 HTTPS를 사용하지 않아 인증 정보가 평문으로 전송될 위험이 있습니다.", loginPageURL),
			Fix:      "로그인 페이지를 포함한 모든 인증 관련 페이지에 HTTPS를 강제 적용하십시오.",
		})
	}
	return findings
}

// checkSessionCookieExpiration checks for session cookies that do not have an expiration.
func checkSessionCookieExpiration(resp *http.Response) []report.Finding {
	if resp == nil {
		return nil
	}

	var findings []report.Finding
	cookies := resp.Cookies()

	for _, cookie := range cookies {
		// Heuristic: identify potential session cookies.
		// This is a simplification; a more robust check would involve common session cookie names.
		isSessionCookie := strings.Contains(strings.ToLower(cookie.Name), "session") ||
			strings.Contains(strings.ToLower(cookie.Name), "jsessionid") ||
			strings.Contains(strings.ToLower(cookie.Name), "phpsessid") ||
			strings.Contains(strings.ToLower(cookie.Name), "aspsessionid")

		if isSessionCookie && cookie.Expires.IsZero() {
			findings = append(findings, report.Finding{
				ID:       "SESSION_COOKIE_NO_EXPIRATION",
				Category: string(checks.CategoryAuthSession),
				Severity: report.SeverityMedium,
				Title:    "세션 쿠키 만료 없음",
				Message:  fmt.Sprintf("세션 쿠키 '%s'가 만료 시간을 설정하지 않아, 장기간 브라우저에 남아있을 수 있습니다.", cookie.Name),
				Fix:      "세션 쿠키에 적절한 만료 시간(Expires 또는 Max-Age)을 설정하여 세션 하이재킹 위험을 줄이십시오.",
			})
		}
	}
	return findings
}
