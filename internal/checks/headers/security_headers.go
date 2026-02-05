package headers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/report"
)

const hstsMaxAgeBaseline = 31536000

func CheckSecurityHeaders(ctx *checks.Context) ([]report.Finding, error) {
	if ctx.Response == nil {
		return nil, nil
	}

	headers := ctx.Response.Header
	var findings []report.Finding

	findings = append(findings, missingHeader("Content-Security-Policy",
		report.SeverityMedium,
		"Missing Content-Security-Policy",
		"XSS 공격 방어 불가",
		"Content-Security-Policy: default-src 'self';",
		headers)...)

	findings = append(findings, missingHeader("X-Frame-Options",
		report.SeverityLow,
		"Missing X-Frame-Options",
		"Clickjacking 공격 가능",
		"X-Frame-Options: DENY",
		headers)...)

	findings = append(findings, missingHeader("X-Content-Type-Options",
		report.SeverityLow,
		"Missing X-Content-Type-Options",
		"MIME 타입 스니핑 방어 불가",
		"X-Content-Type-Options: nosniff",
		headers)...)

	findings = append(findings, missingHeader("Referrer-Policy",
		report.SeverityLow,
		"Missing Referrer-Policy",
		"Referrer 정보 과다 노출 가능",
		"Referrer-Policy: strict-origin-when-cross-origin",
		headers)...)

	findings = append(findings, missingHeader("Permissions-Policy",
		report.SeverityLow,
		"Missing Permissions-Policy",
		"브라우저 기능 제어 미흡",
		"Permissions-Policy: geolocation=()",
		headers)...)

	findings = append(findings, missingHeader("Cross-Origin-Opener-Policy",
		report.SeverityLow,
		"Missing Cross-Origin-Opener-Policy",
		"탭 격리 보호 미흡",
		"Cross-Origin-Opener-Policy: same-origin",
		headers)...)

	findings = append(findings, missingHeader("Cross-Origin-Embedder-Policy",
		report.SeverityLow,
		"Missing Cross-Origin-Embedder-Policy",
		"격리된 컨텍스트 보호 미흡",
		"Cross-Origin-Embedder-Policy: require-corp",
		headers)...)

	findings = append(findings, missingHeader("Cross-Origin-Resource-Policy",
		report.SeverityLow,
		"Missing Cross-Origin-Resource-Policy",
		"리소스 공유 정책 미설정",
		"Cross-Origin-Resource-Policy: same-site",
		headers)...)

	findings = append(findings, checkHSTS(ctx, headers)...)
	findings = append(findings, checkCookieFlags(ctx.Response)...)
	findings = append(findings, checkInfoHeaders(headers)...)

	return findings, nil
}

func missingHeader(name string, severity report.Severity, title, message, fix string, headers http.Header) []report.Finding {
	if headers.Get(name) != "" {
		return nil
	}
	return []report.Finding{
		{
			ID:       strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_MISSING",
			Category: string(checks.CategorySecurityHeaders),
			Severity: severity,
			Title:    title,
			Message:  message,
			Fix:      fix,
		},
	}
}

func checkHSTS(ctx *checks.Context, headers http.Header) []report.Finding {
	if ctx.FinalURL == nil || ctx.FinalURL.Scheme != "https" {
		return nil
	}

	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" {
		return []report.Finding{
			{
				ID:       "HSTS_MISSING",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityHigh,
				Title:    "Missing Strict-Transport-Security",
				Message:  "HTTPS 연결 강제 및 다운그레이드 방어 미흡",
				Fix:      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			},
		}
	}

	maxAge := parseHSTSMaxAge(hsts)
	if maxAge > 0 && maxAge < hstsMaxAgeBaseline {
		return []report.Finding{
			{
				ID:       "HSTS_MAXAGE_LOW",
				Category: string(checks.CategorySecurityHeaders),
				Severity: report.SeverityMedium,
				Title:    "HSTS max-age too low",
				Message:  "HSTS max-age 값이 낮아 보호 기간이 부족합니다",
				Fix:      "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
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
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SECURE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    "Cookie Secure flag missing",
			Message:  "Secure 플래그가 없는 쿠키가 있습니다: " + strings.Join(insecureCookies, ", "),
			Fix:      "Set-Cookie에 Secure 플래그를 추가하세요",
		})
	}

	if len(httpOnlyMissing) > 0 {
		findings = append(findings, report.Finding{
			ID:       "COOKIE_HTTPONLY_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    "Cookie HttpOnly flag missing",
			Message:  "HttpOnly 플래그가 없는 쿠키가 있습니다: " + strings.Join(httpOnlyMissing, ", "),
			Fix:      "Set-Cookie에 HttpOnly 플래그를 추가하세요",
		})
	}

	if len(sameSiteMissing) > 0 {
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_MISSING",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityLow,
			Title:    "Cookie SameSite not set",
			Message:  "SameSite 미설정 쿠키가 있습니다: " + strings.Join(sameSiteMissing, ", "),
			Fix:      "Set-Cookie에 SameSite=Lax 또는 Strict를 추가하세요",
		})
	}

	if len(sameSiteNoneInsecure) > 0 {
		findings = append(findings, report.Finding{
			ID:       "COOKIE_SAMESITE_NONE_INSECURE",
			Category: string(checks.CategoryAuthSession),
			Severity: report.SeverityMedium,
			Title:    "SameSite=None without Secure",
			Message:  "SameSite=None이지만 Secure 플래그가 없는 쿠키가 있습니다: " + strings.Join(sameSiteNoneInsecure, ", "),
			Fix:      "SameSite=None 사용 시 Secure 플래그를 함께 설정하세요",
		})
	}

	return findings
}

func checkInfoHeaders(headers http.Header) []report.Finding {
	var findings []report.Finding

	if server := headers.Get("Server"); server != "" {
		findings = append(findings, report.Finding{
			ID:       "SERVER_HEADER_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    "Server header exposed",
			Message:  "서버 정보 노출",
			Fix:      "Server 헤더 제거 또는 최소화",
		})
	}

	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		findings = append(findings, report.Finding{
			ID:       "X_POWERED_BY_EXPOSED",
			Category: string(checks.CategoryInfrastructure),
			Severity: report.SeverityInfo,
			Title:    "X-Powered-By header exposed",
			Message:  "프레임워크 또는 런타임 정보 노출",
			Fix:      "X-Powered-By 헤더 제거 또는 최소화",
		})
	}

	return findings
}
