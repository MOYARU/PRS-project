// Package injection implements checks for injection vulnerabilities like SQLi and XSS.
package injection

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckSQLInjection attempts to detect SQL Injection vulnerabilities by injecting common SQL error triggers.
func CheckSQLInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	// Basic SQL error patterns (simplified list)
	errorPatterns := []string{
		"SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL error", "SQLite/JDBCDriver", "System.Data.SqlClient",
	}

	// Payloads that might trigger syntax errors
	payloads := []string{"'", "\"", "'--", ") OR 1=1--"}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		return findings, nil
	}

	for param, values := range queryParams {
		originalValue := values[0] // Test primarily the first value

		for _, payload := range payloads {
			// Construct malicious URL
			newParams := cloneParams(queryParams)
			newParams.Set(param, originalValue+payload) // Append payload
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}

			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			bodyBytes, _ := engine.DecodeResponseBody(resp)
			bodyString := string(bodyBytes)

			for _, pattern := range errorPatterns {
				if strings.Contains(bodyString, pattern) {
					findings = append(findings, report.Finding{
						ID:         "SQL_INJECTION_ERROR_BASED",
						Category:   string(checks.CategoryInputHandling),
						Severity:   report.SeverityHigh,
						Confidence: report.ConfidenceHigh,
						Title:      "SQL Injection (Error Based) 취약점",
						Message:    fmt.Sprintf("파라미터 '%s'에 '%s' 입력 시 데이터베이스 에러가 발생했습니다.", param, payload),
						Fix:        "모든 데이터베이스 쿼리에 Prepared Statement(파라미터화된 쿼리)를 사용하고, 입력값을 검증하십시오.",
					})
					// Found one vulnerability for this param, move to next param to avoid spam
					goto NextParam
				}
			}
		}
	NextParam:
	}

	return findings, nil
}

// CheckReflectedXSS attempts to detect Reflected XSS by injecting a script tag.
func CheckReflectedXSS(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	// A unique string to look for in the response
	canary := "PRS_XSS_PROBE"
	payload := fmt.Sprintf("\"><script>alert('%s')</script>", canary)

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		return findings, nil
	}

	for param, values := range queryParams {
		originalValue := values[0]

		// Construct malicious URL
		newParams := cloneParams(queryParams)
		newParams.Set(param, originalValue+payload)
		u.RawQuery = newParams.Encode()

		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		resp, err := ctx.HTTPClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := engine.DecodeResponseBody(resp)
		bodyString := string(bodyBytes)

		// Check if payload is reflected AND content-type is HTML
		if strings.Contains(bodyString, payload) && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			findings = append(findings, report.Finding{
				ID:         "REFLECTED_XSS",
				Category:   string(checks.CategoryClientSecurity),
				Severity:   report.SeverityHigh,
				Confidence: report.ConfidenceMedium, // Medium because browser XSS filters might block it
				Title:      "Reflected XSS 취약점",
				Message:    fmt.Sprintf("파라미터 '%s'에 입력한 스크립트가 응답 본문에 그대로 반환됩니다.", param),
				Fix:        "사용자 입력값을 HTML 엔티티로 인코딩하여 출력하고, 적절한 CSP를 설정하십시오.",
			})
		}
	}

	return findings, nil
}

// CheckBlindSQLInjection attempts to detect time-based blind SQL injection.
func CheckBlindSQLInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	delaySeconds := 5
	// Payloads for different database systems
	payloads := []string{
		fmt.Sprintf("' AND (SELECT %d FROM (SELECT(SLEEP(%d)))a)-- ", delaySeconds, delaySeconds), // MySQL
		fmt.Sprintf("'; SELECT pg_sleep(%d)--", delaySeconds),                                     // PostgreSQL
		fmt.Sprintf("' WAITFOR DELAY '0:0:%d'--", delaySeconds),                                   // MSSQL
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()
	if len(queryParams) == 0 {
		return findings, nil
	}

	for param, values := range queryParams {
		originalValue := values[0]

		for _, payload := range payloads {
			newParams := cloneParams(queryParams)
			newParams.Set(param, originalValue+payload)
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}

			startTime := time.Now()
			resp, err := ctx.HTTPClient.Do(req)
			duration := time.Since(startTime)

			if err != nil {
				continue
			}
			resp.Body.Close()

			if duration.Seconds() >= float64(delaySeconds) {
				msg := msges.GetMessage("BLIND_SQLI_TIME_BASED")
				findings = append(findings, report.Finding{
					ID:                         "BLIND_SQLI_TIME_BASED",
					Category:                   string(checks.CategoryInputHandling),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceMedium,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, param, delaySeconds),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
				// Found a potential vulnerability, move to the next parameter
				goto NextParamBlind
			}
		}
	NextParamBlind:
	}

	return findings, nil
}

// CheckOSCommandInjection attempts to detect time-based OS command injection.
func CheckOSCommandInjection(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	delaySeconds := 5
	// Payloads for both Linux/Unix-like and Windows systems
	payloads := []string{
		fmt.Sprintf("&& sleep %d", delaySeconds),               // Unix
		fmt.Sprintf("; sleep %d", delaySeconds),                // Unix
		fmt.Sprintf("| sleep %d", delaySeconds),                // Unix
		fmt.Sprintf("&& ping -n %d 127.0.0.1", delaySeconds+1), // Windows
		fmt.Sprintf("| ping -n %d 127.0.0.1", delaySeconds+1),  // Windows
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()
	if len(queryParams) == 0 {
		return findings, nil
	}

	for param, values := range queryParams {
		originalValue := values[0]

		for _, payload := range payloads {
			newParams := cloneParams(queryParams)
			newParams.Set(param, originalValue+payload)
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}

			startTime := time.Now()
			resp, err := ctx.HTTPClient.Do(req)
			duration := time.Since(startTime)

			if err != nil {
				continue
			}
			resp.Body.Close()

			if duration.Seconds() >= float64(delaySeconds) {
				msg := msges.GetMessage("OS_COMMAND_INJECTION_TIME_BASED")
				findings = append(findings, report.Finding{
					ID:                         "OS_COMMAND_INJECTION_TIME_BASED",
					Category:                   string(checks.CategoryInputHandling),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceMedium,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, param, delaySeconds),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
				// Found a potential vulnerability, move to the next parameter
				goto NextParamOS
			}
		}
	NextParamOS:
	}

	return findings, nil
}

// TODO: Stored XSS, DOM XSS, NoSQL, LDAP injection checks require more advanced techniques.
// Stored XSS requires crawling and state management.
// DOM XSS requires a headless browser.
// NoSQL/LDAP are highly context-dependent.
// These are placeholders for future implementation.

func cloneParams(v url.Values) url.Values {
	dst := make(url.Values, len(v))
	for k, vv := range v {
		dst[k] = append([]string(nil), vv...)
	}
	return dst
}
