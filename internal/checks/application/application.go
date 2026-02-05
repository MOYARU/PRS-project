package application

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

// CheckApplicationSecurity performs various application-level security checks.
func CheckApplicationSecurity(ctx *checks.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// E. 입력 처리
	findings = append(findings, checkInputReflection(ctx)...)
	// JSON / HTML / JS 컨텍스트 구분 - This requires deeper parsing and content analysis.
	// Placeholder for now.
	// 파라미터 타입 불일치 - This requires knowledge of expected parameter types and sending invalid types.
	// Placeholder for now.

	// F. 접근 제어
	// IDOR 가능성 (숫자 ID 패턴만 감지)
	if ctx.Mode == checks.Active { // IDOR check is active
		findings = append(findings, checkIDOR(ctx)...)
	}
	// CSRF 토큰 부재 (존재 여부만) - Requires analyzing forms/requests for token presence.
	findings = append(findings, checkCSRFTokenPresence(ctx)...)

	// J. API 특화
	// GraphQL introspection enabled (Active check)
	if ctx.Mode == checks.Active {
		findings = append(findings, checkGraphQLIntrospection(ctx)...)
	}

	return findings, nil
}

// checkInputReflection attempts to find reflected input in the response body.
func checkInputReflection(ctx *checks.Context) []report.Finding {
	var findings []report.Finding

	// We'll attempt to inject a unique string into a URL parameter and check if it's reflected.
	// This is a basic form of XSS detection, but focusing on reflection.
	testString := "PRS_TEST_REFLECTION_STRING_12345"
	originalURL := ctx.FinalURL.String()

	// Try adding a new query parameter
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return findings
	}
	query := parsedURL.Query()
	query.Set("prs_test_param", testString)
	parsedURL.RawQuery = query.Encode()

	testURL := parsedURL.String()

	resp, err := engine.FetchWithTLSConfig(testURL, nil)
	if err != nil {
		return findings
	}
	defer resp.Response.Body.Close()

	if resp.Response.StatusCode == http.StatusOK {
		bodyBytes, err := engine.DecodeResponseBody(resp.Response) // Use the helper for decoding
		if err != nil {
			return findings
		}
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, testString) {
			findings = append(findings, report.Finding{
				ID:       "INPUT_REFLECTION_DETECTED",
				Category: string(checks.CategoryInputHandling),
				Severity: report.SeverityMedium,
				Title:    "입력값 Reflection 감지",
				Message:  fmt.Sprintf("URL 파라미터 '%s'의 입력값이 응답 본문에 반영되었습니다. 이는 XSS 공격으로 이어질 수 있습니다.", "prs_test_param"),
				Fix:      "사용자 입력값을 출력 시 적절한 인코딩(HTML 엔티티, URL 인코딩 등)을 적용하여 Reflection을 방지하십시오.",
			})
		}
	}
	return findings
}

// checkIDOR checks for potential IDOR (Insecure Direct Object Reference) vulnerabilities
// by trying to increment/decrement numerical IDs in the URL path or query parameters.
// This is an active check.
func checkIDOR(ctx *checks.Context) []report.Finding {
	var findings []report.Finding
	originalURL := ctx.FinalURL.String()

	// Heuristic: Look for numerical IDs in path segments or query parameters.
	// Example: /users/123 -> /users/124
	// Example: ?id=123 -> ?id=124

	// Path segment IDOR
	pathSegments := strings.Split(ctx.FinalURL.Path, "/")
	for i, segment := range pathSegments {
		if id, err := strconv.Atoi(segment); err == nil && id > 1 { // Found a number, and it's not 0 or 1 (common for default/guest)
			// Try decrementing
			testPath := strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id-1) + strings.Join(pathSegments[i+1:], "/")
			testURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath
			findings = append(findings, probeIDOR(originalURL, testURL, fmt.Sprintf("URL 경로 ID (%d -> %d)", id, id-1))...)

			// Try incrementing (if not already tried)
			testPath = strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id+1) + strings.Join(pathSegments[i+1:], "/")
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath
			findings = append(findings, probeIDOR(originalURL, testURL, fmt.Sprintf("URL 경로 ID (%d -> %d)", id, id+1))...)
		}
	}

	// Query parameter IDOR
	query := ctx.FinalURL.Query()
	for param, values := range query {
		if len(values) == 1 {
			if id, err := strconv.Atoi(values[0]); err == nil && id > 1 {
				// Try decrementing
				newQuery := url.Values{}
				for k, v := range query {
					newQuery[k] = v
				}
				newQuery.Set(param, strconv.Itoa(id-1))
				testURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				findings = append(findings, probeIDOR(originalURL, testURL, fmt.Sprintf("쿼리 파라미터 '%s' ID (%d -> %d)", param, id, id-1))...)

				// Try incrementing
				newQuery.Set(param, strconv.Itoa(id+1))
				testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				findings = append(findings, probeIDOR(originalURL, testURL, fmt.Sprintf("쿼리 파라미터 '%s' ID (%d -> %d)", param, id, id+1))...)
			}
		}
	}

	return findings
}

func probeIDOR(originalURL, testURL, description string) []report.Finding {
	var findings []report.Finding

	// Fetch the original URL to compare response size/content
	originalResp, err := engine.FetchWithTLSConfig(originalURL, nil)
	if err != nil {
		return findings
	}
	defer originalResp.Response.Body.Close()
	originalBody, _ := engine.DecodeResponseBody(originalResp.Response)

	// Fetch the test URL
	testResp, err := engine.FetchWithTLSConfig(testURL, nil)
	if err != nil {
		return findings
	}
	defer testResp.Response.Body.Close()
	testBody, _ := engine.DecodeResponseBody(testResp.Response)

	// Simple heuristic: If the status codes are similar and body content/size is similar but not identical (and not an explicit redirect/error indicating no access)
	// This is a very basic check and needs refinement.
	if originalResp.Response.StatusCode == http.StatusOK && testResp.Response.StatusCode == http.StatusOK {
		// More sophisticated comparison needed here (e.g., semantic diff, checking for error messages)
		if len(originalBody) > 0 && len(testBody) > 0 && len(originalBody) != len(testBody) {
			findings = append(findings, report.Finding{
				ID:       "IDOR_POSSIBLE",
				Category: string(checks.CategoryAccessControl),
				Severity: report.SeverityHigh,
				Title:    "IDOR 가능성 감지",
				Message:  fmt.Sprintf("숫자 ID 변경 (%s) 시 응답 내용이 변경되었습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.", description),
				Fix:      "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
			})
		}
	} else if testResp.Response.StatusCode == http.StatusOK && originalResp.Response.StatusCode == http.StatusNotFound {
		// If original was 404 but test is 200, it means we found something by changing ID (e.g., guessing a valid ID)
		findings = append(findings, report.Finding{
			ID:       "IDOR_RESOURCE_GUESSING",
			Category: string(checks.CategoryAccessControl),
			Severity: report.SeverityMedium,
			Title:    "IDOR 기반 리소스 추정 가능성",
			Message:  fmt.Sprintf("존재하지 않는 ID에 접근 시도 후 ID 변경 (%s)으로 유효한 리소스에 접근했습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.", description),
			Fix:      "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
		})
	}

	return findings
}

// checkCSRFTokenPresence checks for the presence of CSRF tokens in HTML forms.
// This is a very basic check and assumes a simple form structure.
func checkCSRFTokenPresence(ctx *checks.Context) []report.Finding {
	var findings []report.Finding

	if ctx.Response.StatusCode != http.StatusOK || ctx.Response.Header.Get("Content-Type") == "" || !strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		return findings
	}

	bodyBytes, err := engine.DecodeResponseBody(ctx.Response)
	if err != nil {
		return findings
	}
	bodyString := string(bodyBytes)

	// Look for common patterns of forms and CSRF tokens
	// This is a very simplistic check. A robust checker would parse HTML.
	if strings.Contains(strings.ToLower(bodyString), "<form") {
		// Heuristic: check if the page contains a form but no common CSRF token names
		// This is prone to false positives/negatives.
		hasCSRFToken := strings.Contains(strings.ToLower(bodyString), "csrf_token") ||
			strings.Contains(strings.ToLower(bodyString), "authenticity_token") ||
			strings.Contains(strings.ToLower(bodyString), "_token")

		if !hasCSRFToken {
			findings = append(findings, report.Finding{
				ID:       "CSRF_TOKEN_POSSIBLY_MISSING",
				Category: string(checks.CategoryAccessControl),
				Severity: report.SeverityMedium,
				Title:    "CSRF 토큰 부재 가능성",
				Message:  "HTML 폼에서 CSRF(Cross-Site Request Forgery) 공격 방어를 위한 토큰이 발견되지 않았을 수 있습니다.",
				Fix:      "모든 상태 변경 요청을 처리하는 폼에 CSRF 토큰을 포함하고, 토큰의 유효성을 검증하십시오.",
			})
		}
	}

	return findings
}

// checkGraphQLIntrospection checks if GraphQL introspection is enabled.
func checkGraphQLIntrospection(ctx *checks.Context) []report.Finding {
	var findings []report.Finding
	// Mode check is already done in CheckApplicationSecurity, but good to have here for clarity
	if ctx.Mode == checks.Passive {
		return findings
	}

	introspectionQuery := `{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{name description type{...TypeRef}defaultValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"}`

	// Common GraphQL endpoints
	graphqlPaths := []string{"/graphql", "/api/graphql", "/graph"}

	for _, path := range graphqlPaths {
		targetURL := ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + path

		req, err := http.NewRequest("POST", targetURL, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		client := engine.NewHTTPClient(false, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := engine.DecodeResponseBody(resp)
			if err != nil {
				continue
			}
			bodyString := string(bodyBytes)

			// Look for common introspection keywords in the response
			if strings.Contains(bodyString, "__schema") && strings.Contains(bodyString, "queryType") && strings.Contains(bodyString, "fields") {
				findings = append(findings, report.Finding{
					ID:       "GRAPHQL_INTROSPECTION_ENABLED",
					Category: string(checks.CategoryAPI),
					Severity: report.SeverityMedium,
					Title:    "GraphQL Introspection 활성화",
					Message:  fmt.Sprintf("GraphQL Introspection 기능이 '%s' 경로에서 활성화되어 스키마 정보가 노출될 수 있습니다.", path),
					Fix:      "운영 환경에서는 GraphQL Introspection 기능을 비활성화하여 API의 내부 구조 노출을 방지하십시오.",
				})
				// Only report once per target, even if found on multiple paths
				return findings
			}
		}
	}
	return findings
}
