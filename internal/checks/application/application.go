package application

import (
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/PRS-project/internal/checks"                // Keep for Category types
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckApplicationSecurity performs various application-level security checks.
func CheckApplicationSecurity(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// E. 입력 처리
	findings = append(findings, checkInputReflection(ctx)...)
	// JSON / HTML / JS 컨텍스트 구분 - This requires deeper parsing and content analysis.
	// Placeholder for now.
	// 파라미터 타입 불일치 - This requires knowledge of expected parameter types and sending invalid types.
	// Placeholder for now.

	// F. 접근 제어
	// IDOR 가능성 (숫자 ID 패턴만 감지)
	if ctx.Mode == ctxpkg.Active { // IDOR check is active
		findings = append(findings, checkIDOR(ctx)...)
	}
	// CSRF 토큰 부재 (존재 여부만) - Requires analyzing forms/requests for token presence.
	findings = append(findings, checkCSRFTokenPresence(ctx)...)

	// J. API 특화
	// GraphQL introspection enabled (Active check)
	if ctx.Mode == ctxpkg.Active {
		findings = append(findings, checkGraphQLIntrospection(ctx)...)
	}

	return findings, nil
}

// checkInputReflection attempts to find reflected input in the response body.
func checkInputReflection(ctx *ctxpkg.Context) []report.Finding {
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

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return findings
	}

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := engine.DecodeResponseBody(resp) // Use the helper for decoding
		if err != nil {
			return findings
		}
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, testString) {
			msg := msges.GetMessage("INPUT_REFLECTION_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "INPUT_REFLECTION_DETECTED",
				Category:                   string(checks.CategoryInputHandling),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, "prs_test_param"),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}

func checkIDOR(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	var originalURL string
	originalURL = ctx.FinalURL.String()

	// Heuristic: Look for numerical IDs in path segments or query parameters.	// Example: /users/123 -> /users/124
	// Example: ?id=123 -> ?id=124

	// Path segment IDOR
	pathSegments := strings.Split(ctx.FinalURL.Path, "/")
	for i, segment := range pathSegments {
		if id, err := strconv.Atoi(segment); err == nil && id > 1 { // Found a number, and it's not 0 or 1 (common for default/guest)
			// Try decrementing
			testPath := strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id-1) + strings.Join(pathSegments[i+1:], "/")
			var testURL string // Declare testURL
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath
			msg := msges.GetMessage("IDOR_POSSIBLE") // Assuming IDOR_POSSIBLE has format string
			findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id-1), msg.IsPotentiallyFalsePositive)...)

			// Try incrementing (if not already tried)
			testPath = strings.Join(pathSegments[:i], "/") + "/" + strconv.Itoa(id+1) + strings.Join(pathSegments[i+1:], "/")
			testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + testPath // Re-assign testURL
			msg = msges.GetMessage("IDOR_POSSIBLE")                              // Assuming IDOR_POSSIBLE has format string
			findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id+1), msg.IsPotentiallyFalsePositive)...)
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
				msg := msges.GetMessage("IDOR_POSSIBLE") // Assuming IDOR_POSSIBLE has format string
				findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id-1), msg.IsPotentiallyFalsePositive)...)

				// Try incrementing
				newQuery.Set(param, strconv.Itoa(id+1))
				testURL = ctx.FinalURL.Scheme + "://" + ctx.FinalURL.Host + ctx.FinalURL.Path + "?" + newQuery.Encode()
				msg = msges.GetMessage("IDOR_POSSIBLE") // Assuming IDOR_POSSIBLE has format string
				findings = append(findings, probeIDOR(ctx, originalURL, testURL, fmt.Sprintf(msg.Message, id, id+1), msg.IsPotentiallyFalsePositive)...)
			}
		}
	}

	return findings
}

func probeIDOR(ctx *ctxpkg.Context, originalURL, testURL, description string, isPotentiallyFalsePositive bool) []report.Finding {
	var findings []report.Finding

	// Fetch the original URL to compare response size/content
	reqOrig, err := http.NewRequest("GET", originalURL, nil)
	if err != nil {
		return findings
	}
	originalResp, err := ctx.HTTPClient.Do(reqOrig)
	if err != nil {
		return findings
	}
	defer originalResp.Body.Close()
	originalBody, _ := engine.DecodeResponseBody(originalResp)

	// Fetch the test URL
	reqTest, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return findings
	}
	testResp, err := ctx.HTTPClient.Do(reqTest)
	if err != nil {
		return findings
	}
	defer testResp.Body.Close()
	testBody, _ := engine.DecodeResponseBody(testResp)

	// Simple heuristic: If the status codes are similar and body content/size is similar but not identical (and not an explicit redirect/error indicating no access)
	// This is a very basic check and needs refinement.
	if originalResp.StatusCode == http.StatusOK && testResp.StatusCode == http.StatusOK {
		// More sophisticated comparison needed here (e.g., semantic diff, checking for error messages)
		if len(originalBody) > 0 && len(testBody) > 0 && len(originalBody) != len(testBody) {
			msg := msges.GetMessage("IDOR_POSSIBLE")
			findings = append(findings, report.Finding{
				ID:                         "IDOR_POSSIBLE",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, description),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	} else if testResp.StatusCode == http.StatusOK && originalResp.StatusCode == http.StatusNotFound {
		// If original was 404 but test is 200, it means we found something by changing ID (e.g., guessing a valid ID)
		msg := msges.GetMessage("IDOR_RESOURCE_GUESSING")
		findings = append(findings, report.Finding{
			ID:                         "IDOR_RESOURCE_GUESSING",
			Category:                   string(checks.CategoryAccessControl),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, description),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings
}

// checkCSRFTokenPresence checks for the presence of CSRF tokens in HTML forms.
// This is a very basic check and assumes a simple form structure.
func checkCSRFTokenPresence(ctx *ctxpkg.Context) []report.Finding {
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
			msg := msges.GetMessage("CSRF_TOKEN_POSSIBLY_MISSING")
			findings = append(findings, report.Finding{
				ID:                         "CSRF_TOKEN_POSSIBLY_MISSING",
				Category:                   string(checks.CategoryAccessControl),
				Severity:                   report.SeverityMedium,
				Title:                      msg.Title,
				Message:                    msg.Message,
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	return findings
}

// checkGraphQLIntrospection checks if GraphQL introspection is enabled.
func checkGraphQLIntrospection(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	// Mode check is already done in CheckApplicationSecurity, but good to have here for clarity
	if ctx.Mode == ctxpkg.Passive {
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

		resp, err := ctx.HTTPClient.Do(req)
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
				msg := msges.GetMessage("GRAPHQL_INTROSPECTION_ENABLED")
				findings = append(findings, report.Finding{
					ID:                         "GRAPHQL_INTROSPECTION_ENABLED",
					Category:                   string(checks.CategoryAPI),
					Severity:                   report.SeverityMedium,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, path),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
				// Only report once per target, even if found on multiple paths
				return findings
			}
		}
	}
	return findings
}

// TODO: These functions should probably be in a separate utility file or a sub-package
// For now, they are defined here to resolve compilation errors.

// ExtractTextFromHTML parses an HTML body and extracts visible text content.
func ExtractTextFromHTML(body []byte) string {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return ""
	}

	var buf strings.Builder
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			// Trim spaces and newlines
			text := strings.TrimSpace(n.Data)
			if len(text) > 0 {
				buf.WriteString(text)
				buf.WriteString(" ") // Add space between text nodes
			}
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "head", "noscript", "iframe":
				return // Skip content of these tags
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return strings.TrimSpace(buf.String())
}

// CalculateTextSimilarity computes a simple similarity score between two text blocks.
// It tokenizes by spaces and counts common words.
func CalculateTextSimilarity(text1, text2 string) float64 {
	words1 := strings.Fields(strings.ToLower(text1))
	words2 := strings.Fields(strings.ToLower(text2))

	if len(words1) == 0 && len(words2) == 0 {
		return 1.0 // Both empty, considered 100% similar
	}
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0 // One is empty, the other is not, considered 0% similar
	}

	// Create frequency maps
	freq1 := make(map[string]int)
	for _, word := range words1 {
		freq1[word]++
	}

	freq2 := make(map[string]int)
	for _, word := range words2 {
		freq2[word]++
	}

	intersection := 0
	for word, count := range freq1 {
		if freq2[word] > 0 {
			intersection += int(math.Min(float64(count), float64(freq2[word])))
		}
	}

	union := len(words1) + len(words2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// IsErrorPage checks if the response body or status code indicates an error page.
func IsErrorPage(body string, status int) bool {
	// Common error status codes
	if status >= 400 && status < 500 && status != http.StatusOK && status != http.StatusFound && status != http.StatusForbidden {
		return true // Client error without specific redirect/forbidden
	}
	return false
}
