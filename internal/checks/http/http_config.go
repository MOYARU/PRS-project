package http

import (
	"fmt"
	"io"
	"math/rand" // Added for generateRandomString
	"net/http"
	"strings"
	"time" // Added for seeding rand

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// CheckHTTPConfiguration performs various checks on HTTP protocol settings.
func CheckHTTPConfiguration(ctx *checks.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil {
		return findings, nil
	}

	// TRACE 메서드 활성화
	findings = append(findings, checkTRACEMethod(ctx)...)

	// OPTIONS 과다 노출
	findings = append(findings, checkOPTIONSMethod(ctx)...)

	// PUT / DELETE 허용 여부 (Active scan only)
	if ctx.Mode == checks.Active {
		findings = append(findings, checkPUTDELETEMethods(ctx)...)
	}

	// HTTP 응답 코드 이상 (401/403 혼동) - Requires more context/logic, perhaps for specific paths.
	// For now, this is a placeholder.

	// Chunked encoding 취약 설정 - This is hard to detect passively from a single response without deep packet inspection.
	// Placeholder for now.

	// HTTP/2 설정 오류 - Check response headers for H2. If not, maybe try to force HTTP/2?
	// Placeholder for now.

	return findings, nil
}

// checkTRACEMethod checks if the TRACE method is enabled.
func checkTRACEMethod(ctx *checks.Context) []report.Finding {
	var findings []report.Finding
	if ctx.FinalURL.Scheme != "https" { // Only check for TRACE over HTTPS to avoid plaintext issues
		return findings
	}

	// Make a TRACE request
	req, err := http.NewRequest("TRACE", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}

	// Use a new client that doesn't follow redirects for this specific probe
	client := engine.NewHTTPClient(false, nil)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return findings
		}
		bodyString := string(bodyBytes)

		// If the response body contains the TRACE request itself, it's enabled
		if strings.Contains(bodyString, "TRACE / HTTP/1.1") || strings.Contains(bodyString, "TRACE "+ctx.FinalURL.Path+" HTTP/1.1") {
			findings = append(findings, report.Finding{
				ID:       "TRACE_METHOD_ENABLED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityMedium,
				Title:    "TRACE 메서드 활성화",
				Message:  "HTTP TRACE 메서드가 활성화되어 XST (Cross-Site Tracing) 공격에 취약할 수 있습니다.",
				Fix:      "웹 서버 설정에서 TRACE 메서드를 비활성화하십시오.",
			})
		}
	}
	return findings
}

// checkOPTIONSMethod checks for over-exposed OPTIONS method.
func checkOPTIONSMethod(ctx *checks.Context) []report.Finding {
	var findings []report.Finding

	// Make an OPTIONS request
	req, err := http.NewRequest("OPTIONS", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}

	client := engine.NewHTTPClient(false, nil)
	resp, err := client.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			allowedMethods := strings.Split(allowHeader, ",")
			if len(allowedMethods) > 3 { // More than GET, HEAD, POST typically indicates over-exposure
				findings = append(findings, report.Finding{
					ID:       "OPTIONS_OVER_EXPOSED",
					Category: string(checks.CategoryHTTPProtocol),
					Severity: report.SeverityLow,
					Title:    "OPTIONS 메서드 과다 노출",
					Message:  fmt.Sprintf("OPTIONS 메서드를 통해 허용되는 HTTP 메서드('%s')가 과도하게 노출되어 정보 유출 위험이 있습니다.", allowHeader),
					Fix:      "웹 서버 설정에서 OPTIONS 메서드를 통해 노출되는 메서드를 최소화하십시오.",
				})
			}
		}
	}
	return findings
}

// checkPUTDELETEMethods checks if PUT/DELETE methods are allowed (active scan).
func checkPUTDELETEMethods(ctx *checks.Context) []report.Finding {
	var findings []report.Finding
	testURL := ctx.FinalURL.String() + "/prs_test_file_" + generateRandomString(10) // Use a random file name

	// Test PUT
	putReq, err := http.NewRequest("PUT", testURL, strings.NewReader("test_content"))
	if err != nil {
		return findings
	}
	client := engine.NewHTTPClient(false, nil)
	putResp, err := client.Do(putReq)
	if err == nil {
		defer putResp.Body.Close()
		if putResp.StatusCode >= 200 && putResp.StatusCode < 300 || putResp.StatusCode == http.StatusCreated || putResp.StatusCode == http.StatusNoContent {
			findings = append(findings, report.Finding{
				ID:       "PUT_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    "PUT 메서드 허용",
				Message:  fmt.Sprintf("웹 서버가 임의의 경로에 PUT 메서드를 허용하여 파일 생성/수정에 취약할 수 있습니다. 테스트 경로: %s", testURL),
				Fix:      "웹 서버 설정에서 PUT 메서드를 필요한 경우에만 허용하고, 강력한 인증 및 권한 부여를 적용하십시오.",
			})
		}
	}

	// Test DELETE
	deleteReq, err := http.NewRequest("DELETE", testURL, nil)
	if err != nil {
		return findings
	}
	deleteResp, err := client.Do(deleteReq)
	if err == nil {
		defer deleteResp.Body.Close()
		if deleteResp.StatusCode >= 200 && deleteResp.StatusCode < 300 || deleteResp.StatusCode == http.StatusAccepted || deleteResp.StatusCode == http.StatusNoContent {
			findings = append(findings, report.Finding{
				ID:       "DELETE_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    "DELETE 메서드 허용",
				Message:  fmt.Sprintf("웹 서버가 임의의 경로에 DELETE 메서드를 허용하여 파일 삭제에 취약할 수 있습니다. 테스트 경로: %s", testURL),
				Fix:      "웹 서버 설정에서 DELETE 메서드를 필요한 경우에만 허용하고, 강력한 인증 및 권한 부여를 적용하십시오.",
			})
		}
	}

	return findings
}

// generateRandomString generates a random string of specified length.
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))] // rand is not cryptographically secure, but fine for file names
	}
	return string(b)
}

// Placeholder for checkHTTPResponseCodes (401/403 confusion)
// This requires specific scenarios (e.g., trying authenticated vs unauthenticated access to a protected resource)
// func checkHTTPResponseCodes(ctx *checks.Context) []report.Finding {
// 	return nil
// }

// Placeholder for checkChunkedEncoding (vulnerable chunked encoding)
// This is very low-level and hard to detect without custom TCP packet inspection.
// func checkChunkedEncoding(ctx *checks.Context) []report.Finding {
// 	return nil
// }

// Placeholder for checkHTTP2Configuration (HTTP/2 misconfigurations)
// This might involve checking ALPN, or trying to negotiate HTTP/2 explicitly.
// func checkHTTP2Configuration(ctx *checks.Context) []report.Finding {
// 	return nil
// }
