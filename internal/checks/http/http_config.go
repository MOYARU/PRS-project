package http

import (
	"fmt"
	"io"
	"math/rand" // Added for generateRandomString
	"net/http"
	"strings"
	"time" // Added for seeding rand

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	msges "github.com/MOYARU/PRS-project/internal/messages"        // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// CheckHTTPConfiguration performs various checks on HTTP protocol settings.
func CheckHTTPConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil {
		return findings, nil
	}

	// TRACE 메서드 활성화
	findings = append(findings, checkTRACEMethod(ctx)...)

	// OPTIONS 과다 노출
	findings = append(findings, checkOPTIONSMethod(ctx)...)

	// PUT / DELETE 허용 여부 (Active scan only)
	if ctx.Mode == ctxpkg.Active {
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
func checkTRACEMethod(ctx *ctxpkg.Context) []report.Finding {
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
	resp, err := ctx.HTTPClient.Do(req)
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
			msg := msges.GetMessage("TRACE_METHOD_ENABLED")
			findings = append(findings, report.Finding{
				ID:       "TRACE_METHOD_ENABLED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			})
		}
	}
	return findings
}

// checkOPTIONSMethod checks for over-exposed OPTIONS method.
func checkOPTIONSMethod(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding

	// Make an OPTIONS request
	req, err := http.NewRequest("OPTIONS", ctx.FinalURL.String(), nil)
	if err != nil {
		return findings
	}

	resp, err := ctx.HTTPClient.Do(req)
	if err != nil {
		return findings
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		allowHeader := resp.Header.Get("Allow")
		if allowHeader != "" {
			allowedMethods := strings.Split(allowHeader, ",")
			if len(allowedMethods) > 3 { // More than GET, HEAD, POST typically indicates over-exposure
				msg := msges.GetMessage("OPTIONS_OVER_EXPOSED")
				findings = append(findings, report.Finding{
					ID:       "OPTIONS_OVER_EXPOSED",
					Category: string(checks.CategoryHTTPProtocol),
					Severity: report.SeverityLow,
					Title:    msg.Title,
					Message:  fmt.Sprintf(msg.Message, allowHeader),
					Fix:      msg.Fix,
				})
			}
		}
	}
	return findings
}

// checkPUTDELETEMethods checks if PUT/DELETE methods are allowed (active scan).
func checkPUTDELETEMethods(ctx *ctxpkg.Context) []report.Finding {
	var findings []report.Finding
	testURL := ctx.FinalURL.String() + "/prs_test_file_" + generateRandomString(10) // Use a random file name

	// Test PUT
	putReq, err := http.NewRequest("PUT", testURL, strings.NewReader("test_content"))
	if err != nil {
		return findings
	}
	putResp, err := ctx.HTTPClient.Do(putReq)
	if err == nil {
		defer putResp.Body.Close()
		if putResp.StatusCode >= 200 && putResp.StatusCode < 300 || putResp.StatusCode == http.StatusCreated || putResp.StatusCode == http.StatusNoContent {
			msg := msges.GetMessage("PUT_METHOD_ALLOWED")
			findings = append(findings, report.Finding{
				ID:       "PUT_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, testURL),
				Fix:      msg.Fix,
			})
		}
	}

	// Test DELETE
	deleteReq, err := http.NewRequest("DELETE", testURL, nil)
	if err != nil {
		return findings
	}
	deleteResp, err := ctx.HTTPClient.Do(deleteReq)
	if err == nil {
		defer deleteResp.Body.Close()
		if deleteResp.StatusCode >= 200 && deleteResp.StatusCode < 300 || deleteResp.StatusCode == http.StatusAccepted || deleteResp.StatusCode == http.StatusNoContent {
			msg := msges.GetMessage("DELETE_METHOD_ALLOWED")
			findings = append(findings, report.Finding{
				ID:       "DELETE_METHOD_ALLOWED",
				Category: string(checks.CategoryHTTPProtocol),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, testURL),
				Fix:      msg.Fix,
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
