package api

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MOYARU/prs/internal/checks"
	ctxpkg "github.com/MOYARU/prs/internal/checks/context"
	msges "github.com/MOYARU/prs/internal/messages"
	"github.com/MOYARU/prs/internal/report"
)

func CheckRateLimitAbsence(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Response == nil || ctx.Response.Request == nil {
		return findings, nil
	}

	path := ""
	if reqURL, err := url.Parse(ctx.Response.Request.URL.String()); err == nil {
		path = strings.ToLower(reqURL.Path)
	}
	contentType := strings.ToLower(ctx.Response.Header.Get("Content-Type"))
	isLikelyAPI := strings.Contains(contentType, "json") ||
		strings.HasPrefix(path, "/api") ||
		strings.Contains(path, "/graphql")
	if !isLikelyAPI {
		return findings, nil
	}

	// If server already signals throttling, do not report missing headers.
	if ctx.Response.StatusCode == http.StatusTooManyRequests {
		return findings, nil
	}

	activeProbeSummary := ""
	activeProbeNoLimit := false
	if ctx.Mode == ctxpkg.Active && ctx.FinalURL != nil {
		totalRequests := 6
		throttled := false
		retryAfterSeen := false
		xRateLimitSeen := false

		for i := 0; i < totalRequests; i++ {
			req, err := newScanRequest(ctx, http.MethodGet, ctx.FinalURL.String(), nil)
			if err != nil {
				continue
			}
			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}
			if resp.StatusCode == http.StatusTooManyRequests {
				throttled = true
			}
			if resp.Header.Get("Retry-After") != "" {
				retryAfterSeen = true
			}
			if hasXRateLimitHeaders(resp.Header) {
				xRateLimitSeen = true
			}
			resp.Body.Close()
			time.Sleep(50 * time.Millisecond)
		}

		if throttled {
			return findings, nil
		}
		activeProbeNoLimit = !retryAfterSeen && !xRateLimitSeen
		activeProbeSummary = fmt.Sprintf("Active probe sent %d rapid requests; no 429 observed; Retry-After=%t; X-RateLimit headers=%t", totalRequests, retryAfterSeen, xRateLimitSeen)
	}

	if ctx.Response.Header.Get("Retry-After") == "" {
		msg := msges.GetMessage("RETRY_AFTER_HEADER_MISSING")
		evidence := "The 'Retry-After' header was not found in the response."
		if activeProbeSummary != "" {
			evidence = evidence + " " + activeProbeSummary
		}
		findings = append(findings, report.Finding{
			ID:                         "RETRY_AFTER_HEADER_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   evidence,
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	// Check for X-RateLimit-* headers absence
	xRateLimitFound := hasXRateLimitHeaders(ctx.Response.Header)
	if ctx.Mode == ctxpkg.Active && !activeProbeNoLimit {
		xRateLimitFound = true
	}

	if !xRateLimitFound {
		msg := msges.GetMessage("X_RATELIMIT_HEADERS_MISSING")
		evidence := "No 'X-RateLimit-*' headers were found in the response."
		if activeProbeSummary != "" {
			evidence = evidence + " " + activeProbeSummary
		}
		findings = append(findings, report.Finding{
			ID:                         "X_RATELIMIT_HEADERS_MISSING",
			Category:                   string(checks.CategoryAPISecurity),
			Severity:                   report.SeverityLow,
			Confidence:                 report.ConfidenceMedium,
			Title:                      msg.Title,
			Message:                    msg.Message,
			Evidence:                   evidence,
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}

	return findings, nil
}

func hasXRateLimitHeaders(h http.Header) bool {
	for header := range h {
		if strings.HasPrefix(strings.ToLower(header), "x-ratelimit-") {
			return true
		}
	}
	return false
}

func newScanRequest(scanCtx *ctxpkg.Context, method, target string, body io.Reader) (*http.Request, error) {
	if scanCtx != nil && scanCtx.RequestContext != nil {
		return http.NewRequestWithContext(scanCtx.RequestContext, method, target, body)
	}
	return http.NewRequest(method, target, body)
}
