package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html" // Added for HTML parsing

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckWebContentExposure performs various checks on exposed web content like robots.txt, sitemap.xml, etc.
func CheckWebContentExposure(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Active Checks: File probes
	if ctx.Mode == ctxpkg.Active {
		// robots.txt
		findings = append(findings, checkPathExposure(ctx, "/robots.txt", "ROBOTS_TXT_EXPOSED", checks.CategoryFileExposure)...)

		// sitemap.xml
		findings = append(findings, checkPathExposure(ctx, "/sitemap.xml", "SITEMAP_XML_EXPOSED", checks.CategoryFileExposure)...)

		// security.txt
		findings = append(findings, checkPathExposure(ctx, "/.well-known/security.txt", "SECURITY_TXT_EXPOSED", checks.CategoryFileExposure)...)

		// .well-known/ directory listing
		findings = append(findings, checkPathExposure(ctx, "/.well-known/", "WELL_KNOWN_EXPOSED", checks.CategoryFileExposure)...)

		// .git exposure
		findings = append(findings, checkPathExposure(ctx, "/.git/HEAD", "GIT_HEAD_EXPOSED", checks.CategoryFileExposure)...)
		findings = append(findings, checkPathExposure(ctx, "/.git/config", "GIT_CONFIG_EXPOSED", checks.CategoryFileExposure)...)

		// .env exposure
		findings = append(findings, checkPathExposure(ctx, "/.env", "ENV_EXPOSED", checks.CategoryFileExposure)...)

		// CI/CD file traces (e.g., .travis.yml, .gitlab-ci.yml, Jenkinsfile)
		findings = append(findings, checkPathExposure(ctx, "/.travis.yml", "TRAVIS_YML_EXPOSED", checks.CategoryFileExposure)...)
		findings = append(findings, checkPathExposure(ctx, "/.gitlab-ci.yml", "GITLAB_CI_YML_EXPOSED", checks.CategoryFileExposure)...)
		findings = append(findings, checkPathExposure(ctx, "/Jenkinsfile", "JENKINSFILE_EXPOSED", checks.CategoryFileExposure)...)

		// Backup files (.bak, ~) - Placeholder

		// Cloud metadata endpoint access (AWS/GCP) - Placeholder

		// favicon hash 기반 프레임워크 추정 - Placeholder

		// 디버그 페이지 흔적 (/actuator, /debug 존재 여부만)
		findings = append(findings, checkPathExposure(ctx, "/actuator", "ACTUATOR_ENDPOINT_EXPOSED", checks.CategoryInfrastructure)...)
		findings = append(findings, checkPathExposure(ctx, "/debug", "DEBUG_ENDPOINT_EXPOSED", checks.CategoryInfrastructure)...)
	}

	// K. 클라이언트(브라우저) 보안
	if ctx.Response != nil && ctx.Response.StatusCode == http.StatusOK {
		contentType := ctx.Response.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") {
			bodyBytes, err := engine.DecodeResponseBody(ctx.Response)
			if err == nil {
				bodyString := string(bodyBytes)
				// Parse HTML once and reuse the node tree
				doc, err := html.Parse(strings.NewReader(bodyString))
				if err == nil {
					findings = append(findings, checkMixedContent(ctx, doc)...)
					findings = append(findings, checkIframeSandbox(ctx, doc)...)
					findings = append(findings, checkInlineScripts(ctx, doc)...)
				}
			}
		}
	}

	return findings, nil
}

// checkPathExposure attempts to fetch a specific path and reports if it's accessible.
// It now takes the message ID as a parameter.
func checkPathExposure(ctx *ctxpkg.Context, path string, msgID string, category checks.Category) []report.Finding {
	var findings []report.Finding
	targetURL := resolveRelativeURL(ctx.FinalURL, path)

	resp, err := engine.FetchWithTLSConfig(targetURL.String(), nil) // Use default client
	if err != nil {
		return findings
	}
	defer resp.Response.Body.Close()

	// Check if the status code indicates public exposure (e.g., 200 OK, not 404 Not Found)
	// We might need to refine this to ignore 403 Forbidden if it's considered "not exposed" in some contexts
	if resp.Response.StatusCode == http.StatusOK {
		msg := msges.GetMessage(msgID)
		findings = append(findings, report.Finding{
			ID:                         strings.ReplaceAll(strings.ToUpper(path), "/", "_") + "_EXPOSED", // Dynamic ID based on path
			Category:                   string(category),
			Severity:                   report.SeverityMedium,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, path),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

// resolveRelativeURL resolves a relative path against a base URL.
func resolveRelativeURL(baseURL *url.URL, relativePath string) *url.URL {
	newURL, _ := url.Parse(relativePath)
	return baseURL.ResolveReference(newURL)
}

// checkMixedContent detects mixed content issues on HTTPS pages.
func checkMixedContent(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	// Only relevant for HTTPS pages
	if ctx.FinalURL.Scheme != "https" {
		return findings
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attrName := ""
			switch n.Data {
			case "script", "img", "audio", "video", "source", "embed", "track":
				attrName = "src"
			case "link":
				for _, a := range n.Attr {
					if a.Key == "rel" && (a.Val == "stylesheet" || a.Val == "preload") {
						attrName = "href"
						break
					}
				}
			}

			if attrName != "" {
				for _, a := range n.Attr {
					if a.Key == attrName {
						if strings.HasPrefix(a.Val, "http://") {
							msg := msges.GetMessage("MIXED_CONTENT_DETECTED")
							findings = append(findings, report.Finding{
								ID:                         "MIXED_CONTENT_DETECTED",
								Category:                   string(checks.CategoryClientSecurity),
								Severity:                   report.SeverityMedium,
								Title:                      msg.Title,
								Message:                    fmt.Sprintf(msg.Message, a.Val),
								Fix:                        msg.Fix,
								IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
							})
							// Report only once per resource
							break
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return findings
}

// checkIframeSandbox detects if iframes are missing the sandbox attribute.
func checkIframeSandbox(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "iframe" {
			hasSandbox := false
			for _, a := range n.Attr {
				if a.Key == "sandbox" {
					hasSandbox = true
					break
				}
			}
			if !hasSandbox {
				src := ""
				for _, a := range n.Attr {
					if a.Key == "src" {
						src = a.Val
						break
					}
				}
				msg := msges.GetMessage("IFRAME_SANDBOX_MISSING")
				findings = append(findings, report.Finding{
					ID:                         "IFRAME_SANDBOX_MISSING",
					Category:                   string(checks.CategoryClientSecurity),
					Severity:                   report.SeverityMedium,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, src),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return findings
}

// checkInlineScripts checks for the presence of inline <script> tags without a 'src' attribute.
func checkInlineScripts(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	// Check if Content-Security-Policy header exists and is strict enough
	cspHeader := ctx.Response.Header.Get("Content-Security-Policy")
	hasStrictCSP := false
	if cspHeader != "" {
		// A very basic check: does it contain 'unsafe-inline' or is it generally permissive?
		// A more robust check would involve parsing CSP.
		if !strings.Contains(cspHeader, "'unsafe-inline'") &&
			!strings.Contains(cspHeader, "script-src *") &&
			!strings.Contains(cspHeader, "script-src 'self' 'unsafe-eval'") { // simplified check
			hasStrictCSP = true
		}
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			isInline := true
			for _, a := range n.Attr {
				if a.Key == "src" {
					isInline = false
					break
				}
			}
			if isInline && strings.TrimSpace(n.FirstChild.Data) != "" { // Check if it's not an empty script tag
				// If CSP is not strict, or absent, report inline scripts
				if !hasStrictCSP {
					msg := msges.GetMessage("INLINE_SCRIPT_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "INLINE_SCRIPT_DETECTED",
						Category:                   string(checks.CategoryClientSecurity),
						Severity:                   report.SeverityMedium,
						Title:                      msg.Title,
						Message:                    msg.Message,
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
					})
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return findings
}
