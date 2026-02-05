package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html" // Added for HTML parsing

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

// CheckWebContentExposure performs checks for exposed web content like robots.txt, sitemap.xml, etc.
func CheckWebContentExposure(ctx *checks.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// robots.txt
	findings = append(findings, checkPathExposure(ctx, "/robots.txt", "robots.txt 파일 노출", checks.CategoryFileExposure)...)

	// sitemap.xml
	findings = append(findings, checkPathExposure(ctx, "/sitemap.xml", "sitemap.xml 파일 노출", checks.CategoryFileExposure)...)

	// security.txt
	findings = append(findings, checkPathExposure(ctx, "/.well-known/security.txt", "security.txt 파일 노출", checks.CategoryFileExposure)...)

	// .well-known/ directory listing
	findings = append(findings, checkPathExposure(ctx, "/.well-known/", ".well-known 디렉토리 노출", checks.CategoryFileExposure)...)

	// .git exposure
	findings = append(findings, checkPathExposure(ctx, "/.git/HEAD", ".git 디렉토리 노출 (HEAD 파일)", checks.CategoryFileExposure)...)
	findings = append(findings, checkPathExposure(ctx, "/.git/config", ".git 디렉토리 노출 (config 파일)", checks.CategoryFileExposure)...)

	// .env exposure
	findings = append(findings, checkPathExposure(ctx, "/.env", ".env 파일 노출", checks.CategoryFileExposure)...)

	// CI/CD file traces (e.g., .travis.yml, .gitlab-ci.yml, Jenkinsfile)
	findings = append(findings, checkPathExposure(ctx, "/.travis.yml", ".travis.yml (CI/CD) 파일 노출", checks.CategoryFileExposure)...)
	findings = append(findings, checkPathExposure(ctx, "/.gitlab-ci.yml", ".gitlab-ci.yml (CI/CD) 파일 노출", checks.CategoryFileExposure)...)
	findings = append(findings, checkPathExposure(ctx, "/Jenkinsfile", "Jenkinsfile (CI/CD) 파일 노출", checks.CategoryFileExposure)...)

	// Backup files (.bak, ~) - This is hard to detect generically without a wordlist or known patterns.
	// Placeholder for now.

	// Cloud metadata endpoint access (AWS/GCP)
	// This requires making requests to specific internal IPs (e.g., 169.254.169.254) which might not be reachable
	// from the scanner's perspective, or could trigger alerts. More complex.
	// Placeholder for now.

	// favicon hash 기반 프레임워크 추정 - Requires specific logic for hashing favicons and comparing.
	// Placeholder for now.

	// 디버그 페이지 흔적 (/actuator, /debug 존재 여부만)
	findings = append(findings, checkPathExposure(ctx, "/actuator", "/actuator 디버그 엔드포인트 노출", checks.CategoryInfrastructure)...)
	findings = append(findings, checkPathExposure(ctx, "/debug", "/debug 디버그 엔드포인트 노출", checks.CategoryInfrastructure)...)

	// K. 클라이언트(브라우저) 보안
	if ctx.Response != nil && ctx.Response.StatusCode == http.StatusOK {
		contentType := ctx.Response.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") {
			bodyBytes, err := engine.DecodeResponseBody(ctx.Response)
			if err == nil {
				bodyString := string(bodyBytes)
				findings = append(findings, checkMixedContent(ctx, bodyString)...)
				findings = append(findings, checkIframeSandbox(ctx, bodyString)...)
				findings = append(findings, checkInlineScripts(ctx, bodyString)...) // Added inline scripts check
			}
		}
	}

	return findings, nil
}

// checkPathExposure attempts to fetch a specific path and reports if it's accessible.
func checkPathExposure(ctx *checks.Context, path, title string, category checks.Category) []report.Finding {
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
		findings = append(findings, report.Finding{
			ID:       strings.ReplaceAll(strings.ToUpper(path), "/", "_") + "_EXPOSED",
			Category: string(category),
			Severity: report.SeverityMedium,
			Title:    title,
			Message:  fmt.Sprintf("민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.", path),
			Fix:      "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
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
func checkMixedContent(ctx *checks.Context, body string) []report.Finding {
	var findings []report.Finding

	// Only relevant for HTTPS pages
	if ctx.FinalURL.Scheme != "https" {
		return findings
	}

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
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
							findings = append(findings, report.Finding{
								ID:       "MIXED_CONTENT_DETECTED",
								Category: string(checks.CategoryClientSecurity),
								Severity: report.SeverityMedium,
								Title:    "Mixed Content 감지",
								Message:  fmt.Sprintf("HTTPS 페이지에서 안전하지 않은 HTTP 리소스 '%s'를 로드합니다.", a.Val),
								Fix:      "모든 리소스를 HTTPS로 로드하도록 변경하거나 상대 경로를 사용하십시오.",
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
func checkIframeSandbox(ctx *checks.Context, body string) []report.Finding {
	var findings []report.Finding

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return findings
	}

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
				findings = append(findings, report.Finding{
					ID:       "IFRAME_SANDBOX_MISSING",
					Category: string(checks.CategoryClientSecurity),
					Severity: report.SeverityMedium,
					Title:    "Iframe Sandbox 속성 미사용",
					Message:  fmt.Sprintf("<iframe> 태그에 sandbox 속성이 없어 잠재적인 클릭재킹 또는 스크립트 실행 위험이 있습니다. (src: %s)", src),
					Fix:      "모든 <iframe> 태그에 sandbox 속성을 추가하여 포함된 콘텐츠의 권한을 제한하십시오.",
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
func checkInlineScripts(ctx *checks.Context, body string) []report.Finding {
	var findings []report.Finding

	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return findings
	}

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
					findings = append(findings, report.Finding{
						ID:       "INLINE_SCRIPT_DETECTED",
						Category: string(checks.CategoryClientSecurity),
						Severity: report.SeverityMedium,
						Title:    "인라인 스크립트 사용 감지",
						Message:  "Content-Security-Policy(CSP)가 없거나 약하여 인라인 스크립트가 허용됩니다. 이는 XSS 공격 위험을 증가시킬 수 있습니다.",
						Fix:      "모든 인라인 스크립트를 외부 파일로 분리하고, 엄격한 Content-Security-Policy (예: 'nonce' 또는 'hash' 사용, 'unsafe-inline' 제거)를 적용하십시오.",
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
