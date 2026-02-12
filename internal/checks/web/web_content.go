package web

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

var secretPatterns = []struct {
	Name  string
	Regex *regexp.Regexp
}{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Google/Firebase API Key", regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`)},
	{"Generic API Key", regexp.MustCompile(`(?i)(api_key|apikey|secret|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]`)},
	{"Supabase/JWT", regexp.MustCompile(`eyJh[a-zA-Z0-9._-]{20,}`)},
	{"Firebase Config", regexp.MustCompile(`apiKey\s*:\s*['"]([^'"]+)['"]`)},
}

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

		findings = append(findings, checkPathExposure(ctx, "/actuator", "ACTUATOR_ENDPOINT_EXPOSED", checks.CategoryInfrastructure)...)
		findings = append(findings, checkPathExposure(ctx, "/debug", "DEBUG_ENDPOINT_EXPOSED", checks.CategoryInfrastructure)...)

		// Backup files
		backupExtensions := []string{".bak", ".old", ".swp", "~"}
		path := ctx.FinalURL.Path
		if path != "" && path != "/" {
			for _, ext := range backupExtensions {
				findings = append(findings, checkPathExposure(ctx, path+ext, "BACKUP_FILE_EXPOSED", checks.CategoryFileExposure)...)
			}
		}
	}

	// K. 클라이언트(브라우저) 보안
	if ctx.Response != nil && ctx.Response.StatusCode == http.StatusOK {
		contentType := ctx.Response.Header.Get("Content-Type")
		bodyString := string(ctx.BodyBytes)

		if strings.Contains(contentType, "text/html") {
			// Parse HTML once and reuse the node tree
			doc, err := html.Parse(strings.NewReader(bodyString))
			if err == nil {
				findings = append(findings, checkMixedContent(ctx, doc)...)
				findings = append(findings, checkIframeSandbox(ctx, doc)...)
				findings = append(findings, checkInlineScripts(ctx, doc)...)
				findings = append(findings, checkSecrets(bodyString)...)
				findings = append(findings, checkConsoleUsage(bodyString)...)
			}
		} else if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "application/x-javascript") {
			findings = append(findings, checkSecrets(bodyString)...)
			findings = append(findings, checkConsoleUsage(bodyString)...)
		}
	}

	return findings, nil
}

func checkPathExposure(ctx *ctxpkg.Context, path string, msgID string, category checks.Category) []report.Finding {
	var findings []report.Finding
	targetURL := resolveRelativeURL(ctx.FinalURL, path)

	resp, err := engine.FetchWithTLSConfig(targetURL.String(), nil) // Use default client
	if err != nil {
		return findings
	}
	defer resp.Response.Body.Close()

	if resp.Response.StatusCode == http.StatusOK {
		msg := msges.GetMessage(msgID)
		findings = append(findings, report.Finding{
			ID:                         strings.ReplaceAll(strings.ToUpper(path), "/", "_") + "_EXPOSED",
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

func resolveRelativeURL(baseURL *url.URL, relativePath string) *url.URL {
	newURL, _ := url.Parse(relativePath)
	return baseURL.ResolveReference(newURL)
}

func checkMixedContent(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

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

func checkSecrets(content string) []report.Finding {
	var findings []report.Finding
	for _, pattern := range secretPatterns {
		if match := pattern.Regex.FindStringSubmatch(content); len(match) > 0 {
			foundValue := match[0]
			if len(foundValue) > 50 { // Truncate for display
				foundValue = foundValue[:47] + "..."
			}
			msg := msges.GetMessage("SENSITIVE_API_KEY_FOUND")
			findings = append(findings, report.Finding{
				ID:                         "SENSITIVE_API_KEY_FOUND",
				Category:                   string(checks.CategoryInformationLeakage),
				Severity:                   report.SeverityHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, pattern.Name, foundValue),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}
	return findings
}

func checkConsoleUsage(content string) []report.Finding {
	var findings []report.Finding
	if strings.Contains(content, "console.log") || strings.Contains(content, "console.debug") || strings.Contains(content, "console.error") {
		msg := msges.GetMessage("CONSOLE_LOG_EXPOSED")
		findings = append(findings, report.Finding{
			ID:                         "CONSOLE_LOG_EXPOSED",
			Category:                   string(checks.CategoryInformationLeakage),
			Severity:                   report.SeverityInfo,
			Title:                      msg.Title,
			Message:                    fmt.Sprintf(msg.Message, "console.* usage detected"),
			Fix:                        msg.Fix,
			IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
		})
	}
	return findings
}

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

func checkInlineScripts(ctx *ctxpkg.Context, doc *html.Node) []report.Finding {
	var findings []report.Finding

	cspHeader := ctx.Response.Header.Get("Content-Security-Policy")
	hasStrictCSP := false
	if cspHeader != "" {
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
			if isInline && strings.TrimSpace(n.FirstChild.Data) != "" {
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
