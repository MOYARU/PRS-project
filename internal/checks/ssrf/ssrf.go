package ssrf

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/crawler"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

var ssrfPayloads = []string{
	"http://localhost",
	"http://127.0.0.1",
	"http://[::1]",
	"http://0.0.0.0",
	"%68%74%74%70%3A%2F%2F127.0.0.1", // URL Encoded http://127.0.0.1
}

var internalTargets = []struct {
	Port      int
	Signature string
	Service   string
}{
	{22, "SSH-2.0", "SSH"},
	{80, "HTTP/1.1", "Web"},
	{3306, "mysql", "MySQL"},
	{5432, "postgres", "PostgreSQL"},
	{6379, "redis", "Redis"},
	{8080, "Apache Tomcat", "Tomcat"},
}

func isExampleDomainResponse(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "<h1>example domain</h1>") &&
		(strings.Contains(l, "iana.org/domains/example") || strings.Contains(l, "this domain is for use in documentation"))
}

func CheckSSRF(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	callbackURL := "http://example.com"

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	// 1. GET Parameters
	if len(queryParams) > 0 {
		for param := range queryParams {
			// Check External SSRF
			newParams := url.Values{}
			for k, v := range queryParams {
				newParams[k] = v
			}
			newParams.Set(param, callbackURL)
			u.RawQuery = newParams.Encode()

			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}

			resp, err := ctx.HTTPClient.Do(req)
			if err != nil {
				continue
			}

			bodyBytes, _ := engine.DecodeResponseBody(resp)
			bodyString := string(bodyBytes)
			resp.Body.Close()

			if isExampleDomainResponse(bodyString) && !isExampleDomainResponse(string(ctx.BodyBytes)) {
				msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
				findings = append(findings, report.Finding{
					ID:                         "SSRF_CALLBACK_DETECTED",
					Category:                   string(checks.CategorySSRF),
					Severity:                   report.SeverityHigh,
					Confidence:                 report.ConfidenceHigh,
					Title:                      msg.Title,
					Message:                    fmt.Sprintf(msg.Message, param),
					Evidence:                   fmt.Sprintf("Response matched example.com markers when injecting '%s'", callbackURL),
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
			}

			// Check Internal Port Scan
			for _, target := range internalTargets {
				localURL := fmt.Sprintf("http://127.0.0.1:%d", target.Port)
				newParamsLocal := url.Values{}
				for k, v := range queryParams {
					newParamsLocal[k] = v
				}
				newParamsLocal.Set(param, localURL)
				u.RawQuery = newParamsLocal.Encode()

				reqLocal, err := http.NewRequest("GET", u.String(), nil)
				if err != nil {
					continue
				}

				respLocal, err := ctx.HTTPClient.Do(reqLocal)
				if err != nil {
					continue
				}
				bodyBytesLocal, _ := engine.DecodeResponseBody(respLocal)
				bodyStringLocal := string(bodyBytesLocal)
				respLocal.Body.Close()

				if strings.Contains(bodyStringLocal, target.Signature) {
					msg := msges.GetMessage("SSRF_LOCAL_ACCESS_DETECTED")
					findings = append(findings, report.Finding{
						ID:                         "SSRF_LOCAL_ACCESS_DETECTED",
						Category:                   string(checks.CategorySSRF),
						Severity:                   report.SeverityHigh,
						Confidence:                 report.ConfidenceHigh,
						Title:                      msg.Title,
						Message:                    fmt.Sprintf(msg.Message, param, target.Port, target.Service),
						Evidence:                   fmt.Sprintf("Response contained signature '%s' for port %d", target.Signature, target.Port),
						Fix:                        msg.Fix,
						IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
					})
				}
			}
		}
	}

	// 2. POST Forms
	if strings.Contains(ctx.Response.Header.Get("Content-Type"), "text/html") {
		doc, err := html.Parse(bytes.NewReader(ctx.BodyBytes))
		if err == nil {
			forms := crawler.ExtractForms(doc)
			for _, form := range forms {
				if strings.ToUpper(form.Method) != "POST" || len(form.Inputs) == 0 {
					continue
				}

				targetURL := ctx.FinalURL.String()
				if form.ActionURL != "" {
					if actionURL, err := url.Parse(form.ActionURL); err == nil {
						targetURL = ctx.FinalURL.ResolveReference(actionURL).String()
					}
				}

				for _, in := range form.Inputs {
					nameLower := strings.ToLower(in.Name)
					if !strings.Contains(nameLower, "url") && !strings.Contains(nameLower, "uri") &&
						!strings.Contains(nameLower, "link") && !strings.Contains(nameLower, "callback") {
						continue
					}

					formValues := url.Values{}
					for _, input := range form.Inputs {
						if input.Name == in.Name {
							formValues.Set(input.Name, callbackURL)
						} else {
							formValues.Set(input.Name, input.Value)
						}
					}

					req, err := http.NewRequest("POST", targetURL, strings.NewReader(formValues.Encode()))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

					resp, err := ctx.HTTPClient.Do(req)
					if err != nil {
						continue
					}
					bodyBytes, _ := engine.DecodeResponseBody(resp)
					resp.Body.Close()

					if isExampleDomainResponse(string(bodyBytes)) && !isExampleDomainResponse(string(ctx.BodyBytes)) {
						msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
						findings = append(findings, report.Finding{
							ID:                         "SSRF_CALLBACK_DETECTED",
							Category:                   string(checks.CategorySSRF),
							Severity:                   report.SeverityHigh,
							Confidence:                 report.ConfidenceMedium,
							Title:                      msg.Title,
							Message:                    fmt.Sprintf(msg.Message, in.Name+" (POST)"),
							Evidence:                   fmt.Sprintf("Response resembled example.com content after injecting '%s' into '%s'", callbackURL, in.Name),
							Fix:                        msg.Fix,
							IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
