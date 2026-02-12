package ssrf

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

var internalTargets = []struct {
	Port      int
	Signature string
	Service   string
}{
	{22, "SSH-2.0", "SSH"},
	{3306, "mysql", "MySQL"},
	{6379, "redis", "Redis"},
	{8080, "Apache Tomcat", "Tomcat"},
}

func CheckSSRF(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding
	if ctx.Mode != ctxpkg.Active {
		return findings, nil
	}

	callbackURL := "http://example.com"
	expectedContent := "Example Domain"

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()
	if len(queryParams) == 0 {
		return findings, nil
	}

	client := engine.NewHTTPClient(false, nil)

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

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := engine.DecodeResponseBody(resp)
		bodyString := string(bodyBytes)

		if strings.Contains(bodyString, expectedContent) {
			msg := msges.GetMessage("SSRF_CALLBACK_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "SSRF_CALLBACK_DETECTED",
				Category:                   string(checks.CategorySSRF),
				Severity:                   report.SeverityHigh,
				Confidence:                 report.ConfidenceHigh,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, param),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
		resp.Body.Close()

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

			respLocal, err := client.Do(reqLocal)
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
					Fix:                        msg.Fix,
					IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
				})
			}
		}
	}

	return findings, nil
}
