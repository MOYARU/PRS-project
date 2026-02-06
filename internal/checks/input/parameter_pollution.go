package input

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

// CheckParameterPollution checks for Parameter Pollution vulnerabilities.
func CheckParameterPollution(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	if ctx.Mode == ctxpkg.Passive {
		return findings, nil
	}

	u, _ := url.Parse(ctx.FinalURL.String())
	queryParams := u.Query()

	if len(queryParams) == 0 {
		return findings, nil
	}

	client := engine.NewHTTPClient(false, nil)

	for param, values := range queryParams {
		if len(values) == 0 {
			continue
		}

		// Construct URL with duplicated parameter
		// ?param=value&param=polluted
		newParams := url.Values{}
		for k, v := range queryParams {
			newParams[k] = v
		}
		newParams.Add(param, "polluted_value")

		u.RawQuery = newParams.Encode()
		req, err := http.NewRequest("GET", u.String(), nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		bodyBytes, _ := engine.DecodeResponseBody(resp)
		if strings.Contains(string(bodyBytes), "polluted_value") {
			msg := msges.GetMessage("PARAMETER_POLLUTION_DETECTED")
			findings = append(findings, report.Finding{
				ID:                         "PARAMETER_POLLUTION_DETECTED",
				Category:                   string(checks.CategoryInputHandling),
				Severity:                   report.SeverityMedium,
				Confidence:                 report.ConfidenceMedium,
				Title:                      msg.Title,
				Message:                    fmt.Sprintf(msg.Message, param),
				Fix:                        msg.Fix,
				IsPotentiallyFalsePositive: msg.IsPotentiallyFalsePositive,
			})
		}
	}

	return findings, nil
}
