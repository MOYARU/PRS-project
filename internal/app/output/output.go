package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/ui"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/checks/registry"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

// printFindings prints the scan findings to the console with appropriate formatting and colors.
func PrintFindings(findings []report.Finding) {
	if len(findings) == 0 {
		fmt.Printf("%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("ConsoleNoIssues"), ui.ColorReset)
		return
	}

	// Sort findings by severity (High -> Medium -> Low -> Info)
	sort.Slice(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
	})

	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleFindingsTitle"), ui.ColorReset)
	for _, f := range findings {
		var severityColor string
		switch f.Severity {
		case "INFO":
			severityColor = ui.ColorInfo
		case "LOW":
			severityColor = ui.ColorLow
		case "MEDIUM":
			severityColor = ui.ColorMedium
		case "HIGH":
			severityColor = ui.ColorHigh
		default:
			severityColor = ui.ColorWhite // 기본 색상
		}

		// Localize finding details
		var affectedURLs string
		title, message, fix := f.Title, f.Message, f.Fix

		if strings.Contains(message, "\n\nPRS_AFFECTED_URLS_SEPARATOR\n") {
			parts := strings.SplitN(message, "\n\nPRS_AFFECTED_URLS_SEPARATOR\n", 2)
			message = parts[0]
			affectedURLs = parts[1]
		}

		fmt.Printf("\n%s[%s] (%s) %s%s\n", severityColor, f.Severity, f.Category, title, ui.ColorReset)
		fmt.Printf("%s → %s%s\n", ui.ColorGray, message, ui.ColorReset)
		fmt.Printf("%s → %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleFixLabel"), fix, ui.ColorReset)
		if f.Confidence != "" { // Only print confidence if it's provided
			fmt.Printf("%s → %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleConfidenceLabel"), f.Confidence, ui.ColorReset)
		}
		if affectedURLs != "" {
			fmt.Printf("%s → Affected URLs:%s\n", ui.ColorGray, ui.ColorReset)
			for _, u := range strings.Split(affectedURLs, "\n") {
				fmt.Printf("%s   - %s%s\n", ui.ColorGray, u, ui.ColorReset)
			}
		}
	}
}

// 이거 없애야 하나
func SaveJSONReport(target string, scannedURLs []string, findings []report.Finding, startTime, endTime time.Time) error {
	type JSONReport struct {
		Target      string           `json:"target"`
		ScannedURLs []string         `json:"scanned_urls"`
		StartTime   time.Time        `json:"start_time"`
		EndTime     time.Time        `json:"end_time"`
		Findings    []report.Finding `json:"findings"`
	}

	reportData := JSONReport{
		Target:      target,
		ScannedURLs: scannedURLs,
		StartTime:   startTime,
		EndTime:     endTime,
		Findings:    findings,
	}

	timestamp := time.Now().Format("20060102_150405")
	sanitizedTarget := strings.ReplaceAll(target, "://", "_")
	sanitizedTarget = strings.ReplaceAll(sanitizedTarget, "/", "_")
	sanitizedTarget = strings.ReplaceAll(sanitizedTarget, ":", "_")

	filename := fmt.Sprintf("prs_report_%s_%s.json", sanitizedTarget, timestamp)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(reportData); err != nil {
		return err
	}

	fmt.Printf("\n%s\n", msges.GetUIMessage("JSONReportSaved", filename))
	return nil
}

// PrintScanSummary prints a summary of all performed checks
func PrintScanSummary(checkCounts map[string]int, checksRan map[string]bool, findingsByCheck map[string][]report.Finding) {
	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleScanSummaryTitle"), ui.ColorReset)

	for _, check := range registry.DefaultChecks() {
		ran := checksRan[check.ID]
		count := checkCounts[check.ID]

		checkTitle := check.Title
		msg := msges.GetMessage(check.ID)
		if msg.Title != "Message Not Found" {
			checkTitle = msg.Title
		}

		var status, color string

		if !ran {
			if check.Mode == ctxpkg.Active {
				status = msges.GetUIMessage("ConsoleActiveModeRequired")
			} else {
				status = msges.GetUIMessage("ConsoleSkipped")
			}
			color = ui.ColorGray
		} else if count > 0 {
			status = msges.GetUIMessage("CheckStatusFound")
			color = ui.ColorRed
		} else {
			status = msges.GetUIMessage("CheckStatusNotFound")
			color = ui.ColorGreen
		}

		fmt.Printf(" [%s] %s%s%s\n", status, color, checkTitle, ui.ColorReset)

		if count > 0 {
			findings := findingsByCheck[check.ID]
			for i, f := range findings {
				connector := " 	├──"
				if i == len(findings)-1 {
					connector = " 	└──"
				}

				sevColor := ui.ColorWhite
				switch f.Severity {
				case report.SeverityHigh:
					sevColor = ui.ColorHigh
				case report.SeverityMedium:
					sevColor = ui.ColorMedium
				case report.SeverityLow:
					sevColor = ui.ColorLow
				case report.SeverityInfo:
					sevColor = ui.ColorInfo
				}

				fmt.Printf("%s %s[%s] %s%s\n", connector, sevColor, f.Severity, f.Title, ui.ColorReset)
			}
		}
	}
}

func severityWeight(s report.Severity) int {
	switch s {
	case report.SeverityHigh:
		return 3
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 1
	case report.SeverityInfo:
		return 0
	default:
		return -1
	}
}
