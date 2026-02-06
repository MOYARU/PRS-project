package output

import (
	"encoding/json"
	"fmt"
	"os"
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
		msg := msges.GetMessage(f.ID)
		title := f.Title
		message := f.Message
		fix := f.Fix
		if msg.Title != "Message Not Found" {
			title = msg.Title
			message = msg.Message
			fix = msg.Fix
		}

		fmt.Printf("\n%s[%s] (%s) %s%s\n", severityColor, f.Severity, f.Category, title, ui.ColorReset)
		fmt.Printf("%s → %s%s\n", ui.ColorGray, message, ui.ColorReset)
		fmt.Printf("%s → %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleFixLabel"), fix, ui.ColorReset)
		if f.Confidence != "" { // Only print confidence if it's provided
			fmt.Printf("%s → %s: %s%s\n", ui.ColorGray, msges.GetUIMessage("ConsoleConfidenceLabel"), f.Confidence, ui.ColorReset)
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
func PrintScanSummary(performedChecks map[string]bool, allFindings []report.Finding) {
	fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ConsoleScanSummaryTitle"), ui.ColorReset)

	findingsByCheckID := make(map[string]bool)
	for _, f := range allFindings {
		findingsByCheckID[f.ID] = true
	}

	for _, check := range registry.DefaultChecks() {
		wasPerformed := performedChecks[check.ID]
		checkTitle := check.Title
		msg := msges.GetMessage(check.ID)
		if msg.Title != "Message Not Found" {
			checkTitle = msg.Title
		}

		var status, color string
		found := findingsByCheckID[check.ID]

		if found {
			status = msges.GetUIMessage("CheckStatusFound")
			color = ui.ColorRed
		} else {
			status = msges.GetUIMessage("CheckStatusNotFound")
			color = ui.ColorGreen
		}

		if !wasPerformed {
			if check.Mode == ctxpkg.Active {
				status = msges.GetUIMessage("ConsoleActiveModeRequired")
			} else {
				status = msges.GetUIMessage("ConsoleSkipped")
			}
			color = ui.ColorGray
		}

		fmt.Printf(" [%s] %s%s%s\n", status, color, checkTitle, ui.ColorReset)
	}
}
