package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/ui"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/checks/registry"       // Added for DefaultChecks()
	"github.com/MOYARU/PRS-project/internal/report"
)

// printFindings prints the scan findings to the console with color coding.
func PrintFindings(findings []report.Finding) {
	if len(findings) == 0 {
		fmt.Printf("%s✔ No issues found%s\n", ui.ColorGreen, ui.ColorReset)
		return
	}

	fmt.Printf("\n%s--- Findings ---%s\n", ui.ColorWhite, ui.ColorReset)
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

		fmt.Printf("\n%s[%s] (%s) %s%s\n", severityColor, f.Severity, f.Category, f.Title, ui.ColorReset)
		fmt.Printf("%s → %s%s\n", ui.ColorGray, f.Message, ui.ColorReset)
		fmt.Printf("%s → Fix: %s%s\n", ui.ColorGray, f.Fix, ui.ColorReset)
		if f.Confidence != "" { // Only print confidence if it's set
			fmt.Printf("%s → Confidence: %s%s\n", ui.ColorGray, f.Confidence, ui.ColorReset)
		}
	}
}

// SaveJSONReport saves the scan results to a JSON file, including metadata and scope.
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

	fmt.Printf("\n 💾 JSON 리포트가 저장되었습니다: %s\n", filename)
	return nil
}

// PrintScanSummary prints a summary of all performed checks,
// indicating whether issues were found or not.
func PrintScanSummary(performedChecks map[string]bool, allFindings []report.Finding) {
	fmt.Printf("\n%s--- Scan Summary ---%s\n", ui.ColorWhite, ui.ColorReset)

	// Build a map of findings by check ID for quick lookup
	findingsByCheckID := make(map[string]bool)
	for _, f := range allFindings {
		findingsByCheckID[f.ID] = true
	}

	for _, check := range registry.DefaultChecks() {
		_, wasPerformed := performedChecks[check.ID]

		if wasPerformed || check.Mode == ctxpkg.Passive {
			var status string
			var color string
			if findingsByCheckID[check.ID] {
				status = "발견됨"
				color = ui.ColorRed
			} else {
				status = "발견되지 않았습니다"
				color = ui.ColorGreen
			}
			fmt.Printf(" [%s] %s%s %s\n", status, color, check.Title, ui.ColorReset)
		} else if check.Mode == ctxpkg.Active {
			fmt.Printf(" [%s] %s%s %s\n", "Active 모드 필요", ui.ColorGray, check.Title, ui.ColorReset)
		}
	}
}
