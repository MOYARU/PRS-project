package scan

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/output"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/checks/scanner"
	"github.com/MOYARU/PRS-project/internal/crawler" // New import
	"github.com/MOYARU/PRS-project/internal/report"
)

// runScan orchestrates the scanning process.
func RunScan(target string, activeScan bool, crawl bool, depth int, jsonOutput bool, htmlOutput bool, delay int) error {
	// Active scan safety check
	if activeScan {
		fmt.Printf("\n%s[!] WARNING: Active Scan mode can send potentially harmful requests.%s\n", ui.ColorRed, ui.ColorReset)
		fmt.Printf("%s    This tool is intended for assets you own or have explicit permission to test.%s\n", ui.ColorYellow, ui.ColorReset)
		fmt.Printf("%s    Do you want to proceed with the active scan? (y/N): %s", ui.ColorYellow, ui.ColorReset)

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input != "y" {
			fmt.Printf("\n%sActive scan aborted by user.%s\n", ui.ColorYellow, ui.ColorReset)
			return fmt.Errorf("active scan aborted by user")
		}
	}

	fmt.Printf("%sTarget: %s%s\n", ui.ColorWhite, target, ui.ColorReset)

	if activeScan {
		fmt.Printf("%sMode: Active%s\n", ui.ColorWhite, ui.ColorReset)
	} else {
		fmt.Printf("%sMode: Passive%s\n", ui.ColorWhite, ui.ColorReset)
	}

	fmt.Printf("%sStatus: Ready to scan%s\n", ui.ColorGray, ui.ColorReset)

	mode := ctxpkg.Passive
	if activeScan {
		mode = ctxpkg.Active
	}

	delayDuration := time.Duration(delay) * time.Millisecond

	var targets []string
	if crawl {
		c, err := crawler.New(target, depth, delayDuration)
		if err != nil {
			return fmt.Errorf("failed to initialize crawler: %w", err)
		}
		targets = c.Start()
		fmt.Printf("%s✔ 크롤링 완료: 총 %d개의 페이지 발견%s\n", ui.ColorGreen, len(targets), ui.ColorReset)
	} else {
		targets = []string{target}
	}

	// Display Crawled Scope
	if len(targets) > 1 {
		fmt.Printf("\n%s--- 탐색된 범위 (Crawled Scope) ---%s\n", ui.ColorWhite, ui.ColorReset)
		for _, t := range targets {
			fmt.Printf(" - %s\n", t)
		}
		fmt.Println()
	}

	var allFindings []report.Finding
	allPerformedChecks := make(map[string]bool)
	startTime := time.Now()

	for i, t := range targets {
		fmt.Printf("\n%s[%d/%d] Scanning: %s%s\n", ui.ColorWhite, i+1, len(targets), t, ui.ColorReset)
		scn, err := scanner.New(t, mode, delayDuration)
		if err != nil {
			fmt.Printf("%s⚠️ Failed to initialize scanner for %s: %v%s\n", ui.ColorRed, t, err, ui.ColorReset)
			continue
		}
		findings, performedChecks, err := scn.Run()
		if err != nil {
			fmt.Printf("%s⚠️ Failed to scan %s: %v%s\n", ui.ColorRed, t, err, ui.ColorReset)
			continue
		}
		allFindings = append(allFindings, findings...)

		// Merge performed checks logic to accumulate results across multiple targets
		for id, found := range performedChecks {
			if found {
				allPerformedChecks[id] = true
			} else if _, exists := allPerformedChecks[id]; !exists {
				allPerformedChecks[id] = false
			}
		}
	}

	endTime := time.Now()
	fmt.Printf("\n%s✔ All Scans completed%s\n", ui.ColorGreen, ui.ColorReset)

	output.PrintFindings(allFindings)
	output.PrintScanSummary(allPerformedChecks, allFindings)

	if jsonOutput {
		if err := output.SaveJSONReport(target, targets, allFindings, startTime, endTime); err != nil {
			fmt.Printf("❌ Failed to save JSON report: %v\n", err)
		}
	}

	if htmlOutput {
		if err := output.SaveHTMLReport(target, targets, allFindings, startTime, endTime); err != nil {
			fmt.Printf("❌ Failed to save HTML report: %v\n", err)
		}
	}
	return nil
}
