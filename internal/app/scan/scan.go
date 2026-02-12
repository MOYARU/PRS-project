package scan

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/output"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/checks/scanner"
	"github.com/MOYARU/PRS-project/internal/crawler"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

func RunScan(target string, activeScan bool, crawl bool, depth int, jsonOutput bool, htmlOutput bool, delay int) error {
	// Normalize target URL: Add http:// scheme if missing (supports IP addresses and domains)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)
	go func() {
		select {
		case <-c:
			fmt.Println(ui.ColorYellow + msges.GetUIMessage("ScanCancelled") + ui.ColorReset)
			cancel()
		case <-ctx.Done():
		}
	}()

	// Active scan safety check
	if activeScan {
		fmt.Printf("\n%s%s%s\n", ui.ColorRed, msges.GetUIMessage("ActiveScanWarning"), ui.ColorReset)
		fmt.Printf("%s%s%s\n", ui.ColorYellow, msges.GetUIMessage("ActiveScanPermission"), ui.ColorReset)

		prompt := fmt.Sprintf("%s%s%s", ui.ColorYellow, msges.GetUIMessage("ActiveScanPrompt"), ui.ColorReset)
		confirmed, err := ui.Confirm(prompt)
		if err != nil || !confirmed {
			fmt.Printf("\n%s%s%s\n", ui.ColorYellow, msges.GetUIMessage("ActiveScanAborted"), ui.ColorReset)
			return fmt.Errorf("active scan aborted by user")
		}
	}

	fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("Target", target), ui.ColorReset)

	if activeScan {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ModeActive"), ui.ColorReset)
	} else {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ModePassive"), ui.ColorReset)
	}

	fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("StatusReady"), ui.ColorReset)

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
		targets = c.Start(ctx) // Pass context
		fmt.Printf("%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("CrawlingComplete", len(targets)), ui.ColorReset)
	} else {
		targets = []string{target}
	}

	// Check if cancelled during crawl
	if ctx.Err() != nil {
		return nil
	}

	// Display Crawled Scope
	if len(targets) > 1 {
		fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("CrawledScope"), ui.ColorReset)
		for _, t := range targets {
			fmt.Printf(" - %s\n", t)
		}
		fmt.Println()
	}

	var allFindings []report.Finding
	// Track unique findings per check to calculate counts correctly
	checkUniqueFindings := make(map[string]map[string]bool) // CheckID -> Set of (ID|Message)
	checksRan := make(map[string]bool)

	startTime := time.Now()

	type findingKey struct {
		ID      string
		Message string
	}
	type findingInfo struct {
		Finding report.Finding
		URLs    []string
		CheckID string
	}
	aggregatedFindings := make(map[findingKey]*findingInfo)
	var findingKeys []findingKey

	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		fmt.Printf("\n%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("ScanningProgress", i+1, len(targets), t), ui.ColorReset)
		scn, err := scanner.New(t, mode, delayDuration)
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("ScannerInitFailed", t, err), ui.ColorReset)
			continue
		}
		resultsByCheck, err := scn.Run(ctx) // Pass context
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("ScanFailed", t, err), ui.ColorReset)
			continue
		}

		for checkID, findings := range resultsByCheck {
			checksRan[checkID] = true
			if checkUniqueFindings[checkID] == nil {
				checkUniqueFindings[checkID] = make(map[string]bool)
			}

			for _, f := range findings {
				// Global aggregation
				k := findingKey{ID: f.ID, Message: f.Message}
				if _, exists := aggregatedFindings[k]; !exists {
					aggregatedFindings[k] = &findingInfo{Finding: f, URLs: []string{}, CheckID: checkID}
					findingKeys = append(findingKeys, k)
				}
				aggregatedFindings[k].URLs = append(aggregatedFindings[k].URLs, t)

				// Per-check unique counting
				uniqueKey := f.ID + "|" + f.Message
				checkUniqueFindings[checkID][uniqueKey] = true
			}
		}
	}

	findingsByCheck := make(map[string][]report.Finding)
	for _, k := range findingKeys {
		info := aggregatedFindings[k]
		f := info.Finding

		uniqueURLs := make([]string, 0, len(info.URLs))
		seenURLs := make(map[string]bool)
		for _, u := range info.URLs {
			if !seenURLs[u] {
				seenURLs[u] = true
				uniqueURLs = append(uniqueURLs, u)
			}
		}

		if len(uniqueURLs) > 0 {
			f.Message += "\n\nPRS_AFFECTED_URLS_SEPARATOR\n" + strings.Join(uniqueURLs, "\n")
		}
		allFindings = append(allFindings, f)
		if info.CheckID != "" {
			findingsByCheck[info.CheckID] = append(findingsByCheck[info.CheckID], f)
		}
	}

	endTime := time.Now()
	fmt.Printf("\n%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("AllScansCompleted"), ui.ColorReset)

	// Calculate final counts per check
	checkCounts := make(map[string]int)
	for id, uniqueSet := range checkUniqueFindings {
		checkCounts[id] = len(uniqueSet)
	}

	output.PrintFindings(allFindings)
	output.PrintScanSummary(checkCounts, checksRan, findingsByCheck)

	if jsonOutput {
		if err := output.SaveJSONReport(target, targets, allFindings, startTime, endTime); err != nil {
			fmt.Printf("[Error] %s\n", msges.GetUIMessage("JSONReportFailed", err))
		}
	}

	if htmlOutput {
		if err := output.SaveHTMLReport(target, targets, allFindings, startTime, endTime); err != nil {
			fmt.Printf("%s\n", msges.GetUIMessage("HTMLReportFailed", err))
		}
	}
	return nil
}
