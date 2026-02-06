package scan

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	allPerformedChecks := make(map[string]bool)
	startTime := time.Now()

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
		findings, performedChecks, err := scn.Run(ctx) // Pass context
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("ScanFailed", t, err), ui.ColorReset)
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
	fmt.Printf("\n%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("AllScansCompleted"), ui.ColorReset)

	output.PrintFindings(allFindings)
	output.PrintScanSummary(allPerformedChecks, allFindings)

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
