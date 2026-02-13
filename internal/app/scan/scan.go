package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/output"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/checks/scanner"
	"github.com/MOYARU/PRS-project/internal/crawler"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

func RunScan(target string, activeScan bool, crawl bool, depth int, jsonOutput bool, htmlOutput bool, delay int) error {
	// Normalize target URL: Add http:// scheme if missing (supports IP addresses and domains)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		if isHTTPSReachable(target) {
			target = "https://" + target
		} else {
			target = "http://" + target
		}
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
		URLs    map[string]bool
		CheckID string
	}
	aggregatedFindings := make(map[findingKey]*findingInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Concurrency limit (e.g., 5 workers)
	sem := make(chan struct{}, 5)

	var scanErrors []string
	var completedCount int32
	output.PrintScanProgress(0, len(targets), "Ready", "")

	// Create a shared client for connection pooling
	sharedClient := engine.NewHTTPClient(false, nil)
	if delay > 0 {
		sharedClient.Transport = &engine.DelayedTransport{
			Transport: sharedClient.Transport,
			Delay:     delayDuration,
		}
	}

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Update progress bar on completion (defer to ensure it runs even on error)
			defer func() {
				newCount := atomic.AddInt32(&completedCount, 1)
				output.PrintScanProgress(int(newCount), len(targets), "Scanning", urlStr)
			}()

			if ctx.Err() != nil {
				return
			}

			scn, err := scanner.New(urlStr, mode, delayDuration, sharedClient)
			if err != nil {
				mu.Lock()
				scanErrors = append(scanErrors, msges.GetUIMessage("ScannerInitFailed", urlStr, err))
				mu.Unlock()
				return
			}
			resultsByCheck, err := scn.Run(ctx)
			if err != nil {
				mu.Lock()
				scanErrors = append(scanErrors, msges.GetUIMessage("ScanFailed", urlStr, err))
				mu.Unlock()
				return
			}

			mu.Lock()
			defer mu.Unlock()

			for checkID, findings := range resultsByCheck {
				checksRan[checkID] = true
				if checkUniqueFindings[checkID] == nil {
					checkUniqueFindings[checkID] = make(map[string]bool)
				}

				for _, f := range findings {
					// Global aggregation
					k := findingKey{ID: f.ID, Message: f.Message}
					if _, exists := aggregatedFindings[k]; !exists {
						aggregatedFindings[k] = &findingInfo{
							Finding: f,
							URLs:    make(map[string]bool),
							CheckID: checkID,
						}
					}
					aggregatedFindings[k].URLs[urlStr] = true

					// Per-check unique counting
					uniqueKey := f.ID + "|" + f.Message
					checkUniqueFindings[checkID][uniqueKey] = true
				}
			}
		}(i, t)
	}
	wg.Wait()

	findingsByCheck := make(map[string][]report.Finding)

	// Convert aggregated map to slice
	for _, info := range aggregatedFindings {
		f := info.Finding

		for u := range info.URLs {
			f.AffectedURLs = append(f.AffectedURLs, u)
		}

		allFindings = append(allFindings, f)
		if info.CheckID != "" {
			findingsByCheck[info.CheckID] = append(findingsByCheck[info.CheckID], f)
		}
	}

	endTime := time.Now()
	fmt.Printf("\n%s%s%s\n", ui.ColorGreen, msges.GetUIMessage("AllScansCompleted"), ui.ColorReset)

	// Print any scan errors that occurred
	if len(scanErrors) > 0 {
		fmt.Printf("\n%sErrors encountered during scan:%s\n", ui.ColorRed, ui.ColorReset)
		for _, errMsg := range scanErrors {
			fmt.Printf(" - %s\n", errMsg)
		}
	}

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

func isHTTPSReachable(target string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Head("https://" + target)
	if err != nil {
		resp, err = client.Get("https://" + target)
	}
	if err == nil {
		resp.Body.Close()
		return true
	}
	return false
}
