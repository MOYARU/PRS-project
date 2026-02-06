package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/checks/registry"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

type Scanner struct {
	Target  string
	Mode    ctxpkg.ScanMode
	Checks  []checks.Check
	client  *http.Client
	baseURL *http.Request
}

func New(target string, mode ctxpkg.ScanMode, delay time.Duration) (*Scanner, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	client := engine.NewHTTPClient(false, nil)
	if delay > 0 {
		client.Transport = &delayedTransport{
			Transport: client.Transport,
			Delay:     delay,
		}
	}

	return &Scanner{
		Target:  target,
		Mode:    mode,
		Checks:  registry.DefaultChecks(),
		client:  client,
		baseURL: req,
	}, nil
}

func (s *Scanner) Run(ctx context.Context) ([]report.Finding, map[string]bool, error) {
	resp, err := s.client.Do(s.baseURL)
	if err != nil {
		return nil, nil, err
	}
	bodyBytes, err := engine.DecodeResponseBody(resp)
	if err != nil {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	defer resp.Body.Close() // Close the original response body after reading

	initialURL := s.baseURL.URL
	finalURL := resp.Request.URL
	redirected := initialURL.String() != finalURL.String()
	redirectedToHTTPS := initialURL.Scheme == "http" && finalURL.Scheme == "https"
	var redirectTarget *url.URL
	if redirected {
		redirectTarget = finalURL
	}

	scanCtx := &ctxpkg.Context{
		Target:            s.Target,
		Mode:              s.Mode,
		InitialURL:        initialURL,
		FinalURL:          finalURL,
		Response:          resp,
		BodyBytes:         bodyBytes,
		RedirectTarget:    redirectTarget,
		Redirected:        redirected,
		RedirectedToHTTPS: redirectedToHTTPS,
		HTTPClient:        s.client,
	}

	var findings []report.Finding
	seen := make(map[string]bool)
	performedChecks := make(map[string]bool)

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 5) // 최대 5개 동시 체크

	var checksToRun []checks.Check
	for _, check := range s.Checks {
		if s.Mode == ctxpkg.Passive && check.Mode == ctxpkg.Active {
			continue
		}
		checksToRun = append(checksToRun, check)
	}

	totalChecks := len(checksToRun)
	barWidth := 30
	completedChecks := 0

	for _, check := range checksToRun {
		select {
		case <-ctx.Done():
			return findings, performedChecks, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			select {
			case sem <- struct{}{}: // 세마포어 획득
				defer func() { <-sem }() // 세마포어 반납
			case <-ctx.Done():
				return
			}

			results, err := c.Run(scanCtx)

			mu.Lock()
			defer mu.Unlock()

			// 진행률 업데이트
			completedChecks++
			percent := float64(completedChecks) / float64(totalChecks) * 100
			filled := int(float64(barWidth) * percent / 100)
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

			checkTitle := c.Title
			if msg := msges.GetMessage(c.ID); msg.Title != "Message Not Found" {
				checkTitle = msg.Title
			}

			fmt.Printf("\r [%s] %3.0f%% | %s\033[K", bar, percent, msges.GetUIMessage("ScanningCheck", checkTitle))

			if err != nil {
				return
			}

			performedChecks[c.ID] = true

			for _, f := range results {
				if _, ok := seen[f.ID]; !ok {
					findings = append(findings, f)
					seen[f.ID] = true
				}
			}
		}(check)
	}
	wg.Wait()

	// Final 100% Bar
	fmt.Printf("\r [%s] 100%% | %s             \n", strings.Repeat("█", barWidth), msges.GetUIMessage("ScanCompleteMsg"))

	s.printSummary(findings)

	return findings, performedChecks, nil
}

func (s *Scanner) printSummary(findings []report.Finding) {
	counts := make(map[report.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Println("\n" + strings.Repeat("=", 45))
	fmt.Println(msges.GetUIMessage("SummaryReportTitle"))
	fmt.Println(strings.Repeat("=", 45))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, " "+msges.GetUIMessage("SummarySeverity")+"\t"+msges.GetUIMessage("SummaryCount")+"\t")
	fmt.Fprintln(w, " -----------------\t ---------------\t")
	order := []report.Severity{report.SeverityHigh, report.SeverityMedium, report.SeverityLow, report.SeverityInfo}

	total := 0
	for _, sev := range order {
		count := counts[sev]
		total += count
		fmt.Fprintf(w, " %v\t %d\t\n", sev, count)
	}
	fmt.Fprintln(w, " -----------------\t ---------------\t")
	fmt.Fprintf(w, " "+msges.GetUIMessage("SummaryTotal")+"\t %d\t\n", total)
	w.Flush()
	fmt.Println(strings.Repeat("=", 45))
	fmt.Println()
}

type delayedTransport struct {
	Transport http.RoundTripper
	Delay     time.Duration
}

func (t *delayedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Delay > 0 {
		time.Sleep(t.Delay)
	}
	if t.Transport == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.Transport.RoundTrip(req)
}
