package scanner

import (
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

func (s *Scanner) Run() ([]report.Finding, map[string]bool, error) {
	// Use the scanner's client for the initial fetch
	resp, err := s.client.Do(s.baseURL)
	if err != nil {
		return nil, nil, err
	}

	// Read the response body once and store it in ctx.BodyBytes
	// so that multiple checks can access it without re-reading from the io.ReadCloser.
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

	ctx := &ctxpkg.Context{
		Target:            s.Target,
		Mode:              s.Mode,
		InitialURL:        initialURL,
		FinalURL:          finalURL,
		Response:          resp,
		BodyBytes:         bodyBytes, // Populated BodyBytes
		RedirectTarget:    redirectTarget,
		Redirected:        redirected,
		RedirectedToHTTPS: redirectedToHTTPS,
		HTTPClient:        s.client, // Pass the shared client to all checks
	}

	var findings []report.Finding
	seen := make(map[string]bool)
	performedChecks := make(map[string]bool) // To store if a check was performed and found issues

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 5) // 최대 5개의 점검을 동시에 수행

	// Filter checks to run based on mode to calculate total count
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
		wg.Add(1)
		go func(c checks.Check) {
			defer wg.Done()
			sem <- struct{}{} // 세마포어 획득
			results, err := c.Run(ctx)
			<-sem // 세마포어 반납

			mu.Lock()
			defer mu.Unlock()

			// 진행률 업데이트
			completedChecks++
			percent := float64(completedChecks) / float64(totalChecks) * 100
			filled := int(float64(barWidth) * percent / 100)
			bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
			fmt.Printf("\r [%s] %3.0f%% | 검사 중: %s\033[K", bar, percent, c.Title)

			if err != nil {
				// 병렬 처리 중 에러 발생 시 로그만 남기고 계속 진행 (전체 중단 방지)
				return
			}

			if len(results) > 0 {
				performedChecks[c.ID] = true
			} else {
				performedChecks[c.ID] = false
			}

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
	fmt.Printf("\r [%s] 100%% | 검사 완료!             \n", strings.Repeat("█", barWidth))

	s.printSummary(findings)

	return findings, performedChecks, nil
}

func (s *Scanner) printSummary(findings []report.Finding) {
	counts := make(map[report.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Println("\n" + strings.Repeat("=", 45))
	fmt.Println("취약점 스캔 요약 리포트")
	fmt.Println(strings.Repeat("=", 45))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, " 심각도 (Severity)\t 발견 수 (Count)\t")
	fmt.Fprintln(w, " -----------------\t ---------------\t")

	// Define order of severity for display
	order := []report.Severity{report.SeverityHigh, report.SeverityMedium, report.SeverityLow, report.SeverityInfo}

	total := 0
	for _, sev := range order {
		count := counts[sev]
		total += count
		fmt.Fprintf(w, " %v\t %d\t\n", sev, count)
	}
	fmt.Fprintln(w, " -----------------\t ---------------\t")
	fmt.Fprintf(w, " 합계 (Total)\t %d\t\n", total)
	w.Flush()
	fmt.Println(strings.Repeat("=", 45))
	fmt.Println()
}

// delayedTransport applies a delay before each request.
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
