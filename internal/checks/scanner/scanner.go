package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
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

func New(target string, mode ctxpkg.ScanMode, delay time.Duration, client *http.Client) (*Scanner, error) {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if client == nil {
		client = engine.NewHTTPClient(false, nil)
	}

	return &Scanner{
		Target:  target,
		Mode:    mode,
		Checks:  registry.DefaultChecks(),
		client:  client,
		baseURL: req,
	}, nil
}

func (s *Scanner) Run(ctx context.Context) (map[string][]report.Finding, error) {
	resp, err := s.client.Do(s.baseURL)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := engine.DecodeResponseBody(resp)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decode response body: %w", err)
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

	resultsByCheck := make(map[string][]report.Finding)

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

	for _, check := range checksToRun {
		select {
		case <-ctx.Done():
			return resultsByCheck, ctx.Err()
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

			if err != nil {
				return
			}

			resultsByCheck[c.ID] = results
		}(check)
	}
	wg.Wait()

	// Flatten findings for local summary (deduplicated)
	var allFindings []report.Finding
	seen := make(map[string]bool)
	for _, findings := range resultsByCheck {
		for _, f := range findings {
			key := f.ID + "|" + f.Message
			if !seen[key] {
				allFindings = append(allFindings, f)
				seen[key] = true
			}
		}
	}

	return resultsByCheck, nil
}
