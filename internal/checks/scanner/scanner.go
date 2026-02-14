package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	"github.com/MOYARU/PRS-project/internal/checks/registry"
	"github.com/MOYARU/PRS-project/internal/engine"
	"github.com/MOYARU/PRS-project/internal/report"
)

type Scanner struct {
	Target string
	Mode   ctxpkg.ScanMode
	Checks []checks.Check
	client *http.Client
}

func New(target string, mode ctxpkg.ScanMode, delay time.Duration, client *http.Client) (*Scanner, error) {
	if _, err := http.NewRequest("GET", target, nil); err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if client == nil {
		client = engine.NewHTTPClient(false, nil)
	}

	return &Scanner{
		Target: target,
		Mode:   mode,
		Checks: registry.DefaultChecks(),
		client: client,
	}, nil
}

// fix: Run 메서드에서 체크 실행 시 context 취소를 제대로 처리하도록 수정
func (s *Scanner) Run(ctx context.Context) (map[string][]report.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Target, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := engine.DecodeResponseBody(resp)
	if err != nil {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}
	defer resp.Body.Close() // Close the original response body after reading

	initialURL := req.URL
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

	return resultsByCheck, nil
}
