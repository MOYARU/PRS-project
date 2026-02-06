package crawler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/ui"
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"golang.org/x/net/html"
)

type Crawler struct {
	BaseURL  *url.URL
	MaxDepth int
	Visited  map[string]bool
	Results  []string
	Client   *http.Client
	mu       sync.Mutex
	sem      chan struct{}
	wg       sync.WaitGroup // 고루틴
}

func New(target string, depth int, delay time.Duration) (*Crawler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	client := engine.NewHTTPClient(false, nil)
	if delay > 0 {
		client.Transport = &delayedTransport{
			Transport: client.Transport,
			Delay:     delay,
		}
	}

	return &Crawler{
		BaseURL:  u,
		MaxDepth: depth,
		Visited:  make(map[string]bool),
		Results:  []string{},
		Client:   client,
		sem:      make(chan struct{}, 10), // 동시 요청 제한
	}, nil
}

func (c *Crawler) Start(ctx context.Context) []string {
	ctx, cancel := ui.WaitForCancel(ctx)
	defer cancel()

	fmt.Printf("%s%s%s\n", ui.ColorInfo, msges.GetUIMessage("CrawlerStart", c.MaxDepth), ui.ColorReset)
	c.wg.Add(1)
	go c.crawl(ctx, c.BaseURL.String(), 0)
	c.wg.Wait()
	fmt.Println() // 크롤링 완료 후 줄바꿈
	return c.Results
}

func (c *Crawler) crawl(ctx context.Context, targetURL string, depth int) {
	defer c.wg.Done()

	select {
	case <-ctx.Done():
		return
	default:
	}

	if depth > c.MaxDepth {
		return
	}

	// Normalize URL (remove fragment)
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	u.Fragment = ""
	targetURL = u.String()

	c.mu.Lock()
	if c.Visited[targetURL] {
		c.mu.Unlock()
		return
	}
	c.Visited[targetURL] = true
	c.Results = append(c.Results, targetURL)
	c.mu.Unlock()

	fmt.Print(".") // 진행 상황 시각화

	select {
	case c.sem <- struct{}{}: // 세마포어 획득
		defer func() { <-c.sem }() // 함수 종료 시 반납
	case <-ctx.Done():
		return
	}

	resp, err := c.Client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return
	}

	links := c.extractLinks(resp.Body)
	for _, link := range links {
		absoluteURL := c.resolveURL(link)
		if absoluteURL != "" && c.isSameDomain(absoluteURL) {
			c.wg.Add(1)
			go c.crawl(ctx, absoluteURL, depth+1)
		}
	}
}

func (c *Crawler) extractLinks(body io.Reader) []string {
	var links []string
	z := html.NewTokenizer(body)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			if t.Data == "a" {
				for _, a := range t.Attr {
					if a.Key == "href" {
						links = append(links, a.Val)
					}
				}
			} else if t.Data == "form" {
				for _, a := range t.Attr {
					if a.Key == "action" {
						links = append(links, a.Val)
					}
				}
			}
		}
	}
	return links
}

func (c *Crawler) resolveURL(ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return c.BaseURL.ResolveReference(u).String()
}

func (c *Crawler) isSameDomain(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}

	linkHost := strings.ToLower(u.Host)
	baseHost := strings.ToLower(c.BaseURL.Host)

	// 동일 도메인이거나 서브도메인인 경우 허용
	return linkHost == baseHost || strings.HasSuffix(linkHost, "."+baseHost)
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
