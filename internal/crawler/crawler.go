package crawler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/ui"
	"github.com/MOYARU/PRS-project/internal/engine"
	"golang.org/x/net/html"
)

type Crawler struct {
	BaseURL  *url.URL
	MaxDepth int
	Visited  map[string]bool
	Results  []string
	Client   *http.Client
	mu       sync.Mutex
	sem      chan struct{}  // 동시성 제어를 위한 세마포어
	wg       sync.WaitGroup // 고루틴 대기를 위한 WaitGroup
}

func New(target string, depth int, delay time.Duration) (*Crawler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}

	// engine.NewHTTPClient가 delay를 지원하지 않을 수 있으므로
	// 클라이언트 생성 후 Transport를 래핑하여 딜레이를 적용합니다.
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
		sem:      make(chan struct{}, 10), // 최대 10개의 동시 요청 허용
	}, nil
}

func (c *Crawler) Start() []string {
	fmt.Printf("%s[*] 사이트 구조 크롤링 시작 (Max Depth: %d)...%s\n", ui.ColorInfo, c.MaxDepth, ui.ColorReset)
	c.wg.Add(1)
	go c.crawl(c.BaseURL.String(), 0)
	c.wg.Wait()
	fmt.Println() // 크롤링 완료 후 줄바꿈
	return c.Results
}

func (c *Crawler) crawl(targetURL string, depth int) {
	defer c.wg.Done()

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

	fmt.Print(".") // 진행 상황 시각화 (페이지 방문 시 점 출력)

	c.sem <- struct{}{}        // 세마포어 획득 (슬롯 차지)
	defer func() { <-c.sem }() // 함수 종료 시 반납

	// Fetch page
	resp, err := c.Client.Get(targetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Only parse HTML
	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return
	}

	links := c.extractLinks(resp.Body)
	for _, link := range links {
		absoluteURL := c.resolveURL(link)
		if absoluteURL != "" && c.isSameDomain(absoluteURL) {
			c.wg.Add(1)
			go c.crawl(absoluteURL, depth+1)
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

	// 동일 도메인이거나 서브도메인인 경우 허용 (예: sub.example.com -> example.com)
	return linkHost == baseHost || strings.HasSuffix(linkHost, "."+baseHost)
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
