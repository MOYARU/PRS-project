package crawler

import (
	"context"
	"fmt"
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
	Forms    []Form
	Client   *http.Client
	mu       sync.Mutex
	sem      chan struct{}
	wg       sync.WaitGroup // 고루틴
}

type Form struct {
	ActionURL string
	Method    string
	Inputs    []FormInput
}

type FormInput struct {
	Name  string
	Type  string
	Value string
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
		Forms:    []Form{},
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

	// 리다이렉트 등으로 인해 최종 URL이 변경되었을 수 있으므로, 상대 경로 해석을 위해 URL 업데이트
	if resp.Request != nil && resp.Request.URL != nil {
		u = resp.Request.URL
	}

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return
	}

	links, forms, pageBase := c.extractData(doc)

	resolveBase := u
	if pageBase != nil {
		resolveBase = u.ResolveReference(pageBase)
	}

	c.mu.Lock()
	c.Forms = append(c.Forms, forms...)
	c.mu.Unlock()

	for _, link := range links {
		absoluteURL := c.resolveURL(resolveBase, link)
		if absoluteURL != "" && c.isSameDomain(absoluteURL) {
			c.wg.Add(1)
			go c.crawl(ctx, absoluteURL, depth+1)
		}
	}
}

func (c *Crawler) extractData(n *html.Node) ([]string, []Form, *url.URL) {
	var links []string
	var forms []Form
	var base *url.URL

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "base":
				if base == nil { // 첫 번째 base 태그만 유효
					for _, a := range n.Attr {
						if a.Key == "href" {
							if parsedBase, err := url.Parse(a.Val); err == nil {
								base = parsedBase
							}
						}
					}
				}
			case "a", "area", "link":
				for _, a := range n.Attr {
					if a.Key == "href" {
						links = append(links, a.Val)
					}
				}
			case "script", "iframe", "frame", "img", "embed", "source", "track":
				for _, a := range n.Attr {
					if a.Key == "src" {
						links = append(links, a.Val)
					}
				}
			case "object":
				for _, a := range n.Attr {
					if a.Key == "data" {
						links = append(links, a.Val)
					}
				}
			case "form":
				form := Form{Method: "GET"}
				for _, a := range n.Attr {
					if a.Key == "action" {
						form.ActionURL = a.Val
						links = append(links, a.Val)
					}
					if a.Key == "method" {
						form.Method = strings.ToUpper(a.Val)
					}
				}
				form.Inputs = ExtractInputs(n)
				forms = append(forms, form)
			case "meta":
				var httpEquiv, content string
				for _, a := range n.Attr {
					k := strings.ToLower(a.Key)
					if k == "http-equiv" {
						httpEquiv = strings.ToLower(a.Val)
					} else if k == "content" {
						content = a.Val
					}
				}
				if httpEquiv == "refresh" {
					if idx := strings.Index(strings.ToLower(content), "url="); idx != -1 {
						urlPart := content[idx+4:]
						urlPart = strings.Trim(urlPart, "'\" ")
						links = append(links, urlPart)
					}
				}
			case "button", "input":
				for _, a := range n.Attr {
					if a.Key == "formaction" {
						links = append(links, a.Val)
					}
				}
			}

			// Check for onclick navigation (simple heuristic)
			for _, a := range n.Attr {
				if a.Key == "onclick" {
					val := a.Val
					if strings.Contains(val, "location") || strings.Contains(val, "open") {
						// Extract potential URL inside quotes
						for _, quote := range []string{"'", "\""} {
							start := strings.Index(val, quote)
							if start != -1 {
								end := strings.Index(val[start+1:], quote)
								if end != -1 {
									links = append(links, val[start+1:start+1+end])
								}
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return links, forms, base
}

func ExtractForms(n *html.Node) []Form {
	var forms []Form
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := Form{Method: "GET"}
			for _, a := range n.Attr {
				if a.Key == "action" {
					form.ActionURL = a.Val
				}
				if a.Key == "method" {
					form.Method = strings.ToUpper(a.Val)
				}
			}
			form.Inputs = ExtractInputs(n)
			forms = append(forms, form)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return forms
}

func ExtractInputs(n *html.Node) []FormInput {
	var inputs []FormInput
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.Data == "input" {
				input := FormInput{Type: "text"}
				for _, a := range n.Attr {
					if a.Key == "name" {
						input.Name = a.Val
					}
					if a.Key == "type" {
						input.Type = a.Val
					}
					if a.Key == "value" {
						input.Value = a.Val
					}
				}
				if input.Name != "" {
					inputs = append(inputs, input)
				}
			} else if n.Data == "textarea" {
				for _, a := range n.Attr {
					if a.Key == "name" {
						inputs = append(inputs, FormInput{Name: a.Val, Type: "textarea"})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return inputs
}

func (c *Crawler) resolveURL(baseURL *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return baseURL.ResolveReference(refURL).String()
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
