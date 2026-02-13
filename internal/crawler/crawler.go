package crawler

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/MOYARU/PRS-project/internal/app/ui"
	"github.com/MOYARU/PRS-project/internal/engine"
	"golang.org/x/net/html"
)

var jsURLRegex = regexp.MustCompile(`(?:"|')(((?:https?://|/)[^"'\s<>]+))(?:"|')`)

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

	client := engine.NewHTTPClient(true, nil)
	if delay > 0 {
		client.Transport = &engine.DelayedTransport{
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

	c.wg.Add(1)
	go c.crawl(ctx, c.BaseURL.String(), 0)

	// robots.txt 및 sitemap.xml 파싱 시작
	c.wg.Add(1)
	go c.processRobotsAndSitemap(ctx)

	c.wg.Wait()
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

	// Visited Limit to prevent infinite crawling
	c.mu.Lock()
	if len(c.Visited) >= 1000 {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Normalize URL (remove fragment)
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	u.Fragment = ""
	// Canonicalize: remove trailing slash
	if u.Path != "/" && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	targetURL = u.String()

	c.mu.Lock()
	if c.Visited[targetURL] {
		c.mu.Unlock()
		return
	}
	c.Visited[targetURL] = true
	c.Results = append(c.Results, targetURL)
	c.mu.Unlock()

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

	contentType := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(contentType, "text/html")
	isJS := strings.Contains(contentType, "javascript") || strings.HasSuffix(u.Path, ".js")

	if !isHTML && !isJS {
		return
	}

	var links []string
	var resolveBase *url.URL = u

	if isHTML {
		doc, err := html.Parse(resp.Body)
		if err != nil {
			return
		}

		var forms []Form
		var pageBase *url.URL
		links, forms, pageBase = c.extractData(doc)

		if pageBase != nil {
			resolveBase = u.ResolveReference(pageBase)
		}

		c.mu.Lock()
		c.Forms = append(c.Forms, forms...)
		c.mu.Unlock()
	} else if isJS {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			links = c.extractLinksFromJS(string(bodyBytes))
		}
	}

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

			// Check for onclick navigation (improved heuristic)
			for _, a := range n.Attr {
				k := strings.ToLower(a.Key)
				if k == "onclick" || k == "onmousedown" || k == "onmouseup" {
					val := a.Val
					if strings.Contains(val, "location") || strings.Contains(val, "open") || strings.Contains(val, "window") {
						// Extract all potential URLs inside quotes
						for _, quote := range []string{"'", "\""} {
							parts := strings.Split(val, quote)
							for i := 1; i < len(parts); i += 2 {
								candidate := strings.TrimSpace(parts[i])
								if candidate != "" {
									links = append(links, candidate)
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

func (c *Crawler) extractLinksFromJS(content string) []string {
	var links []string
	matches := jsURLRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			links = append(links, match[1])
		}
	}
	return links
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
			} else if n.Data == "select" {
				// Handle select/option
				name := ""
				for _, a := range n.Attr {
					if a.Key == "name" {
						name = a.Val
						break
					}
				}
				if name != "" {
					inputs = append(inputs, FormInput{Name: name, Type: "select"})
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

func (c *Crawler) processRobotsAndSitemap(ctx context.Context) {
	defer c.wg.Done()

	// robots.txt
	robotsURL := c.BaseURL.ResolveReference(&url.URL{Path: "/robots.txt"})
	c.parseRobotsTXT(ctx, robotsURL.String())

	// sitemap.xml
	sitemapURL := c.BaseURL.ResolveReference(&url.URL{Path: "/sitemap.xml"})
	c.parseSitemapXML(ctx, sitemapURL.String())
}

func (c *Crawler) parseRobotsTXT(ctx context.Context, targetURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Disallow: /path or Allow: /path
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path := strings.TrimSpace(parts[1])
				if path != "" && strings.HasPrefix(path, "/") {
					absoluteURL := c.BaseURL.ResolveReference(&url.URL{Path: path}).String()
					if c.isSameDomain(absoluteURL) {
						c.wg.Add(1)
						go c.crawl(ctx, absoluteURL, 0)
					}
				}
			}
		}
		// Sitemap: http://example.com/sitemap.xml
		if strings.HasPrefix(line, "Sitemap:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				sitemapLoc := strings.TrimSpace(parts[1])
				if sitemapLoc != "" {
					c.parseSitemapXML(ctx, sitemapLoc)
				}
			}
		}
	}
}

func (c *Crawler) parseSitemapXML(ctx context.Context, targetURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	decoder := xml.NewDecoder(resp.Body)
	for {
		t, _ := decoder.Token()
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "loc" {
				var loc string
				if err := decoder.DecodeElement(&loc, &se); err == nil {
					loc = strings.TrimSpace(loc)
					if loc != "" && c.isSameDomain(loc) {
						if strings.HasSuffix(loc, ".xml") {
							c.parseSitemapXML(ctx, loc)
						} else {
							c.wg.Add(1)
							go c.crawl(ctx, loc, 0)
						}
					}
				}
			}
		}
	}
}
