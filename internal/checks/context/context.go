package context

import (
	"net/http"
	"net/url"
)

type ScanMode string

const (
	Passive ScanMode = "passive"
	Active  ScanMode = "active"
)

type Context struct {
	Target            string
	Mode              ScanMode
	InitialURL        *url.URL
	FinalURL          *url.URL
	Response          *http.Response
	BodyBytes         []byte
	RedirectTarget    *url.URL
	Redirected        bool
	RedirectedToHTTPS bool
	HTTPClient        *http.Client
}
