package checks

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
	RedirectTarget    *url.URL
	Redirected        bool
	RedirectedToHTTPS bool
}
