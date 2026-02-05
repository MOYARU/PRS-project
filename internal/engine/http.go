package engine

import (
	"crypto/tls"
	"net/http"
	"time"
)

func NewHTTPClient(allowRedirect bool, tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Timeout: 11 * time.Second, // Increased timeout to 11 seconds
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	if !allowRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
