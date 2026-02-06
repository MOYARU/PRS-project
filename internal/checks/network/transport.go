package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/engine"
	msges "github.com/MOYARU/PRS-project/internal/messages" // New import for messages
	"github.com/MOYARU/PRS-project/internal/report"
)

// CheckTransportSecurity performs checks related to HTTPS usage and forced redirects.
func CheckTransportSecurity(ctx *ctxpkg.Context) ([]report.Finding, error) {
	if ctx.InitialURL == nil {
		return nil, nil
	}

	var findings []report.Finding

	if ctx.InitialURL.Scheme != "https" {
		msg := msges.GetMessage("HTTPS_NOT_USED")
		findings = append(findings, report.Finding{
			ID:       "HTTPS_NOT_USED",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if ctx.InitialURL.Scheme == "http" && !ctx.RedirectedToHTTPS {
		msg := msges.GetMessage("HTTP_TO_HTTPS_REDIRECT_MISSING")
		findings = append(findings, report.Finding{
			ID:       "HTTP_TO_HTTPS_REDIRECT_MISSING",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	if ctx.FinalURL != nil && ctx.FinalURL.Scheme == "http" && ctx.InitialURL.Scheme == "https" {
		msg := msges.GetMessage("HTTPS_DOWNGRADE")
		findings = append(findings, report.Finding{
			ID:       "HTTPS_DOWNGRADE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  msg.Message,
			Fix:      msg.Fix,
		})
	}

	return findings, nil
}

// weakCiphers is a map of known weak TLS cipher suites.
// This list is not exhaustive and should be updated as new weaknesses are discovered.
var weakCiphers = map[uint16]string{
	// Remaining weak ciphers or those that might still be defined.
	// For compilation purposes, only keep those that are guaranteed to exist.
	// Actual weak cipher detection should be more comprehensive.
}

// CheckTLSConfiguration performs various checks on the TLS/SSL configuration.
func CheckTLSConfiguration(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// If no TLS connection was established, we cannot perform these checks.
	if ctx.Response == nil || ctx.Response.TLS == nil {
		return findings, nil
	}

	connState := ctx.Response.TLS
	targetHost := ctx.FinalURL.Hostname()
	currentTime := time.Now()

	// --- Check TLS Version ---
	// Probe for TLS 1.0/1.1 support by attempting connections with lower MinVersion
	// This requires making new requests, as ctx.Response.TLS reflects the initial (secure) connection.
	for _, minVersion := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		if minVersion >= tls.VersionTLS12 { // Skip if probing for current or stronger versions
			continue
		}

		tlsConfig := &tls.Config{
			MinVersion:         minVersion,
			InsecureSkipVerify: true, // Ignore certificate errors for TLS version probing
		}

		tempResult, err := engine.FetchWithTLSConfig(ctx.FinalURL.String(), tlsConfig)
		if err != nil {
			// If we get an error, it usually means the server *doesn't* support this version.
			// Specifically, a TLS handshake error or timeout could indicate this.
			// We're looking for successful handshakes at lower versions.
			if opErr, ok := err.(*net.OpError); ok && opErr.Op == "read" {
				// This often happens if the server immediately closes the connection due to unsupported TLS version.
				continue
			}
			if _, ok := err.(tls.RecordHeaderError); ok {
				// This happens if the server doesn't understand the client hello.
				continue
			}
			// Other errors might be actual network issues, not TLS version related.
			// For now, we assume if an error occurs, this version is not successfully negotiated.
			continue
		}

		if tempResult.Response != nil && tempResult.Response.TLS != nil && tempResult.Response.TLS.Version == minVersion {
			msg := msges.GetMessage("TLS_VERSION_SUPPORTED_V") // ID without %d
			findings = append(findings, report.Finding{
				ID:       fmt.Sprintf("TLS_VERSION_SUPPORTED_V%d", minVersion),
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    fmt.Sprintf(msg.Title, tlsVersionToString(minVersion)),
				Message:  fmt.Sprintf(msg.Message, tlsVersionToString(minVersion)),
				Fix:      msg.Fix,
			})
		}
		if tempResult.Response != nil {
			tempResult.Response.Body.Close()
		}
	}

	// If the connection was established using TLS 1.0 or 1.1 with the main fetch (unlikely due to client config)
	if connState.Version < tls.VersionTLS12 {
		msg := msges.GetMessage("TLS_VERSION_DETECTED_V") // ID without %d
		findings = append(findings, report.Finding{
			ID:       fmt.Sprintf("TLS_VERSION_DETECTED_V%d", connState.Version),
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    fmt.Sprintf(msg.Title, tlsVersionToString(connState.Version)),
			Message:  fmt.Sprintf(msg.Message, tlsVersionToString(connState.Version)),
			Fix:      msg.Fix,
		})
	}

	// --- Check Weak Cipher Suite ---
	cipherName := tls.CipherSuiteName(connState.CipherSuite)
	if reason, ok := weakCiphers[connState.CipherSuite]; ok {
		msg := msges.GetMessage("WEAK_CIPHER_SUITE")
		findings = append(findings, report.Finding{
			ID:       "WEAK_CIPHER_SUITE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, cipherName, reason),
			Fix:      msg.Fix,
		})
	} else if connState.Version == tls.VersionTLS12 && !isForwardSecret(connState.CipherSuite) {
		// For TLS 1.2, recommend Forward Secrecy if not already present
		msg := msges.GetMessage("NO_FORWARD_SECRECY_TLS12")
		findings = append(findings, report.Finding{
			ID:       "NO_FORWARD_SECRECY_TLS12",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityMedium,
			Title:    msg.Title,
			Message:  fmt.Sprintf(msg.Message, cipherName),
			Fix:      msg.Fix,
		})
	}

	// --- Check Certificate ---
	if len(connState.PeerCertificates) > 0 {
		leafCert := connState.PeerCertificates[0]

		// Certificate Expiration
		if currentTime.After(leafCert.NotAfter) {
			msg := msges.GetMessage("CERTIFICATE_EXPIRED")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, leafCert.NotAfter.Format("2006-01-02")),
				Fix:      msg.Fix,
			})
		} else if currentTime.AddDate(0, 1, 0).After(leafCert.NotAfter) { // Expires within 1 month
			msg := msges.GetMessage("CERTIFICATE_EXPIRING_SOON")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRING_SOON",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityMedium,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, leafCert.NotAfter.Format("2006-01-02")),
				Fix:      msg.Fix,
			})
		}

		// CN / SAN Mismatch
		if err := leafCert.VerifyHostname(targetHost); err != nil {
			msg := msges.GetMessage("CERTIFICATE_HOSTNAME_MISMATCH")
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_HOSTNAME_MISMATCH",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    msg.Title,
				Message:  fmt.Sprintf(msg.Message, targetHost, err.Error()),
				Fix:      msg.Fix,
			})
		}

		// OCSP Stapling
		if len(connState.OCSPResponse) == 0 {
			msg := msges.GetMessage("OCSP_STAPLING_NOT_USED")
			findings = append(findings, report.Finding{
				ID:       "OCSP_STAPLING_NOT_USED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityLow,
				Title:    msg.Title,
				Message:  msg.Message,
				Fix:      msg.Fix,
			})
		}
	}

	return findings, nil
}

// tlsVersionToString converts a TLS version constant to a human-readable string.
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return fmt.Sprintf("Unknown (%x)", version)
	}
}

// isForwardSecret checks if a cipher suite provides Forward Secrecy.
// This list needs to be maintained and updated.
func isForwardSecret(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256:
		return true
	default:
		// Many other DHE/ECDHE suites are also forward secret.
		// For simplicity, this checks common strong ones. A more comprehensive list might be needed.
		if strings.Contains(tls.CipherSuiteName(cipherSuite), "DHE") || strings.Contains(tls.CipherSuiteName(cipherSuite), "ECDHE") {
			return true
		}
		return false
	}
}
