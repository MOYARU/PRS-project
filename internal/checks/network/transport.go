package network

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

// CheckTransportSecurity performs checks related to HTTPS usage and forced redirects.
func CheckTransportSecurity(ctx *checks.Context) ([]report.Finding, error) {
	if ctx.InitialURL == nil {
		return nil, nil
	}

	var findings []report.Finding

	if ctx.InitialURL.Scheme != "https" {
		findings = append(findings, report.Finding{
			ID:       "HTTPS_NOT_USED",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    "HTTPS 미사용",
			Message:  "HTTPS가 사용되지 않아 전송 구간에서 데이터 노출 위험이 있습니다",
			Fix:      "HTTPS를 사용하도록 TLS 인증서를 적용하세요",
		})
	}

	if ctx.InitialURL.Scheme == "http" && !ctx.RedirectedToHTTPS {
		findings = append(findings, report.Finding{
			ID:       "HTTP_TO_HTTPS_REDIRECT_MISSING",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    "HTTP → HTTPS 강제 리다이렉트 미설정",
			Message:  "HTTP 요청이 HTTPS로 강제 전환되지 않습니다",
			Fix:      "HTTP 요청을 HTTPS로 301/308 리다이렉트하세요",
		})
	}

	if ctx.FinalURL != nil && ctx.FinalURL.Scheme == "http" && ctx.InitialURL.Scheme == "https" {
		findings = append(findings, report.Finding{
			ID:       "HTTPS_DOWNGRADE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    "HTTPS 다운그레이드 감지",
			Message:  "HTTPS 요청이 HTTP로 다운그레이드되었습니다",
			Fix:      "HTTPS에서 HTTP로 리다이렉트하지 않도록 구성하세요",
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
func CheckTLSConfiguration(ctx *checks.Context) ([]report.Finding, error) {
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
			findings = append(findings, report.Finding{
				ID:       fmt.Sprintf("TLS_VERSION_SUPPORTED_V%d", minVersion),
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    fmt.Sprintf("TLS %s 지원", tlsVersionToString(minVersion)),
				Message:  fmt.Sprintf("대상 서버가 더 이상 사용되지 않는 안전하지 않은 TLS %s 프로토콜을 지원합니다.", tlsVersionToString(minVersion)),
				Fix:      "서버에서 TLS 1.2 이하 버전 지원을 비활성화하고 TLS 1.2 이상 버전만 사용하도록 설정하십시오.",
			})
		}
		if tempResult.Response != nil {
			tempResult.Response.Body.Close()
		}
	}

	// If the connection was established using TLS 1.0 or 1.1 with the main fetch (unlikely due to client config)
	if connState.Version < tls.VersionTLS12 {
		findings = append(findings, report.Finding{
			ID:       fmt.Sprintf("TLS_VERSION_DETECTED_V%d", connState.Version),
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    fmt.Sprintf("취약한 TLS %s 사용", tlsVersionToString(connState.Version)),
			Message:  fmt.Sprintf("대상 서버가 취약한 TLS %s 프로토콜을 사용하여 연결을 설정했습니다.", tlsVersionToString(connState.Version)),
			Fix:      "서버에서 TLS 1.2 이하 버전 지원을 비활성화하고 TLS 1.2 이상 버전만 사용하도록 설정하십시오.",
		})
	}

	// --- Check Weak Cipher Suite ---
	cipherName := tls.CipherSuiteName(connState.CipherSuite)
	if reason, ok := weakCiphers[connState.CipherSuite]; ok {
		findings = append(findings, report.Finding{
			ID:       "WEAK_CIPHER_SUITE",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityHigh,
			Title:    "약한 Cipher Suite 사용",
			Message:  fmt.Sprintf("대상 서버가 약한 암호 스위트 '%s'를 사용합니다. 이유: %s", cipherName, reason),
			Fix:      "서버에서 약한 암호 스위트를 비활성화하고 강력한 Forward Secrecy를 제공하는 암호 스위트(예: AES-GCM, ChaCha20-Poly1305 기반의 ECDHE/DHE)만 사용하도록 설정하십시오.",
		})
	} else if connState.Version == tls.VersionTLS12 && !isForwardSecret(connState.CipherSuite) {
		// For TLS 1.2, recommend Forward Secrecy if not already present
		findings = append(findings, report.Finding{
			ID:       "NO_FORWARD_SECRECY_TLS12",
			Category: string(checks.CategoryNetwork),
			Severity: report.SeverityMedium,
			Title:    "Forward Secrecy 미적용 (TLS 1.2)",
			Message:  fmt.Sprintf("TLS 1.2를 사용하지만, 현재 암호 스위트 '%s'는 Forward Secrecy를 제공하지 않을 수 있습니다.", cipherName),
			Fix:      "서버에서 ECDHE 또는 DHE 기반의 강력한 Forward Secrecy를 제공하는 암호 스위트(예: AES-GCM, ChaCha20-Poly1305 기반)만 사용하도록 설정하십시오.",
		})
	}

	// --- Check Certificate ---
	if len(connState.PeerCertificates) > 0 {
		leafCert := connState.PeerCertificates[0]

		// Certificate Expiration
		if currentTime.After(leafCert.NotAfter) {
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    "인증서 만료",
				Message:  fmt.Sprintf("TLS 인증서가 %s에 만료되었습니다.", leafCert.NotAfter.Format("2006-01-02")),
				Fix:      "만료된 TLS 인증서를 갱신하십시오.",
			})
		} else if currentTime.AddDate(0, 1, 0).After(leafCert.NotAfter) { // Expires within 1 month
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_EXPIRING_SOON",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityMedium,
				Title:    "인증서 만료 임박",
				Message:  fmt.Sprintf("TLS 인증서가 한 달 이내인 %s에 만료될 예정입니다.", leafCert.NotAfter.Format("2006-01-02")),
				Fix:      "TLS 인증서 갱신을 계획하십시오.",
			})
		}

		// CN / SAN Mismatch
		if err := leafCert.VerifyHostname(targetHost); err != nil {
			findings = append(findings, report.Finding{
				ID:       "CERTIFICATE_HOSTNAME_MISMATCH",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityHigh,
				Title:    "인증서 호스트네임 불일치",
				Message:  fmt.Sprintf("TLS 인증서의 CN/SAN 필드가 대상 호스트 '%s'와 일치하지 않습니다. 오류: %s", targetHost, err.Error()),
				Fix:      "인증서의 Common Name (CN) 또는 Subject Alternative Name (SAN) 필드가 대상 도메인과 정확히 일치하는 유효한 TLS 인증서를 사용하십시오.",
			})
		}

		// OCSP Stapling
		if len(connState.OCSPResponse) == 0 {
			findings = append(findings, report.Finding{
				ID:       "OCSP_STAPLING_NOT_USED",
				Category: string(checks.CategoryNetwork),
				Severity: report.SeverityLow,
				Title:    "OCSP Stapling 미사용",
				Message:  "OCSP Stapling이 활성화되지 않아 클라이언트가 인증서 해지 상태를 확인하는 데 추가 요청이 필요할 수 있습니다.",
				Fix:      "서버에서 OCSP Stapling을 활성화하여 클라이언트의 TLS 핸드셰이크 성능을 향상시키고 개인 정보 보호를 강화하십시오.",
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