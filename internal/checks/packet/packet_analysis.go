package packet

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/MOYARU/PRS-project/internal/checks"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/MOYARU/PRS-project/internal/report"
)

// CanonicalPacket represents a simplified view of the request/response pair
// focusing on security-relevant fields.
type CanonicalPacket struct {
	ReqAuthorization string
	ReqCookie        string
	ReqOrigin        string
	ReqReferer       string
	ReqAccept        string
	RespContentType  string
	RespWWWAuth      string
	RespCORSOrigin   string
	RespCORSCreds    string
}

// CheckPacketAnomalies analyzes the request and response for protocol anomalies and security misconfigurations.
func CheckPacketAnomalies(ctx *ctxpkg.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// 1. Canonicalization: Extract meaningful fields
	packet := extractCanonical(ctx)

	// 2. Packet-based Findings

	// Check A: Content-Type Mismatch (Header vs Body Sniffing)
	// Only check if body is not empty and header is present
	if len(ctx.BodyBytes) > 0 && packet.RespContentType != "" {
		detectedType := http.DetectContentType(ctx.BodyBytes)
		// Simplify detected type (e.g., "text/html; charset=utf-8" -> "text/html")
		simpleDetected := strings.Split(detectedType, ";")[0]
		simpleHeader := strings.Split(packet.RespContentType, ";")[0]

		// Mismatch logic: e.g., Header says JSON but Body is HTML
		if simpleHeader == "application/json" && strings.Contains(simpleDetected, "html") {
			msg := msges.GetMessage("PACKET_CONTENT_TYPE_MISMATCH")
			findings = append(findings, report.Finding{
				ID:         "PACKET_CONTENT_TYPE_MISMATCH",
				Category:   string(checks.CategoryHTTPProtocol),
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceHigh,
				Title:      msg.Title,
				Message:    fmt.Sprintf(msg.Message, simpleHeader, simpleDetected),
				Fix:        msg.Fix,
			})
		}
	}

	// Check B: Authorization / Status Code Anomaly
	// e.g., 200 OK but sends WWW-Authenticate (Confusing state)
	if ctx.Response.StatusCode == http.StatusOK && packet.RespWWWAuth != "" {
		msg := msges.GetMessage("PACKET_WWW_AUTHENTICATE_ON_200")
		findings = append(findings, report.Finding{
			ID:         "PACKET_WWW_AUTHENTICATE_ON_200",
			Category:   string(checks.CategoryAuthSession),
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	// Check C: CORS Header Combination
	if packet.RespCORSOrigin == "*" && packet.RespCORSCreds == "true" {
		msg := msges.GetMessage("PACKET_CORS_BAD_COMBINATION")
		findings = append(findings, report.Finding{
			ID:         "PACKET_CORS_BAD_COMBINATION",
			Category:   string(checks.CategoryNetwork),
			Severity:   report.SeverityMedium,
			Confidence: report.ConfidenceHigh,
			Title:      msg.Title,
			Message:    msg.Message,
			Fix:        msg.Fix,
		})
	}

	// Check D: Accept Header Ignored
	// If request specifically asked for JSON but got HTML
	if strings.Contains(packet.ReqAccept, "application/json") &&
		!strings.Contains(packet.ReqAccept, "text/html") && // Ensure it didn't accept HTML too
		strings.Contains(packet.RespContentType, "text/html") {

		msg := msges.GetMessage("PACKET_ACCEPT_IGNORED")
		findings = append(findings, report.Finding{
			ID:         "PACKET_ACCEPT_IGNORED",
			Category:   string(checks.CategoryHTTPProtocol),
			Severity:   report.SeverityInfo,
			Confidence: report.ConfidenceMedium,
			Title:      msg.Title,
			Message:    fmt.Sprintf(msg.Message, packet.ReqAccept, packet.RespContentType),
			Fix:        msg.Fix,
		})
	}

	return findings, nil
}

// extractCanonical extracts relevant security fields from the context.
func extractCanonical(ctx *ctxpkg.Context) CanonicalPacket {
	p := CanonicalPacket{}

	// Request Fields (if available)
	if ctx.Response != nil && ctx.Response.Request != nil {
		req := ctx.Response.Request
		p.ReqAuthorization = req.Header.Get("Authorization")
		p.ReqCookie = req.Header.Get("Cookie")
		p.ReqOrigin = req.Header.Get("Origin")
		p.ReqReferer = req.Header.Get("Referer")
		p.ReqAccept = req.Header.Get("Accept")
	}

	// Response Fields
	if ctx.Response != nil {
		p.RespContentType = ctx.Response.Header.Get("Content-Type")
		p.RespWWWAuth = ctx.Response.Header.Get("WWW-Authenticate")
		p.RespCORSOrigin = ctx.Response.Header.Get("Access-Control-Allow-Origin")
		p.RespCORSCreds = ctx.Response.Header.Get("Access-Control-Allow-Credentials")
	}

	return p
}
