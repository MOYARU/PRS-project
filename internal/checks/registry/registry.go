package registry

import (
	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/checks/application"
	"github.com/MOYARU/PRS/internal/checks/authsession"
	"github.com/MOYARU/PRS/internal/checks/headers"
	"github.com/MOYARU/PRS/internal/checks/http"
	"github.com/MOYARU/PRS/internal/checks/network"
	"github.com/MOYARU/PRS/internal/checks/web"
)

func DefaultChecks() []checks.Check {
	return []checks.Check{
		{
			ID:          "NETWORK_TRANSPORT_SECURITY",
			Category:    checks.CategoryNetwork,
			Title:       "네트워크 전송 보안 기본 점검",
			Description: "HTTPS 사용 및 강제 리다이렉트 여부를 점검합니다.",
			Mode:        checks.Passive,
			Run:         network.CheckTransportSecurity,
		},
		{
			ID:          "SECURITY_HEADERS",
			Category:    checks.CategorySecurityHeaders,
			Title:       "보안 헤더 점검",
			Description: "CSP, HSTS, XFO 등 주요 보안 헤더를 점검합니다.",
			Mode:        checks.Passive,
			Run:         headers.CheckSecurityHeaders,
		},
		{
			ID:          "TLS_CONFIGURATION",
			Category:    checks.CategoryNetwork,
			Title:       "TLS 설정 점검",
			Description: "TLS 버전, 암호 스위트, 인증서 유효성(만료, 호스트네임), OCSP Stapling 여부를 점검합니다.",
			Mode:        checks.Passive,
			Run:         network.CheckTLSConfiguration,
		},
		{
			ID:          "HTTP_CONFIGURATION",
			Category:    checks.CategoryHTTPProtocol,
			Title:       "HTTP 프로토콜 설정 점검",
			Description: "TRACE/OPTIONS 메서드 활성화, PUT/DELETE 허용 여부 등을 점검합니다.",
			Mode:        checks.Active,               // Changed to Active
			Run:         http.CheckHTTPConfiguration, // Corrected from httpchecks to http
		},
		{
			ID:          "AUTH_SESSION_CONFIGURATION",
			Category:    checks.CategoryAuthSession,
			Title:       "인증/세션 설정 점검",
			Description: "로그인 페이지 HTTPS 사용 여부, 세션 쿠키 만료 설정 등을 점검합니다.",
			Mode:        checks.Passive,
			Run:         authsession.CheckAuthSessionConfiguration,
		},
		{
			ID:          "WEB_CONTENT_EXPOSURE",
			Category:    checks.CategoryFileExposure,
			Title:       "웹 콘텐츠 노출 점검",
			Description: "민감할 수 있는 파일 (robots.txt, .git, .env 등) 노출 여부를 점검합니다.",
			Mode:        checks.Passive,
			Run:         web.CheckWebContentExposure,
		},
		{
			ID:          "APPLICATION_SECURITY",
			Category:    checks.CategoryAppLogic, // E. 입력 처리, F. 접근 제어 falls under AppLogic generally
			Title:       "애플리케이션 보안 점검",
			Description: "입력값 Reflection, IDOR 가능성, CSRF 토큰 부재 등을 점검합니다.",
			Mode:        checks.Active, // Contains active checks like IDOR
			Run:         application.CheckApplicationSecurity,
		},
	}
}
