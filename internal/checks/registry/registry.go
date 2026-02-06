package registry

import (
	"github.com/MOYARU/PRS-project/internal/checks"
	"github.com/MOYARU/PRS-project/internal/checks/application"
	"github.com/MOYARU/PRS-project/internal/checks/authsession"
	ctxpkg "github.com/MOYARU/PRS-project/internal/checks/context" // New import with alias
	"github.com/MOYARU/PRS-project/internal/checks/headers"
	"github.com/MOYARU/PRS-project/internal/checks/http"
	"github.com/MOYARU/PRS-project/internal/checks/network"

	"github.com/MOYARU/PRS-project/internal/checks/api"             // New import
	"github.com/MOYARU/PRS-project/internal/checks/components"      // New import
	"github.com/MOYARU/PRS-project/internal/checks/deserialization" // New import
	"github.com/MOYARU/PRS-project/internal/checks/info"            // New import
	"github.com/MOYARU/PRS-project/internal/checks/injection"       // New import
	"github.com/MOYARU/PRS-project/internal/checks/input"           // New import
	"github.com/MOYARU/PRS-project/internal/checks/packet"          // New import
	"github.com/MOYARU/PRS-project/internal/checks/ssrf"            // New import
	"github.com/MOYARU/PRS-project/internal/checks/web"             // New import
)

func DefaultChecks() []checks.Check {
	return []checks.Check{
		{
			ID:          "NETWORK_TRANSPORT_SECURITY",
			Category:    checks.CategoryNetwork,
			Title:       "네트워크 전송 보안 기본 점검",
			Description: "HTTPS 사용 및 강제 리다이렉트 여부를 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckTransportSecurity,
		},
		{
			ID:          "SECURITY_HEADERS",
			Category:    checks.CategorySecurityHeaders,
			Title:       "보안 헤더 점검",
			Description: "CSP, HSTS, XFO 등 주요 보안 헤더를 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         headers.CheckSecurityHeaders,
		},
		{
			ID:          "TLS_CONFIGURATION",
			Category:    checks.CategoryNetwork,
			Title:       "TLS 설정 점검",
			Description: "TLS 버전, 암호 스위트, 인증서 유효성(만료, 호스트네임), OCSP Stapling 여부를 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckTLSConfiguration,
		},
		{
			ID:          "HTTP_CONFIGURATION",
			Category:    checks.CategoryHTTPProtocol,
			Title:       "HTTP 프로토콜 설정 점검",
			Description: "TRACE/OPTIONS 메서드 활성화, PUT/DELETE 허용 여부 등을 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         http.CheckHTTPConfiguration,
		},
		{
			ID:          "AUTH_SESSION_HARDENING",
			Category:    checks.CategoryAuthSession,
			Title:       "인증/세션 강화 점검 (쿠키 속성)",
			Description: "Secure/HttpOnly, SameSite=None + Secure 누락, Session Cookie Expires 설정 등을 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         authsession.CheckAuthSessionHardening,
		},
		{
			ID:          "SESSION_MANAGEMENT",
			Category:    checks.CategoryAuthSession,
			Title:       "세션 관리 점검",
			Description: "로그인 전/후 Set-Cookie 동일 여부, 세션 재발급 여부 등을 점검합니다.",
			Mode:        ctxpkg.Active, // Requires comparing pre/post login, so active.
			Run:         authsession.CheckSessionManagement,
		},
		{
			ID:          "PARAMETER_POLLUTION",
			Category:    checks.CategoryInputHandling,
			Title:       "파라미터 오염 (Parameter Pollution) 점검",
			Description: "동일 파라미터 중복 전송 시 애플리케이션 처리 방식에 대한 잠재적 취약점을 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         input.CheckParameterPollution,
		},
		{
			ID:          "CONTENT_TYPE_CONFUSION",
			Category:    checks.CategoryAPISecurity,
			Title:       "Content-Type 혼동 점검",
			Description: "JSON API의 text/plain 허용, Accept 헤더 무시 등 Content-Type 처리 취약점을 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         api.CheckContentTypeConfusion,
		},
		{
			ID:          "METHOD_OVERRIDE_ALLOWED",
			Category:    checks.CategoryAPISecurity,
			Title:       "HTTP Method Override 허용 점검",
			Description: "X-HTTP-Method-Override 헤더 등을 통한 HTTP Method Override 허용 여부를 점검합니다 (상태 변경 없음).",
			Mode:        ctxpkg.Active,
			Run:         api.CheckMethodOverride,
		},
		{
			ID:          "CORS_CONFIGURATION",
			Category:    checks.CategoryNetwork, // CORS is network related, but could be API as well
			Title:       "CORS 설정 오류 점검",
			Description: "Cross-Origin Resource Sharing (CORS) 설정의 잠재적 보안 취약점을 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         network.CheckCORSConfiguration,
		},
		{
			ID:          "INFORMATION_LEAKAGE",
			Category:    checks.CategoryInformationLeakage,
			Title:       "정보 누출 점검",
			Description: "스택 트레이스, DB 에러 문자열, 프레임워크 시그니처, 디버그/메타 엔드포인트 노출 여부를 점검합니다.",
			Mode:        ctxpkg.Passive, // Can be active depending on how deep the check goes
			Run:         info.CheckInformationLeakage,
		},
		{
			ID:          "JSON_UNEXPECTED_FIELD_INSERTION",
			Category:    checks.CategoryAPISecurity,
			Title:       "JSON 예상 외 필드 삽입 점검",
			Description: "JSON 요청에 예상되지 않은 필드를 삽입했을 때 애플리케이션의 응답을 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         api.CheckJSONUnexpectedField,
		},
		{
			ID:          "RATE_LIMIT_ABSENCE",
			Category:    checks.CategoryAPISecurity,
			Title:       "Rate Limit 부재 점검",
			Description: "Retry-After, X-RateLimit-* 헤더 부재 등 Rate Limit 설정의 부재를 점검합니다.",
			Mode:        ctxpkg.Passive,
			Run:         api.CheckRateLimitAbsence,
		},
		{
			ID:          "APPLICATION_SECURITY",
			Category:    checks.CategoryAppLogic,
			Title:       "애플리케이션 보안 점검",
			Description: "입력값 Reflection, IDOR 가능성, CSRF 토큰 부재 등을 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         application.CheckApplicationSecurity,
		},
		{
			ID:          "PACKET_ANALYSIS",
			Category:    checks.CategoryHTTPProtocol,
			Title:       "패킷 기반 이상 징후 분석",
			Description: "요청/응답 패킷을 정규화하여 Content-Type 불일치, 인증 헤더 이상, CORS 조합 오류 등을 분석합니다.",
			Mode:        ctxpkg.Passive,
			Run:         packet.CheckPacketAnomalies,
		},
		{
			ID:          "WEB_CONTENT_EXPOSURE",
			Category:    checks.CategoryFileExposure,
			Title:       "웹 콘텐츠 및 파일 노출 점검",
			Description: "민감한 파일 노출 및 웹 콘텐츠 보안(Mixed Content 등)을 점검합니다.",
			Mode:        ctxpkg.Passive, // Runs in both modes, internal logic handles active probes
			Run:         web.CheckWebContentExposure,
		},
		{
			ID:          "SQL_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "SQL Injection 점검",
			Description: "URL 파라미터에 SQL 구문을 주입하여 에러 발생 여부를 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckSQLInjection,
		},
		{
			ID:          "REFLECTED_XSS",
			Category:    checks.CategoryClientSecurity,
			Title:       "Reflected XSS 점검",
			Description: "URL 파라미터에 스크립트를 주입하여 응답 본문에 반사되는지 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckReflectedXSS,
		},
		{
			ID:          "BLIND_SQL_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "블라인드 SQL Injection 점검 (시간 기반)",
			Description: "URL 파라미터에 시간 지연 SQL 페이로드를 주입하여 응답 시간 변화를 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckBlindSQLInjection,
		},
		{
			ID:          "OS_COMMAND_INJECTION",
			Category:    checks.CategoryInputHandling,
			Title:       "OS 커맨드 인젝션 점검 (시간 기반)",
			Description: "URL 파라미터에 시간 지연 OS 명령어 페이로드를 주입하여 응답 시간 변화를 점검합니다.",
			Mode:        ctxpkg.Active,
			Run:         injection.CheckOSCommandInjection,
		},
		// TODO: Stored XSS, DOM XSS, NoSQL, LDAP injection checks will be added here.
		{
			ID:          "SSRF_DETECTION",
			Category:    checks.CategorySSRF,
			Title:       "SSRF (Server-Side Request Forgery) 탐지",
			Description: "외부 URL 주입을 통해 서버가 임의의 요청을 보내는지 확인합니다.",
			Mode:        ctxpkg.Active,
			Run:         ssrf.CheckSSRF,
		},
		{
			ID:          "INSECURE_DESERIALIZATION",
			Category:    checks.CategoryIntegrityFailures,
			Title:       "안전하지 않은 역직렬화 탐지",
			Description: "파라미터 및 쿠키에서 직렬화된 데이터 패턴을 식별합니다.",
			Mode:        ctxpkg.Passive, // Can be extended to Active
			Run:         deserialization.CheckInsecureDeserialization,
		},
		{
			ID:          "VULNERABLE_COMPONENTS",
			Category:    checks.CategoryVulnerableComponents,
			Title:       "취약한 컴포넌트 버전 식별",
			Description: "서버 헤더 및 HTML 주석을 분석하여 오래된 소프트웨어 버전을 식별합니다.",
			Mode:        ctxpkg.Passive,
			Run:         components.CheckVulnerableComponents,
		},
	}
}
