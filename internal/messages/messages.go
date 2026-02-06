package messages

import "fmt"

// MessageDetail holds the localized details for a finding.
type MessageDetail struct {
	Title                      string
	Message                    string
	Fix                        string
	IsPotentiallyFalsePositive bool // New field for false positive indication
}

// messages is a map of finding IDs to their detailed messages.
var messages = map[string]MessageDetail{
	"CORS_WILDCARD_ORIGIN": {
		Title:                      "CORS 와일드카드 Origin 허용",
		Message:                    "Access-Control-Allow-Origin 헤더가 '*'로 설정되어 있어 모든 도메인에서의 리소스 접근을 허용합니다. 민감한 정보가 노출될 위험이 있습니다.",
		Fix:                        "Access-Control-Allow-Origin 헤더에 와일드카드('*') 대신 신뢰할 수 있는 특정 도메인을 명시하십시오. 여러 도메인을 지원해야 하는 경우, 서버 측에서 Origin 헤더를 검증한 후 화이트리스트에 있는 경우에만 해당 Origin을 반환하도록 구현해야 합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"CORS_ORIGIN_REFLECTION": {
		Title:                      "CORS Origin Reflection 취약점",
		Message:                    "요청의 Origin 헤더 '%s'가 Access-Control-Allow-Origin에 그대로 반영됩니다. 이는 임의의 도메인에서 리소스 접근을 허용할 수 있습니다.",
		Fix:                        "Access-Control-Allow-Origin 헤더에 허용된 Origin(화이트리스트)만 명시적으로 지정하고, 요청 Origin을 그대로 반영하지 마십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_NOT_USED": {
		Title:                      "HTTPS 미사용",
		Message:                    "HTTPS가 사용되지 않아 전송 구간에서 데이터 노출 위험이 있습니다",
		Fix:                        "Let's Encrypt와 같은 신뢰할 수 있는 인증 기관(CA)에서 유효한 TLS 인증서를 발급받아 웹 서버에 적용하십시오. 모든 프로덕션 트래픽은 암호화된 채널(HTTPS)을 통해서만 전송되어야 합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTP_TO_HTTPS_REDIRECT_MISSING": {
		Title:                      "HTTP → HTTPS 강제 리다이렉트 미설정",
		Message:                    "HTTP 요청이 HTTPS로 강제 전환되지 않습니다",
		Fix:                        "웹 서버 설정(Nginx, Apache 등)에서 80번 포트(HTTP)로 들어오는 모든 요청을 443번 포트(HTTPS)로 301(Moved Permanently) 리다이렉트하도록 구성하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"HTTPS_DOWNGRADE": {
		Title:                      "HTTPS 다운그레이드 감지",
		Message:                    "HTTPS 요청이 HTTP로 다운그레이드되었습니다",
		Fix:                        "HTTPS에서 HTTP로 리다이렉트하지 않도록 구성하세요",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_SUPPORTED_V": { // %d is not part of the ID, it's a format specifier
		Title:                      "TLS %s 지원",
		Message:                    "대상 서버가 더 이상 사용되지 않는 안전하지 않은 TLS %s 프로토콜을 지원합니다.",
		Fix:                        "웹 서버의 SSL/TLS 설정에서 SSLv3, TLS 1.0, TLS 1.1과 같은 구형 프로토콜을 비활성화하십시오. 보안을 위해 TLS 1.2 및 TLS 1.3 버전만 활성화하는 것을 권장합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"TLS_VERSION_DETECTED_V": { // %d is not part of the ID, it's a format specifier
		Title:                      "취약한 TLS %s 사용",
		Message:                    "대상 서버가 취약한 TLS %s 프로토콜을 사용하여 연결을 설정했습니다.",
		Fix:                        "웹 서버의 SSL/TLS 설정에서 SSLv3, TLS 1.0, TLS 1.1과 같은 구형 프로토콜을 비활성화하십시오. 보안을 위해 TLS 1.2 및 TLS 1.3 버전만 활성화하는 것을 권장합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"WEAK_CIPHER_SUITE": {
		Title:                      "약한 Cipher Suite 사용",
		Message:                    "대상 서버가 약한 암호 스위트 '%s'를 사용합니다. 이유: %s",
		Fix:                        "RC4, 3DES, CBC 모드 등 취약한 암호 알고리즘을 사용하는 Cipher Suite를 비활성화하십시오. 대신 Forward Secrecy를 지원하는 ECDHE 또는 DHE 키 교환 방식과 AES-GCM, ChaCha20-Poly1305와 같은 강력한 암호화 알고리즘을 우선순위로 설정하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"NO_FORWARD_SECRECY_TLS12": {
		Title:                      "Forward Secrecy 미적용 (TLS 1.2)",
		Message:                    "TLS 1.2를 사용하지만, 현재 암호 스위트 '%s'는 Forward Secrecy를 제공하지 않을 수 있습니다.",
		Fix:                        "서버에서 ECDHE 또는 DHE 기반의 강력한 Forward Secrecy를 제공하는 암호 스위트(예: AES-GCM, ChaCha20-Poly1305 기반)만 사용하도록 설정하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRED": {
		Title:                      "인증서 만료",
		Message:                    "TLS 인증서가 %s에 만료되었습니다.",
		Fix:                        "만료된 TLS 인증서를 갱신하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_EXPIRING_SOON": {
		Title:                      "인증서 만료 임박",
		Message:                    "TLS 인증서가 한 달 이내인 %s에 만료될 예정입니다.",
		Fix:                        "TLS 인증서 갱신을 계획하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"CERTIFICATE_HOSTNAME_MISMATCH": {
		Title:                      "인증서 호스트네임 불일치",
		Message:                    "TLS 인증서의 CN/SAN 필드가 대상 호스트 '%s'와 일치하지 않습니다. 오류: %s",
		Fix:                        "인증서의 Common Name (CN) 또는 Subject Alternative Name (SAN) 필드가 대상 도메인과 정확히 일치하는 유효한 TLS 인증서를 사용하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"OCSP_STAPLING_NOT_USED": {
		Title:                      "OCSP Stapling 미사용",
		Message:                    "OCSP Stapling이 활성화되지 않아 클라이언트가 인증서 해지 상태를 확인하는 데 추가 요청이 필요할 수 있습니다.",
		Fix:                        "서버에서 OCSP Stapling을 활성화하여 클라이언트의 TLS 핸드셰이크 성능을 향상시키고 개인 정보 보호를 강화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INPUT_REFLECTION_DETECTED": {
		Title:                      "입력값 Reflection 감지",
		Message:                    "URL 파라미터 '%s'의 입력값이 응답 본문에 반영되었습니다. 이는 XSS 공격으로 이어질 수 있습니다.",
		Fix:                        "사용자 입력값을 출력 시 적절한 인코딩(HTML 엔티티, URL 인코딩 등)을 적용하여 Reflection을 방지하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"IDOR_POSSIBLE": {
		Title:                      "IDOR 가능성 감지",
		Message:                    "숫자 ID 변경 (%s) 시 응답 내용이 변경되었습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.",
		Fix:                        "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"IDOR_RESOURCE_GUESSING": {
		Title:                      "IDOR 기반 리소스 추정 가능성",
		Message:                    "존재하지 않는 ID에 접근 시도 후 ID 변경 (%s)으로 유효한 리소스에 접근했습니다. 이는 다른 사용자의 리소스에 접근 가능함을 의미할 수 있습니다.",
		Fix:                        "숫자 ID를 사용하는 리소스 접근 시 서버 측에서 적절한 접근 제어 (예: 소유자 확인)를 구현하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"CSRF_TOKEN_POSSIBLY_MISSING": {
		Title:                      "CSRF 토큰 부재 가능성",
		Message:                    "HTML 폼에서 CSRF(Cross-Site Request Forgery) 공격 방어를 위한 토큰이 발견되지 않았을 수 있습니다.",
		Fix:                        "모든 상태 변경 요청을 처리하는 폼에 CSRF 토큰을 포함하고, 토큰의 유효성을 검증하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"GRAPHQL_INTROSPECTION_ENABLED": {
		Title:                      "GraphQL Introspection 활성화",
		Message:                    "GraphQL Introspection 기능이 '%s' 경로에서 활성화되어 스키마 정보가 노출될 수 있습니다.",
		Fix:                        "운영 환경에서는 GraphQL Introspection 기능을 비활성화하여 API의 내부 구조 노출을 방지하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_MANAGEMENT_MANUAL_REVIEW_NEEDED": {
		Title:                      "세션 관리 점검 (수동 검증 필요)",
		Message:                    "세션 관리 취약점(로그인 후 세션 재발급 여부, 로그인 전후 쿠키 변경 등)은 자동화된 검증이 어렵습니다. 수동 검증이 필요합니다.",
		Fix:                        "로그인 시 세션 ID 재발급, 로그아웃 시 세션 무효화, 민감한 쿠키의 변경 여부 등을 수동으로 확인하고 적절한 세션 관리 정책을 구현하십시오.",
		IsPotentiallyFalsePositive: true, // Explicitly marked for manual review, so also potentially false positive for automation
	},
	"LOGIN_PAGE_HTTPS_MISSING": {
		Title:                      "로그인 페이지 HTTPS 미사용",
		Message:                    "로그인 페이지 '%s'가 HTTPS를 사용하지 않아 인증 정보가 평문으로 전송될 위험이 있습니다.",
		Fix:                        "로그인 페이지를 포함한 모든 인증 관련 페이지에 HTTPS를 강제 적용하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_SECURE_FLAG_MISSING": {
		Title:                      "쿠키 Secure 플래그 누락",
		Message:                    "HTTPS 페이지에서 '%s' 쿠키에 Secure 플래그가 설정되지 않아 HTTP 통신 시 노출될 위험이 있습니다.",
		Fix:                        "모든 민감한 쿠키에 Secure 플래그를 설정하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"COOKIE_HTTPONLY_FLAG_MISSING": {
		Title:                      "쿠키 HttpOnly 플래그 누락",
		Message:                    "'%s' 쿠키에 HttpOnly 플래그가 설정되지 않아 클라이언트 측 스크립트에 의해 접근될 수 있습니다.",
		Fix:                        "민감한 쿠키에 HttpOnly 플래그를 설정하여 XSS 공격으로부터 보호하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"SAMESITE_NONE_SECURE_MISSING": {
		Title:                      "SameSite=None 쿠키에 Secure 플래그 누락",
		Message:                    "'%s' 쿠키(헤더 값)가 SameSite=None을 사용하지만 Secure 플래그가 없습니다.",
		Fix:                        "SameSite=None을 사용하는 모든 쿠키에 Secure 플래그를 함께 설정하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"SESSION_COOKIE_NO_EXPIRATION": {
		Title:                      "세션 쿠키 만료 없음",
		Message:                    "세션 관련 쿠키 '%s'가 만료 시간을 설정하지 않아, 장기간 브라우저에 남아있을 수 있습니다.",
		Fix:                        "세션 관련 쿠키에 적절한 만료 시간(Expires 또는 Max-Age)을 설정하여 세션 하이재킹 위험을 줄이십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"CONTENT_SECURITY_POLICY_MISSING": { // From missingHeader("Content-Security-Policy", ...)
		Title:                      "Missing Content-Security-Policy",
		Message:                    "XSS 공격 방어 불가",
		Fix:                        "웹 서버 또는 애플리케이션 응답 헤더에 'Content-Security-Policy'를 추가하십시오. 예: \"default-src 'self';\". 이는 신뢰할 수 있는 소스에서만 스크립트, 스타일, 이미지 등을 로드하도록 제한하여 XSS 공격을 완화합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"X_FRAME_OPTIONS_MISSING": { // From missingHeader("X-Frame-Options", ...)
		Title:                      "Missing X-Frame-Options",
		Message:                    "Clickjacking 공격 가능",
		Fix:                        "응답 헤더에 'X-Frame-Options: DENY' (모든 프레임 차단) 또는 'X-Frame-Options: SAMEORIGIN' (동일 출처만 허용)을 추가하여 클릭재킹(Clickjacking) 공격을 방지하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"X_CONTENT_TYPE_OPTIONS_MISSING": { // From missingHeader("X-Content-Type-Options", ...)
		Title:                      "Missing X-Content-Type-Options",
		Message:                    "MIME 타입 스니핑 방어 불가",
		Fix:                        "응답 헤더에 'X-Content-Type-Options: nosniff'를 추가하십시오. 이는 브라우저가 선언된 Content-Type과 다른 MIME 타입으로 리소스를 해석(Sniffing)하는 것을 방지하여 XSS 등의 위험을 줄입니다.",
		IsPotentiallyFalsePositive: false,
	},
	"REFERRER_POLICY_MISSING": { // From missingHeader("Referrer-Policy", ...)
		Title:                      "Missing Referrer-Policy",
		Message:                    "Referrer 정보 과다 노출 가능",
		Fix:                        "Referrer-Policy: strict-origin-when-cross-origin",
		IsPotentiallyFalsePositive: false,
	},
	"PERMISSIONS_POLICY_MISSING": { // From missingHeader("Permissions-Policy", ...)
		Title:                      "Missing Permissions-Policy",
		Message:                    "브라우저 기능 제어 미흡",
		Fix:                        "Permissions-Policy: geolocation=()",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_OPENER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Opener-Policy", ...)
		Title:                      "Missing Cross-Origin-Opener-Policy",
		Message:                    "탭 격리 보호 미흡",
		Fix:                        "Cross-Origin-Opener-Policy: same-origin",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_EMBEDDER_POLICY_MISSING": { // From missingHeader("Cross-Origin-Embedder-Policy", ...)
		Title:                      "Missing Cross-Origin-Embedder-Policy",
		Message:                    "격리된 컨텍스트 보호 미흡",
		Fix:                        "Cross-Origin-Embedder-Policy: require-corp",
		IsPotentiallyFalsePositive: false,
	},
	"CROSS_ORIGIN_RESOURCE_POLICY_MISSING": { // From missingHeader("Cross-Origin-Resource-Policy", ...)
		Title:                      "Missing Cross-Origin-Resource-Policy",
		Message:                    "리소스 공유 정책 미설정",
		Fix:                        "Cross-Origin-Resource-Policy: same-site",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MISSING": {
		Title:                      "Missing Strict-Transport-Security",
		Message:                    "HTTPS 연결 강제 및 다운그레이드 방어 미흡",
		Fix:                        "응답 헤더에 'Strict-Transport-Security'를 추가하십시오. 권장 값: \"max-age=31536000; includeSubDomains; preload\". 이는 브라우저가 해당 도메인에 대해 일정 기간 동안 HTTPS로만 접속하도록 강제합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"HSTS_MAXAGE_LOW": {
		Title:                      "HSTS max-age too low",
		Message:                    "HSTS max-age 값이 낮아 보호 기간이 부족합니다",
		Fix:                        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		IsPotentiallyFalsePositive: false,
	},
	"SERVER_HEADER_EXPOSED": {
		Title:                      "Server header exposed",
		Message:                    "서버 정보 노출",
		Fix:                        "웹 서버 설정에서 'Server' 헤더를 제거하거나 일반적인 값(예: 'Server: WebServer')으로 변경하여 구체적인 서버 소프트웨어 및 버전 정보가 노출되지 않도록 하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"X_POWERED_BY_EXPOSED": {
		Title:                      "X-Powered-By header exposed",
		Message:                    "프레임워크 또는 런타임 정보 노출",
		Fix:                        "애플리케이션 서버 또는 프레임워크 설정에서 'X-Powered-By' 헤더 생성을 비활성화하십시오. (예: PHP의 expose_php = Off, Express.js의 app.disable('x-powered-by'))",
		IsPotentiallyFalsePositive: false,
	},
	"TRACE_METHOD_ENABLED": {
		Title:                      "TRACE 메서드 활성화",
		Message:                    "HTTP TRACE 메서드가 활성화되어 XST (Cross-Site Tracing) 공격에 취약할 수 있습니다.",
		Fix:                        "웹 서버 설정에서 TRACE 메서드를 비활성화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"OPTIONS_OVER_EXPOSED": {
		Title:                      "OPTIONS 메서드 과다 노출",
		Message:                    "OPTIONS 메서드를 통해 허용되는 HTTP 메서드('%s')가 과도하게 노출되어 정보 유출 위험이 있습니다.",
		Fix:                        "웹 서버 설정에서 불필요한 HTTP 메서드(PUT, DELETE, TRACE 등)를 비활성화하고, OPTIONS 요청에 대해 필요한 메서드만 응답하도록 구성하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"PUT_METHOD_ALLOWED": {
		Title:                      "PUT 메서드 허용",
		Message:                    "웹 서버가 임의의 경로에 PUT 메서드를 허용하여 파일 생성/수정에 취약할 수 있습니다. 테스트 경로: %s",
		Fix:                        "REST API 등에서 꼭 필요한 경우가 아니라면 웹 서버 설정에서 PUT 메서드를 비활성화하십시오. 사용해야 한다면 해당 엔드포인트에 대해 강력한 인증 및 권한 검사를 적용해야 합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"DELETE_METHOD_ALLOWED": {
		Title:                      "DELETE 메서드 허용",
		Message:                    "웹 서버가 임의의 경로에 DELETE 메서드를 허용하여 파일 삭제에 취약할 수 있습니다. 테스트 경로: %s",
		Fix:                        "REST API 등에서 꼭 필요한 경우가 아니라면 웹 서버 설정에서 DELETE 메서드를 비활성화하십시오. 사용해야 한다면 해당 엔드포인트에 대해 강력한 인증 및 권한 검사를 적용해야 합니다.",
		IsPotentiallyFalsePositive: false,
	},
	"ROBOTS_TXT_EXPOSED": {
		Title:                      "robots.txt 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"SITEMAP_XML_EXPOSED": {
		Title:                      "sitemap.xml 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"SECURITY_TXT_EXPOSED": {
		Title:                      "security.txt 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"WELL_KNOWN_EXPOSED": {
		Title:                      ".well-known 디렉토리 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_HEAD_EXPOSED": {
		Title:                      ".git 디렉토리 노출 (HEAD 파일)",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"GIT_CONFIG_EXPOSED": {
		Title:                      ".git 디렉토리 노출 (config 파일)",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"ENV_EXPOSED": {
		Title:                      ".env 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"TRAVIS_YML_EXPOSED": {
		Title:                      ".travis.yml (CI/CD) 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"GITLAB_CI_YML_EXPOSED": {
		Title:                      ".gitlab-ci.yml (CI/CD) 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"JENKINSFILE_EXPOSED": {
		Title:                      "Jenkinsfile (CI/CD) 파일 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"ACTUATOR_ENDPOINT_EXPOSED": {
		Title:                      "/actuator 디버그 엔드포인트 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"DEBUG_ENDPOINT_EXPOSED": {
		Title:                      "/debug 디버그 엔드포인트 노출",
		Message:                    "민감할 수 있는 파일/디렉토리 '%s'가 외부에 노출되어 있습니다.",
		Fix:                        "해당 파일/디렉토리에 대한 외부 접근을 차단하거나 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"MIXED_CONTENT_DETECTED": {
		Title:                      "Mixed Content 감지",
		Message:                    "HTTPS 페이지에서 안전하지 않은 HTTP 리소스 '%s'를 로드합니다.",
		Fix:                        "모든 리소스를 HTTPS로 로드하도록 변경하거나 상대 경로를 사용하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"IFRAME_SANDBOX_MISSING": {
		Title:                      "Iframe Sandbox 속성 미사용",
		Message:                    "<iframe> 태그에 sandbox 속성이 없어 잠재적인 클릭재킹 또는 스크립트 실행 위험이 있습니다. (src: %s)",
		Fix:                        "모든 <iframe> 태그에 sandbox 속성을 추가하여 포함된 콘텐츠의 권한을 제한하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INLINE_SCRIPT_DETECTED": {
		Title:                      "인라인 스크립트 사용 감지",
		Message:                    "Content-Security-Policy(CSP)가 없거나 약하여 인라인 스크립트가 허용됩니다. 이는 XSS 공격 위험을 증가시킬 수 있습니다.",
		Fix:                        "가능한 모든 JavaScript 코드를 외부 .js 파일로 분리하십시오. 인라인 스크립트가 꼭 필요한 경우, CSP 헤더에 'nonce' 또는 'sha256' 해시를 사용하여 승인된 스크립트만 실행되도록 허용하고 'unsafe-inline' 사용을 지양하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"JSON_API_TEXT_PLAIN_ALLOWED": {
		Title:                      "JSON API에 text/plain Content-Type 허용",
		Message:                    "JSON API 엔드포인트가 'Content-Type: text/plain' 요청을 JSON으로 처리하여 Content-Type 혼동 취약점에 노출될 수 있습니다.",
		Fix:                        "API 요청 처리 시 'Content-Type: application/json'만 허용하고, 다른 Content-Type은 거부하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"ACCEPT_HEADER_IGNORED": {
		Title:                      "Accept 헤더 무시",
		Message:                    "클라이언트의 'Accept: text/html' 요청을 무시하고 JSON Content-Type을 반환했습니다. Content-Type Negotiation 취약점이 있을 수 있습니다.",
		Fix:                        "클라이언트의 Accept 헤더를 존중하고, 요청된 Content-Type으로 응답하거나 적절한 오류를 반환하도록 구성하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"METHOD_OVERRIDE_ALLOWED": {
		Title:                      "HTTP Method Override 허용",
		Message:                    "X-HTTP-Method-Override 헤더를 사용하여 POST 요청을 '%s' 메서드로 오버라이드할 수 있습니다. 이는 예상치 못한 동작을 유발할 수 있습니다.",
		Fix:                        "불필요한 HTTP Method Override 기능을 비활성화하거나, 허용된 메서드만 엄격하게 처리하도록 구성하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"RETRY_AFTER_HEADER_MISSING": {
		Title:                      "Retry-After 헤더 부재",
		Message:                    "응답에 'Retry-After' 헤더가 없어 클라이언트가 Rate Limit 초과 시 재시도 간격을 알 수 없습니다.",
		Fix:                        "Rate Limit 적용 시 클라이언트에게 적절한 재시도 간격을 제공하기 위해 'Retry-After' 헤더를 포함하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"X_RATELIMIT_HEADERS_MISSING": {
		Title:                      "X-RateLimit-* 헤더 부재",
		Message:                    "응답에 'X-RateLimit-*' 관련 헤더가 없어 클라이언트가 Rate Limit 정보를 알 수 없습니다.",
		Fix:                        "Rate Limit 정보를 클라이언트에게 명확히 전달하기 위해 'X-RateLimit-*' 헤더를 포함하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_STACK_TRACE": {
		Title:                      "스택 트레이스 노출",
		Message:                    "응답 본문에서 애플리케이션의 스택 트레이스가 발견되었습니다. 내부 시스템 정보가 노출될 위험이 있습니다.",
		Fix:                        "애플리케이션의 에러 처리 설정을 검토하여 운영(Production) 환경에서는 스택 트레이스가 클라이언트로 전송되지 않도록 하십시오. 대신 사용자 친화적인 일반 오류 페이지를 표시하고, 상세 로그는 서버 측에만 기록해야 합니다.",
		IsPotentiallyFalsePositive: false, // High confidence finding
	},
	"INFORMATION_LEAKAGE_DB_ERROR": {
		Title:                      "데이터베이스 에러 문자열 노출",
		Message:                    "응답 본문에서 데이터베이스 에러 관련 문자열이 발견되었습니다. 데이터베이스 구조나 쿼리 방식 등 내부 시스템 정보가 노출될 위험이 있습니다.",
		Fix:                        "SQL 예외나 데이터베이스 오류 메시지가 그대로 노출되지 않도록 예외 처리 로직을 강화하십시오. 사용자에게는 일반적인 오류 메시지만 반환해야 합니다.",
		IsPotentiallyFalsePositive: false, // High confidence finding
	},
	"INFORMATION_LEAKAGE_X_POWERED_BY": {
		Title:                      "X-Powered-By 헤더 노출",
		Message:                    "X-Powered-By 헤더를 통해 사용 중인 기술 스택('%s')이 노출되고 있습니다.",
		Fix:                        "X-Powered-By 헤더를 제거하여 사용 중인 기술 스택 정보 노출을 최소화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_SERVER_HEADER": {
		Title:                      "Server 헤더 노출",
		Message:                    "Server 헤더를 통해 웹 서버 정보('%s')가 노출되고 있습니다.",
		Fix:                        "Server 헤더를 제거하거나 일반적인 값으로 변경하여 웹 서버 정보 노출을 최소화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_FRAMEWORK_SIGNATURE": {
		Title:                      "프레임워크/서버 시그니처 노출",
		Message:                    "응답 본문에서 사용 중인 웹 프레임워크나 서버의 버전 정보 등 시그니처가 발견되었습니다. 공격자가 특정 버전에 대한 취약점을 찾아 공격할 수 있습니다.",
		Fix:                        "불필요한 프레임워크/서버 시그니처 정보를 응답에서 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"INFORMATION_LEAKAGE_DEBUG_META_ENDPOINT": {
		Title:                      "디버그/메타 엔드포인트 노출",
		Message:                    "민감한 정보가 포함될 수 있는 '%s' 엔드포인트가 노출되어 있습니다.",
		Fix:                        "운영 환경에서 디버그 및 메타 엔드포인트에 대한 접근을 제한하거나 비활성화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"JSON_UNEXPECTED_FIELD_INSERTION": {
		Title:                      "JSON 예상 외 필드 삽입 점검 (TODO)",
		Message:                    "JSON 요청에 예상되지 않은 필드를 삽입했을 때의 애플리케이션 처리 로직 검증이 필요합니다.",
		Fix:                        "JSON 요청 처리 시 허용된 필드만 파싱하고, 예상되지 않은 필드는 무시하거나 오류를 반환하도록 구성하십시오.",
		IsPotentiallyFalsePositive: true, // This is a TODO, so it's heuristic/tentative
	},
	"PARAMETER_POLLUTION_DETECTED": {
		Title:                      "파라미터 오염 (Parameter Pollution) 감지",
		Message:                    "파라미터 '%s'에 중복 값을 전송했을 때 응답 내용이 크게 변경되었습니다. 이는 파라미터 오염 취약점의 가능성을 나타냅니다.",
		Fix:                        "애플리케이션이 중복된 파라미터를 안전하게 처리하도록 구성하십시오 (예: 첫 번째 값만 사용, 모든 값 배열로 처리 등).",
		IsPotentiallyFalsePositive: true, // Heuristic based on response similarity
	},
	"PACKET_CONTENT_TYPE_MISMATCH": {
		Title:                      "Content-Type 헤더와 본문 불일치",
		Message:                    "응답 헤더의 Content-Type('%s')과 실제 본문 데이터의 형식('%s')이 일치하지 않습니다. 이는 MIME Sniffing 공격이나 파싱 오류를 유발할 수 있습니다.",
		Fix:                        "서버에서 올바른 Content-Type 헤더를 설정하고, 'X-Content-Type-Options: nosniff' 헤더를 적용하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_WWW_AUTHENTICATE_ON_200": {
		Title:                      "200 OK 응답에 인증 요구 헤더 존재",
		Message:                    "요청이 성공(200 OK)했음에도 불구하고 'WWW-Authenticate' 헤더가 존재합니다. 이는 인증 로직의 구성 오류일 수 있습니다.",
		Fix:                        "인증이 필요한 경우 401 Unauthorized 상태 코드를 사용하고, 그렇지 않은 경우 불필요한 인증 헤더를 제거하십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_CORS_BAD_COMBINATION": {
		Title:                      "불안전한 CORS 헤더 조합",
		Message:                    "Access-Control-Allow-Origin이 와일드카드('*')이면서 Access-Control-Allow-Credentials가 'true'로 설정되어 있습니다. (또는 허용되지 않는 다중 Origin)",
		Fix:                        "Credentials를 허용할 경우 명시적인 Origin을 지정하고 와일드카드를 사용하지 마십시오.",
		IsPotentiallyFalsePositive: false,
	},
	"PACKET_ACCEPT_IGNORED": {
		Title:                      "Accept 헤더 무시됨",
		Message:                    "클라이언트가 요청한 Accept 타입('%s')과 다른 Content-Type('%s')으로 응답했습니다. 콘텐츠 협상(Content Negotiation)이 제대로 동작하지 않을 수 있습니다.",
		Fix:                        "서버가 클라이언트의 Accept 헤더를 존중하여 적절한 포맷으로 응답하거나, 지원하지 않는 경우 406 Not Acceptable을 반환하도록 구성하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"BLIND_SQLI_TIME_BASED": {
		Title:                      "블라인드 SQL 인젝션 (시간 기반) 가능성",
		Message:                    "파라미터 '%s'에 시간 지연 페이로드를 주입했을 때, 서버 응답이 약 %d초 지연되었습니다. 이는 시간 기반 블라인드 SQL 인젝션에 취약할 수 있음을 나타냅니다.",
		Fix:                        "모든 데이터베이스 쿼리에 Prepared Statement(파라미터화된 쿼리)를 사용하고, 사용자 입력값을 검증하십시오. 특히 숫자 입력값도 문자열로 처리하여 쿼리에 직접 연결하지 마십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"OS_COMMAND_INJECTION_TIME_BASED": {
		Title:                      "OS 커맨드 인젝션 (시간 기반) 가능성",
		Message:                    "파라미터 '%s'에 시간 지연 페이로드를 주입했을 때, 서버 응답이 약 %d초 지연되었습니다. 이는 OS 커맨드 인젝션에 취약할 수 있음을 나타냅니다.",
		Fix:                        "외부 입력을 사용하여 시스템 명령어를 실행하지 마십시오. 반드시 필요한 경우, 허용된 명령어와 인자 목록(Whitelist)을 엄격하게 적용하고, 쉘 메타문자(;, |, &, ` 등)를 필터링하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_CALLBACK_DETECTED": {
		Title:                      "SSRF (Server-Side Request Forgery) 취약점 가능성",
		Message:                    "파라미터 '%s'에 외부 URL을 주입했을 때, 서버가 해당 URL의 콘텐츠를 가져오거나 응답이 변경되었습니다. 이는 서버가 사용자 입력 URL을 검증 없이 요청하고 있음을 나타냅니다.",
		Fix:                        "사용자가 입력한 URL에 대해 서버 측에서 요청을 보낼 때, 허용된 도메인/IP 목록(Whitelist)을 적용하고 내부 네트워크(Localhost, Private IP)로의 접근을 차단하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"SSRF_LOCAL_ACCESS_DETECTED": {
		Title:                      "SSRF 내부망(Localhost) 접근 감지",
		Message:                    "파라미터 '%s'를 통해 로컬 호스트(127.0.0.1:%d)의 서비스에 접근할 수 있습니다. 응답에서 '%s' 서비스의 특징이 발견되었습니다.",
		Fix:                        "서버에서 외부로 나가는 요청에 대해 내부 네트워크(127.0.0.0/8, 10.0.0.0/8 등)로의 접근을 차단(Deny List)하거나, 허용된 도메인만 접근 가능하도록(Allow List) 설정하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"INSECURE_DESERIALIZATION_SUSPECTED": {
		Title:                      "안전하지 않은 역직렬화 의심 (Serialized Data 감지)",
		Message:                    "파라미터 또는 쿠키 '%s'에서 직렬화된 데이터(Java, PHP, Python 등) 패턴이 감지되었습니다. 신뢰할 수 없는 데이터의 역직렬화는 RCE(원격 코드 실행)로 이어질 수 있습니다.",
		Fix:                        "신뢰할 수 없는 소스에서 온 데이터를 역직렬화하지 마십시오. 가능하다면 JSON과 같은 안전한 데이터 포맷을 사용하고, 역직렬화 시 타입 제약이나 서명을 통해 무결성을 검증하십시오.",
		IsPotentiallyFalsePositive: true,
	},
	"COMPONENT_OUTDATED_DETECTED": {
		Title:                      "오래되거나 취약한 컴포넌트 버전 감지",
		Message:                    "서버 헤더 또는 HTML 주석에서 오래된 버전의 소프트웨어 정보('%s')가 발견되었습니다. 이는 알려진 취약점(CVE)에 노출될 위험이 있습니다.",
		Fix:                        "사용 중인 소프트웨어 및 라이브러리를 최신 보안 패치가 적용된 버전으로 업데이트하고, 불필요한 버전 정보 노출을 설정에서 비활성화하십시오.",
		IsPotentiallyFalsePositive: false,
	},
}

// GetMessage retrieves the message details for a given finding ID.
// It returns a MessageDetail struct. If the ID is not found, it returns
// a default "message not found" struct.
func GetMessage(id string) MessageDetail {
	if msg, ok := messages[id]; ok {
		return msg
	}
	return MessageDetail{
		Title:                      "Message Not Found",
		Message:                    fmt.Sprintf("Message details for ID '%s' not found.", id),
		Fix:                        "Please check the message ID.",
		IsPotentiallyFalsePositive: true, // Default to true for unknown messages to be safe
	}
}
