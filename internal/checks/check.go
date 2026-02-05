package checks

import "github.com/MOYARU/PRS/internal/report"

type Category string

const (
	CategoryNetwork         Category = "A. 네트워크 / 전송 계층"
	CategoryHTTPProtocol    Category = "B. HTTP / 프로토콜 설정"
	CategorySecurityHeaders Category = "C. 보안 헤더"
	CategoryAuthSession     Category = "D. 인증 / 세션"
	CategoryInputHandling   Category = "E. 입력 처리"
	CategoryAccessControl   Category = "F. 접근 제어"
	CategoryFileExposure    Category = "G. 파일 / 리소스 노출"
	CategoryInfrastructure  Category = "H. 서버 / 인프라 설정"
	CategoryAppLogic        Category = "I. 애플리케이션 로직"
	CategoryAPI             Category = "J. API 특화"
	CategoryClientSecurity  Category = "K. 클라이언트(브라우저) 보안"
	CategoryOps             Category = "L. 운영 / 배포 / 메타데이터"
)

type Check struct {
	ID          string
	Category    Category
	Title       string
	Description string
	Mode        ScanMode
	Run         func(*Context) ([]report.Finding, error)
}
