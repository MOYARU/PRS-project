package checks

import (
	context "github.com/MOYARU/PRS-project/internal/checks/context" // Import the dedicated context package with alias
	"github.com/MOYARU/PRS-project/internal/report"
)

type Category string

const (
	CategoryNetwork              Category = "A. 네트워크 / 전송 계층"
	CategoryHTTPProtocol         Category = "B. HTTP / 프로토콜 설정"
	CategorySecurityHeaders      Category = "C. 보안 헤더"
	CategoryAuthSession          Category = "D. 인증 / 세션"
	CategoryInputHandling        Category = "E. 입력 처리"
	CategoryAccessControl        Category = "F. 접근 제어"
	CategoryFileExposure         Category = "G. 파일 / 리소스 노출"
	CategoryInfrastructure       Category = "H. 서버 / 인프라 설정"
	CategoryAppLogic             Category = "I. 애플리케이션 로직"
	CategoryAPI                  Category = "J. API 특화"
	CategoryClientSecurity       Category = "K. 클라이언트(브라우저) 보안"
	CategoryOps                  Category = "L. 운영 / 배포 / 메타데이터"
	CategoryInformationLeakage   Category = "M. 정보 누출"  // New category for stack traces, DB errors, etc.
	CategoryAPISecurity          Category = "N. API 보안" // New category for Content-Type Confusion, Method Override, Rate Limit, JSON Field Insertion
	CategoryVulnerableComponents Category = "O. 취약한 컴포넌트 사용 (A06)"
	CategoryIntegrityFailures    Category = "P. 소프트웨어 및 데이터 무결성 실패 (A08)"
	CategorySSRF                 Category = "Q. 서버 측 요청 위조 (SSRF) (A10)"
)

type Check struct {
	ID          string
	Category    Category
	Title       string
	Description string
	Mode        context.ScanMode                                 // Use ScanMode from context package
	Run         func(*context.Context) ([]report.Finding, error) // Use Context from context package
}
