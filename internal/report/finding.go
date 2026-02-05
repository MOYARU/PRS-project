package report

type Severity string

const (
	SeverityInfo   Severity = "INFO"
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Finding struct {
	ID       string
	Category string
	Severity Severity
	Title    string
	Message  string
	Fix      string
}
