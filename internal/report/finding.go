package report

type Severity string

const (
	SeverityInfo   Severity = "INFO"
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Confidence represents the level of certainty for a finding.
type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

type Finding struct {
	ID        string
	Category  string
	Severity  Severity
	Confidence Confidence // Added Confidence field
	Title     string
	Message   string
	Fix       string
	IsPotentiallyFalsePositive bool
}
