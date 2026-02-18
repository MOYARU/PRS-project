package version

const Value = "2.1.1"

func ScannerUserAgent() string {
	return "PRS/" + Value + " (defensive security scanner)"
}

func RepeaterUserAgent() string {
	return "PRS-Repeater/" + Value
}

func FuzzerUserAgent() string {
	return "PRS-Fuzzer/" + Value
}
