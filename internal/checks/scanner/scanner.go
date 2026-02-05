package scanner

import (
	"fmt"
	"time"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/checks/registry"
	"github.com/MOYARU/PRS/internal/engine"
	"github.com/MOYARU/PRS/internal/report"
)

type Scanner struct {
	Target string
	Mode   checks.ScanMode
	Checks []checks.Check
}

func New(target string, mode checks.ScanMode) *Scanner {
	return &Scanner{
		Target: target,
		Mode:   mode,
		Checks: registry.DefaultChecks(),
	}
}

func (s *Scanner) Run() ([]report.Finding, error) {
	result, err := engine.Fetch(s.Target)
	if err != nil {
		return nil, err
	}
	if result.Response == nil {
		return nil, fmt.Errorf("no response received")
	}

	defer result.Response.Body.Close()

	ctx := &checks.Context{
		Target:            s.Target,
		Mode:              s.Mode,
		InitialURL:        result.InitialURL,
		FinalURL:          result.FinalURL,
		Response:          result.Response,
		RedirectTarget:    result.RedirectTarget,
		Redirected:        result.Redirected,
		RedirectedToHTTPS: result.RedirectedToHTTPS,
	}

	var findings []report.Finding
	for _, check := range s.Checks {
		if s.Mode == checks.Passive && check.Mode == checks.Active {
			continue
		}

		fmt.Printf(" [~] Scanning %s...\r", check.Title)
		time.Sleep(time.Second + time.Duration(time.Now().Nanosecond())%time.Second) // 1-2 second random delay
		
		results, err := check.Run(ctx)
		if err != nil {
			// Clear the scanning message if an error occurs
			fmt.Print("                                \r") // Clear line
			return nil, err
		}
		
		// Clear the scanning message after check completes
		fmt.Print("                                \r") // Clear line

		findings = append(findings, results...)
	}

	return findings, nil
}
