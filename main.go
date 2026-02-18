/*
Copyright (c) 2026 moyaru <rbffo@icloud.com>
*/

package main

import (
	"os"

	"github.com/MOYARU/prs/cmd"
	"github.com/MOYARU/prs/internal/app/ui"
	msges "github.com/MOYARU/prs/internal/messages"
)

func main() {
	// Interactive entry only: show language selector when no command args are provided.
	// Non-interactive execution defaults to English.
	if len(os.Args) == 1 {
		ui.SelectLanguage()
	} else {
		msges.SetLanguage(msges.LangEN)
	}
	cmd.Execute()
}
