/*
Copyright © 2026 モヤル <rbffo@icloud.com>
*/

package main

import (
	"github.com/MOYARU/PRS-project/cmd"
	"github.com/MOYARU/PRS-project/internal/app/ui"
)

func main() {
	ui.SelectLanguage()
	cmd.Execute()
}
