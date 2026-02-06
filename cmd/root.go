/*
Copyright © 2026 モヤル <rbffo@icloud.com>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/MOYARU/PRS-project/internal/app/interactive"
	"github.com/MOYARU/PRS-project/internal/app/scan"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"

	activeScan bool
	jsonOutput bool
	htmlOutput bool
	crawl      bool
	depth      int
	delay      int
)

var rootCmd = &cobra.Command{
	Use:   "prs [target]",
	Short: "PRS is a defensive-first web security scanner that identifies common vulnerabilities and misconfigurations including network, TLS, HTTP, security headers, authentication, session, file exposure, input handling, access control, and client-side security issues, without direct exploitation.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			interactive.RunInteractiveMode(cmd)
		} else {
			// One-shot execution for provided arguments
			target := args[0]
			err := scan.RunScan(target, activeScan, crawl, depth, jsonOutput, htmlOutput, delay)
			if err != nil {
				fmt.Printf("%s❌ Scan failed: %v%s\n", ui.ColorRed, err, ui.ColorReset)
				os.Exit(1)
			}
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
func init() {
	rootCmd.Flags().BoolVar(&activeScan, "active", false, "Enable active scan (disabled by default)")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")
	rootCmd.Flags().BoolVar(&htmlOutput, "html", false, "Output result as HTML")
	rootCmd.Flags().BoolVar(&crawl, "crawler", false, "Enable crawling to discover more pages")
	rootCmd.Flags().IntVar(&depth, "depth", 2, "Crawling depth (default: 2)")
	rootCmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests in milliseconds (e.g., 500)")
	// Mark flags as hidden if in interactive mode, or just don't set them for interactive.
	// For now, keep them as is.

	rootCmd.Long = ui.AsciiArt + `
PRS (Passive Reconnaissance Scanner) is a lightweight, defensive-first web security scanner.
It performs various checks to identify common vulnerabilities and misconfigurations in web applications and infrastructure.

Usage:
   prs [target_url] [flags]

Example:
  prs https://example.com
  prs https://example.com --crawler --depth 3
  prs https://example.com --active

Flags:
  --active             Enable active scan (disabled by default)
  --crawler            Enable crawling to discover more pages
  --depth              Crawling depth (default: 2)
  --json               Output result as JSON (not yet implemented)
  --html               Output result as HTML
  --delay              Delay between requests in milliseconds

This tool is intended for ethical hacking and security testing on assets you own or have explicit permission to test.
`
}
