/*
Copyright © 2026 モヤル <rbffo@icloud.com>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/MOYARU/PRS/internal/checks"
	"github.com/MOYARU/PRS/internal/checks/scanner"
	"github.com/spf13/cobra"
)

const asciiArt = `

      :::::::::       :::::::::       :::::::: 
     :+:    :+:      :+:    :+:     :+:    :+: 
    +:+    +:+      +:+    +:+     +:+         
   +#++:++#+       +#++:++#:      +#++:++#++   
  +#+             +#+    +#+            +#+    
 #+#             #+#    #+#     #+#    #+#     
###             ###    ###      ########       
`

var (
	version = "0.1.0"

	activeScan bool
	confirmOwn bool
	jsonOutput bool
)

var rootCmd = &cobra.Command{
	Use:   "PRS [target]",
	Short: "PRS is a defensive-first web security scanner that identifies common vulnerabilities and misconfigurations including network, TLS, HTTP, security headers, authentication, session, file exposure, input handling, access control, and client-side security issues, without direct exploitation.",
	Long: asciiArt + `
PRS (Passive Reconnaissance Scanner) is a lightweight, defensive-first web security scanner.
It performs various checks to identify common vulnerabilities and misconfigurations in web applications and infrastructure.

Usage:
  PRS [target_url] [flags]

Example:
  PRS https://example.com
  PRS https://example.com --active --i-own-this-site

Flags:
  --active             Enable active scan (disabled by default)
  --i-own-this-site    Confirm you own or have permission to test the target (required for active scan)
  --json               Output result as JSON (not yet implemented)

This tool is intended for ethical hacking and security testing on assets you own or have explicit permission to test.
`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println(cmd.Long)
			os.Exit(0)
		}

		target := args[0]
		fmt.Println("Target:", target)

		if activeScan {
			fmt.Println("Mode: Active")
		} else {
			fmt.Println("Mode: Passive")
		}

		fmt.Println("Status: Ready to scan")

		mode := checks.Passive
		if activeScan {
			mode = checks.Active
		}

		scan := scanner.New(target, mode)
		findings, err := scan.Run()
		if err != nil {
			fmt.Println("❌ Failed to scan target:", err)
			os.Exit(1)
		}
		fmt.Println("✔ Scan completed")

		if len(findings) == 0 {
			fmt.Println("✔ No issues found")
		}

		for _, f := range findings {
			fmt.Printf("\n[%s] (%s) %s\n", f.Severity, f.Category, f.Title)
			fmt.Println(" →", f.Message)
			fmt.Println(" → Fix:", f.Fix)
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
	rootCmd.Flags().BoolVar(&confirmOwn, "i-own-this-site", false, "Confirm you own or have permission to test the target")
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output result as JSON")
}
