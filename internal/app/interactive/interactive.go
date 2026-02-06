package interactive

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/MOYARU/PRS-project/internal/app/scan"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	"github.com/spf13/cobra" // cobra import
)

// RunInteractiveMode starts the interactive mode of PRS.
func RunInteractiveMode(cmdObj *cobra.Command) { // Change signature
	fmt.Println(cmdObj.Long) // Use cmdObj.Long
	fmt.Printf("%s\nEntering interactive mode. Type 'help' for commands or 'exit' to quit.%s\n", ui.ColorGray, ui.ColorReset)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(ui.ColorGray + "\n> " + ui.ColorReset)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "exit" || input == "quit" {
			fmt.Printf("%sExiting PRS interactive mode. Goodbye!%s\n", ui.ColorGray, ui.ColorReset)
			break
		}

		if input == "help" {
			fmt.Printf("%sAvailable commands:%s\n", ui.ColorWhite, ui.ColorReset)
			fmt.Printf("%s  scan <target_url> [--active] [--crawler] [--depth N] [--json] [--html] [--delay MS]%s\n", ui.ColorGray, ui.ColorReset)
			fmt.Printf("%s  prs <target_url> ...%s\n", ui.ColorGray, ui.ColorReset) // Added prs alias to help
			fmt.Printf("%s  help%s\n", ui.ColorGray, ui.ColorReset)
			fmt.Printf("%s  exit / quit%s\n", ui.ColorGray, ui.ColorReset)
			continue
		}

		// Basic command parsing (will be improved later)
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]
		cmdArgs := parts[1:] // Use cmdArgs to avoid conflict with args from rootCmd.Run

		switch command {
		case "scan", "prs":
			if len(cmdArgs) == 0 {
				fmt.Printf("%sError: '%s' command requires a target URL.%s\n", ui.ColorRed, command, ui.ColorReset)
				continue
			}

			target := cmdArgs[0]

			// Parse flags for interactive scan
			active, jsonOut, htmlOut, crawl, depth, delay := parseScanFlags(cmdArgs[1:])

			err := scan.RunScan(target, active, crawl, depth, jsonOut, htmlOut, delay)
			if err != nil {
				fmt.Printf("%s Scan failed: %v%s\n", ui.ColorRed, err, ui.ColorReset)
			}
		default:
			fmt.Printf("%sError: Unknown command '%s'. Type 'help' for available commands.%s\n", ui.ColorRed, command, ui.ColorReset)
		}
	}
}

// parseScanFlags parses the command line arguments for --active and --i-own-this-site flags.
func parseScanFlags(args []string) (bool, bool, bool, bool, int, int) {
	active := false
	jsonOut := false
	htmlOut := false
	crawl := false
	depth := 2
	delay := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--active":
			active = true
		case "--json":
			jsonOut = true
		case "--html":
			htmlOut = true
		case "--crawler":
			crawl = true
		case "--depth":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					depth = d
					i++ // Skip next arg
				}
			}
		case "--delay":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					delay = d
					i++ // Skip next arg
				}
			}
		}
	}
	return active, jsonOut, htmlOut, crawl, depth, delay
}
