package interactive

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MOYARU/PRS-project/internal/app/scan"
	"github.com/MOYARU/PRS-project/internal/app/ui"
	msges "github.com/MOYARU/PRS-project/internal/messages"
	"github.com/spf13/cobra" // cobra import
	"golang.org/x/term"
)

// RunInteractiveMode starts the interactive mode of PRS.
func RunInteractiveMode(cmdObj *cobra.Command) {
	fmt.Println(cmdObj.Long)
	fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("InteractiveWelcome"), ui.ColorReset)

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to enter raw mode:", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	var cmdBuffer []byte
	history := []string{}
	historyIndex := 0

Loop:
	for {
		// Print prompt
		prompt := getPrompt()
		fmt.Print("\r\033[K" + prompt + string(cmdBuffer))

		// Read byte
		b := make([]byte, 1024)
		n, err := os.Stdin.Read(b)
		if err != nil {
			break
		}

		// Handle arrow keys + Escape sequence
		if n >= 3 && b[0] == 27 && b[1] == 91 {
			switch b[2] {
			case 65: // Up Arrow
				if historyIndex > 0 {
					historyIndex--
					cmdBuffer = []byte(history[historyIndex])
				}
			case 66: // Down Arrow
				if historyIndex < len(history)-1 {
					historyIndex++
					cmdBuffer = []byte(history[historyIndex])
				} else {
					historyIndex = len(history)
					cmdBuffer = []byte{}
				}
			case 68: // Left Arrow
				msges.SetLanguage(msges.LangKO)
			case 67: // Right Arrow
				msges.SetLanguage(msges.LangEN)
			}
			continue
		}

		// Handle other keys
		for i := 0; i < n; i++ {
			char := b[i]
			switch char {
			case 3: // Ctrl+C
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println()
				return
			case 13: // Enter
				term.Restore(int(os.Stdin.Fd()), oldState)
				fmt.Println()
				input := strings.TrimSpace(string(cmdBuffer))
				if len(input) > 0 {
					history = append(history, input)
					historyIndex = len(history)
				}
				cmdBuffer = []byte{}

				// Process command
				if processCommand(input) {
					return // Exit requested
				}
				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				continue Loop
			case 127, 8: // Backspace
				if len(cmdBuffer) > 0 {
					_, size := utf8.DecodeLastRune(cmdBuffer)
					cmdBuffer = cmdBuffer[:len(cmdBuffer)-size]
				}
			default:
				if char >= 32 {
					cmdBuffer = append(cmdBuffer, char)
				}
			}
		}
	}
}

func getPrompt() string {
	lang := "KO"
	if msges.CurrentLanguage == msges.LangEN {
		lang = "EN"
	}
	return fmt.Sprintf("%s[%s] > %s", ui.ColorGray, lang, ui.ColorReset)
}

func processCommand(input string) bool {

	// Handle exit commands
	if input == "exit" || input == "quit" {
		fmt.Printf("%s%s%s\n", ui.ColorGray, msges.GetUIMessage("InteractiveExit"), ui.ColorReset)
		return true
	}

	if input == "help" {
		fmt.Printf("%s%s%s\n", ui.ColorWhite, msges.GetUIMessage("InteractiveHelp"), ui.ColorReset)
		fmt.Printf("%s  scan <target_url> [--active] [--depth N] [--json] [--delay MS]%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  prs <target_url> ...%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  repeater <METHOD> <url> [body]%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  fuzz <url_with_FUZZ> <wordlist_path>%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  help%s\n", ui.ColorGray, ui.ColorReset)
		fmt.Printf("%s  exit / quit%s\n", ui.ColorGray, ui.ColorReset)
		return false
	}

	parts := strings.Fields(input)
	if len(parts) == 0 {
		return false
	}

	command := parts[0]
	cmdArgs := parts[1:]

	switch command {
	case "scan", "prs":
		if len(cmdArgs) == 0 {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveErrorTarget", command), ui.ColorReset)
			return false
		}

		target := cmdArgs[0]
		active, jsonOut, depth, delay := parseScanFlags(cmdArgs[1:])

		crawl := true // Always enabled

		htmlOut, err := ui.Confirm(msges.GetUIMessage("AskSaveHTML"))
		if err != nil {
			fmt.Println()
			return false
		}

		err = scan.RunScan(target, active, crawl, depth, jsonOut, htmlOut, delay)
		if err != nil {
			fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveScanFailed", err), ui.ColorReset)
		}
	case "repeater":
		handleRepeater(cmdArgs)
	case "fuzz":
		handleFuzzer(cmdArgs)
	default:
		fmt.Printf("%s%s%s\n", ui.ColorRed, msges.GetUIMessage("InteractiveErrorUnknown", command), ui.ColorReset)
	}
	return false
}

// flag parsing helper
func parseScanFlags(args []string) (bool, bool, int, int) {
	active := false
	jsonOut := false
	depth := 2
	delay := 0

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--active":
			active = true
		case "--json":
			jsonOut = true
		case "--depth":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					depth = d
					i++
				}
			}
		case "--delay":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					delay = d
					i++
				}
			}
		}
	}
	return active, jsonOut, depth, delay
}

func handleRepeater(args []string) {
	if len(args) < 2 {
		fmt.Printf("%sUsage: repeater <METHOD> <URL> [BODY]%s\n", ui.ColorRed, ui.ColorReset)
		return
	}
	method := strings.ToUpper(args[0])
	url := args[1]
	var body io.Reader
	if len(args) > 2 {
		bodyContent := strings.Join(args[2:], " ")
		body = strings.NewReader(bodyContent)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		fmt.Printf("%sError creating request: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}

	req.Header.Set("User-Agent", "PRS-Repeater/1.5.0")
	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("%sRequest failed: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	fmt.Printf("\n%s[%s] %s %s (%v)%s\n", ui.ColorGreen, method, resp.Status, url, duration, ui.ColorReset)
	for k, v := range resp.Header {
		fmt.Printf("%s%s: %s%s\n", ui.ColorGray, k, strings.Join(v, ", "), ui.ColorReset)
	}
	fmt.Println()

	bodyBytes, _ := io.ReadAll(resp.Body)
	fmt.Println(string(bodyBytes))
}

func handleFuzzer(args []string) {
	if len(args) < 2 {
		fmt.Printf("%sUsage: fuzz <URL_WITH_FUZZ> <WORDLIST_PATH>%s\n", ui.ColorRed, ui.ColorReset)
		return
	}
	targetURL := args[0]
	wordlistPath := args[1]

	if !strings.Contains(targetURL, "FUZZ") {
		fmt.Printf("%sError: URL must contain 'FUZZ' placeholder.%s\n", ui.ColorRed, ui.ColorReset)
		return
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		fmt.Printf("%sError opening wordlist: %v%s\n", ui.ColorRed, err, ui.ColorReset)
		return
	}
	defer file.Close()

	fmt.Printf("%sStarting Fuzzer on %s...%s\n", ui.ColorGreen, targetURL, ui.ColorReset)

	client := &http.Client{Timeout: 5 * time.Second}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" {
			continue
		}

		url := strings.Replace(targetURL, "FUZZ", word, -1)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("User-Agent", "PRS-Fuzzer/1.5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		color := ui.ColorWhite
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			color = ui.ColorGreen
		} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			color = ui.ColorInfo // Assuming ColorInfo exists (Blue/Cyan)
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			color = ui.ColorLow // Assuming ColorLow exists (Yellow/Orange)
		} else if resp.StatusCode >= 500 {
			color = ui.ColorRed
		}

		fmt.Printf("[%s%d%s] %s\n", color, resp.StatusCode, ui.ColorReset, url)
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("%sFuzzing completed.%s\n", ui.ColorGreen, ui.ColorReset)
}
