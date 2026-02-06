package ui

const AsciiArt = `

      :::::::::       :::::::::       :::::::: 
     :+:    :+:      :+:    :+:     :+:    :+: 
    +:+    +:+      +:+    +:+     +:+         
   +#++:++#+       +#++:++#:      +#++:++#++   
  +#+             +#+    +#+            +#+    
 #+#             #+#    #+#     #+#    #+#     
###             ###    ###      ########       
`

const (
	ColorReset  = "\033[0m"
	ColorGray   = "\033[90m" // Light gray
	ColorWhite  = "\033[97m" // White
	ColorRed    = "\033[91m" // Bright Red
	ColorGreen  = "\033[92m" // Bright Green
	ColorYellow = "\033[93m" // Bright Yellow

	// Severity-specific colors
	ColorInfo   = "\033[37m" // White/Light Gray for INFO
	ColorLow    = "\033[34m" // Blue for LOW
	ColorMedium = "\033[33m" // Yellow/Orange for MEDIUM
	ColorHigh   = "\033[31m" // Red for HIGH
)
