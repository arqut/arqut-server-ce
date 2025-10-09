package main

import "os"

func main() {
	// Check for subcommand
	if len(os.Args) > 1 && os.Args[1] == "apikey" {
		handleAPIKeyCommand()
		return
	}

	// Default: run server
	runServer()
}
