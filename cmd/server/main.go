package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
)

var rootCmd = &cobra.Command{
	Use:   "arqut-server",
	Short: "ArqTurn Server - TURN/STUN server with WebRTC signaling",
	Long: `ArqTurn Server is a self-contained server that combines:
- TURN/STUN server for NAT traversal
- WebRTC signaling via WebSocket
- Peer registry and session management
- REST API for peer management and credentials`,
	Run: func(cmd *cobra.Command, args []string) {
		// Default: run server
		runServer()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.yaml", "config file path")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
