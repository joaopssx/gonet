package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gonet",
	Short: "gonet is a userspace TCP/IP stack",
	Long:  `A complete userspace TCP/IP stack implemented in Go using raw sockets and TUN devices.`,
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gonet networking stack",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Starting gonet...")
		// TODO: Initialize and start the networking stack
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of gonet",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gonet v0.1.0")
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
