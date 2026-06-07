package main

import (
	"fmt"
	"os"

	"github.com/joaopssx/gonet/internal/config"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gonet",
	Short: "gonet is a userspace TCP/IP stack",
	Long:  `A complete userspace TCP/IP stack implemented in Go using raw sockets and TUN devices.`,
}

var cfgPath string

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the gonet networking stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Starting gonet...")

		// Load config if provided
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Override with flags if explicitly set
		if cmd.Flags().Changed("mode") {
			cfg.Mode, _ = cmd.Flags().GetString("mode")
		}
		if cmd.Flags().Changed("device") {
			cfg.DeviceName, _ = cmd.Flags().GetString("device")
		}
		if cmd.Flags().Changed("ip") {
			cfg.DeviceIP, _ = cmd.Flags().GetString("ip")
		}
		if cmd.Flags().Changed("peer") {
			cfg.PeerIP, _ = cmd.Flags().GetString("peer")
		}
		if cmd.Flags().Changed("mtu") {
			cfg.MTU, _ = cmd.Flags().GetInt("mtu")
		}
		if cmd.Flags().Changed("log-level") {
			cfg.LogLevel, _ = cmd.Flags().GetString("log-level")
		}

		// Validate final configuration
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}

		// TODO: Initialize and start the networking stack
		fmt.Printf("Config loaded successfully: %+v\n", cfg)
		return nil
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
	startCmd.Flags().StringVarP(&cfgPath, "config", "c", "", "path to config file (YAML/JSON)")
	startCmd.Flags().String("mode", "tun", "networking mode: tun or raw")
	startCmd.Flags().String("device", "gonet0", "interface name")
	startCmd.Flags().String("ip", "", "device IP address")
	startCmd.Flags().String("peer", "", "peer IP address")
	startCmd.Flags().Int("mtu", 1500, "MTU of the interface")
	startCmd.Flags().String("log-level", "info", "log level: debug, info, warn, error")

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
