package main

import (
	"os"

	"github.com/h2hsecure/sshkeyman/cmd/auth/apps"
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	cfgFile string

	rootCmd = &cobra.Command{
		Use:   "sshkeyman",
		Short: "Keycloak Authentication Command for linux",
		Long:  apps.AppDescription,
	}
)

func main() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "/etc/nss_external.yaml", "config file (default is /etc/nss_external.yaml)")
	rootCmd.PersistentFlags().StringP("author", "a", "Auth Keycloak", "author name for copyright attribution")

	rootCmd.AddCommand(apps.KeyCmd)
	rootCmd.AddCommand(apps.SyncUserCmd)
	rootCmd.AddCommand(apps.NewUserCmd)

	if err := rootCmd.Execute(); err != nil {
		// fmt.Fprintf(os.Stderr, "run failed: %s\n", err.Error())
		os.Exit(2)
	}
}
