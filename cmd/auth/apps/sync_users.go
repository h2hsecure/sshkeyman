package apps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"

	"github.com/spf13/cobra"
)

var SyncUserCmd = &cobra.Command{
	Use:   "sync",
	Short: "This tool sync users from related datasource to local computer",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)

		// Launch the application
		if err := SyncUser(c); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}
	},
}

func SyncUser(c chan os.Signal) error {
	cfg := domain.LoadConfig()

	keycloak := adapter.NewKeyCloakAdapter(cfg)
	backend, err := adapter.NewBoldDB(cfg.DBPath, false)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	userDetails, err := keycloak.FetchUsers(ctx)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}

	for _, userDetail := range userDetails {
		user, err := backend.ReadUser(ctx, userDetail.Username)

		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("backend read: %w", err)
		}

		if errors.Is(err, domain.ErrNotFound) {
			if cfg.Nss.Override {
				continue
			}
		}

		err = backend.CreateUser(ctx, user.User.Username, domain.KeyDto{
			SshKeys: []domain.SshKey{},
		})

		if err != nil {
			return fmt.Errorf("backend write: %w", err)
		}
	}

	return nil
}
