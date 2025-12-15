package apps

import (
	"context"
	"fmt"
	"os"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var KeyCmd = &cobra.Command{
	Use:   "ssh_auth_keys [username]",
	Short: "ssh auth keys application to return related user's public key",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)

		// Launch the application
		if err := KeyCommand(context.Background(), c); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}
	},
}

func KeyCommand(ctx context.Context, c chan os.Signal) error {
	if len(os.Args) == 0 {
		panic("you should give username as a parameter")
	}

	username := os.Args[2]
	cfg := domain.LoadConfig()

	db, err := adapter.NewBoldDB(cfg.DBPath, true)
	if err != nil {
		return err
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Warn().Err(err).Msgf("db close")
		}
	}()

	keyDto, err := db.ReadUser(ctx, username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read user: %s\n", err.Error())
	}

	for _, key := range keyDto.SshKeys {
		fmt.Printf("%s %s %s\n", key.Aglo, key.Key, key.Name)
	}
	return nil
}
