package apps

import (
	"context"
	"fmt"
	"os"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/protosam/go-libnss/structs"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var NewUserCmd = &cobra.Command{
	Use:   "new [user] [key]",
	Short: "Create new user record for ssh keys database",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)

		// Launch the application
		if err := NewUser(c); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}
	},
}

func NewUser(c chan os.Signal) error {
	if len(os.Args) == 2 {
		panic("you should give username as a parameter")
	}

	username := os.Args[2]

	cfg := domain.LoadConfig()

	db, err := adapter.NewBoldDB(cfg.DBPath, false)
	if err != nil {
		return err
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Warn().Err(err).Msgf("db close")
		}
	}()

	var keyDto domain.KeyDto

	keyDto.User = structs.Passwd{
		Username: username,
		Password: "",
		UID:      500,
		Dir:      "/home/" + username,
		Shell:    "/bin/bash",
		Gecos:    "test",
	}

	keyDto.SshKeys = append(keyDto.SshKeys, domain.SshKey{
		Aglo: os.Args[3],
		Key:  os.Args[4],
		Name: os.Args[5],
	})

	if err := db.CreateUser(context.Background(), username, keyDto); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}
