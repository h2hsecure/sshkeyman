package apps

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false})

		// Launch the application
		if err := SyncUser(c); err != nil {
			log.Err(err).Send()
			os.Exit(1)
		}
	},
}

func SyncUser(c chan os.Signal) error {
	cfg := domain.LoadConfig()

	conn, err := net.Dial("unix", cfg.ManagementSocketPath)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = fmt.Fprintf(conn, "SYNC\n")
	if err != nil {
		return fmt.Errorf("sent command")
	}

	buf := make([]byte, 1024)
	readCount, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read buf: %w", err)
	}

	readStr := string(buf[:readCount])

	if strings.Contains(readStr, "NOTFOUND") {
		return fmt.Errorf("snyc failed. take a look systemd daemon logs")
	}

	log.Info().Msg("sync completed")

	return nil
}
