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

var KeyCmd = &cobra.Command{
	Use:   "ssh_auth_keys [username]",
	Short: "ssh auth keys application to return related user's public key",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false})

		// Launch the application
		if err := AuthKey(c); err != nil {
			log.Err(err).Send()
			os.Exit(1)
		}
	},
}

func AuthKey(c chan os.Signal) error {
	if len(os.Args) == 0 {
		return fmt.Errorf("you should give username as a parameter")
	}

	username := os.Args[2]
	cfg := domain.LoadConfig()

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = fmt.Fprintf(conn, "GETSSHKEY %s\n", username)
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
		return fmt.Errorf("user not found")
	}

	var algo, key, name string

	if count, err := fmt.Sscanf(readStr, "OK %s %s %s", &algo, &key, &name); err != nil || count != 3 {
		return fmt.Errorf("internal")
	}

	fmt.Printf("%s %s %s\n", algo, key, name)
	return nil
}
