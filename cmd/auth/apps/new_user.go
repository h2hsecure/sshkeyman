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

var NewUserCmd = &cobra.Command{
	Use:   "new [user] [key]",
	Short: "Create new user record for ssh keys database",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(5),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false})

		// Launch the application
		if err := NewUser(args, c); err != nil {
			log.Err(err).Interface("args", args).Send()
			os.Exit(1)
		}
	},
}

func NewUser(args []string, c chan os.Signal) error {
	cfg := domain.LoadConfig()

	conn, err := net.Dial("unix", cfg.ManagementSocketPath)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	// r := bufio.NewWriter(conn)
	//fmt.Fprintf(os.Stderr, "SETUSER %s %s %s %s\n", args[0], args[1], args[2], args[3])
	//_, err = fmt.Fprintf(r, "SETUSER %s\n", os.Args[2])
	count, err := fmt.Fprintf(conn, "SETUSER %s %s %s %s \n", args[0], args[1], args[2], args[3])
	if err != nil {
		return fmt.Errorf("sent command")
	}

	buf := make([]byte, 1024)
	readCount, err := conn.Read(buf[:])
	if err != nil {
		return fmt.Errorf("read buf count: %d path: %s : %w", count, cfg.SocketPath, err)
	}

	readStr := string(buf[0:readCount])

	if strings.Contains(readStr, "NOTFOUND") {
		return fmt.Errorf("user not found")
	}

	log.Info().Str("username", args[0]).Msg("created")

	return nil
}
