package apps

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/h2hsecure/sshkeyman/internal/domain"
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

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("Dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	_, err = fmt.Fprintf(conn, "GETSSHKEY %s", username)

	if err != nil {
		fmt.Fprintf(os.Stderr, "read user: %s\n", err.Error())
		os.Exit(1)
	}

	buf := make([]byte, 1024)
	readCound, err := conn.Read(buf)

	if err != nil {
		fmt.Fprintf(os.Stderr, "read user: %s\n", err.Error())
		os.Exit(1)
	}

	readStr := string(buf[:readCound])

	if strings.Contains(readStr, "NOTFOUND") {
		fmt.Fprintf(os.Stderr, "user not found: %s\n", err.Error())
		os.Exit(2)
	}

	var algo, key, name string

	if count, err := fmt.Sscanf(readStr, "OK %s %s %s", algo, key, name); err != nil || count != 3 {
		fmt.Fprintf(os.Stderr, "internal: %s\n", err.Error())
		os.Exit(2)
	}

	fmt.Printf("%s %s %s\n", algo, key, name)
	return nil
}
