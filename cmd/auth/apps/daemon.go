package apps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var DaemonCmd = &cobra.Command{
	Use:   "server",
	Short: "Serve user database",
	Long:  AppDescription,
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// Listen for termination signal for gracefully shutdown
		c := make(chan os.Signal, 1)

		// Launch the application
		if err := NewDaemon(c); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}
	},
}

// Example backing store
type User struct {
	UID   uint32
	GID   uint32
	Home  string
	Shell string
}

func NewDaemon(c chan os.Signal) error {
	cfg := domain.LoadConfig()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	_ = os.Remove(cfg.SocketPath)

	l, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()
	// Correct permissions for NSS access
	if err := os.Chmod(cfg.SocketPath, 0o666); err != nil {
		return fmt.Errorf("chmod: %v", err)
	}

	log.Info().Msg("myservice NSS daemon listening")

	db, err := adapter.NewBoldDB(cfg.DBPath, true)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}

	grp, ctx := errgroup.WithContext(context.Background())

	grp.Go(func() error {
		for {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept: %w", err)
			}

			go handleConn(ctx, conn, db)
		}
	})

	grp.Go(func() error {
		ticker := time.NewTicker(1 * time.Minute)

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("closing")
			case <-ticker.C:
				err := SyncUser(c)
				if err != nil {
					return fmt.Errorf("sync: %w", err)
				}
			}
		}
	})

	grp.Go(func() error {
		s := <-c
		return fmt.Errorf("signal recieved: %v", s)
	})

	err = grp.Wait()
	if err != nil {
		log.Info().Msg("closing the app")
	}

	return nil
}

func handleConn(ctx context.Context, conn net.Conn, db domain.BoltDB) {
	defer func() {
		_ = conn.Close()
	}()
	log.Printf("handling connection")
	// Hard timeout: NSS must never block
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}

	line = strings.TrimSpace(line)
	fields := strings.Fields(line)

	if len(fields) != 2 {
		return
	}

	var user domain.KeyDto
	usernameOrId := fields[1]

	switch fields[0] {
	case "GETPWNAM":
		user, err = db.ReadUser(ctx, usernameOrId)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		if errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		_, _ = fmt.Fprintf(
			conn,
			"OK %s %d %d %s %s\n",
			user.User.Username,
			user.User.UID,
			user.User.GID,
			user.User.Dir,
			user.User.Shell,
		)
	case "GETPWUID":
		uid, _ := strconv.ParseUint(usernameOrId, 10, 32)
		user, err = db.ReadUserById(ctx, uint(uid))
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		if errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		_, _ = fmt.Fprintf(
			conn,
			"OK %s %d %d %s %s\n",
			user.User.Username,
			user.User.UID,
			user.User.GID,
			user.User.Dir,
			user.User.Shell,
		)
	case "GETSSHKEY":
		keyDto, err := db.ReadUser(ctx, usernameOrId)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		if errors.Is(err, domain.ErrNotFound) {
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		for _, key := range keyDto.SshKeys {
			_, _ = fmt.Fprintf(conn, "OK %s %s %s\n", key.Aglo, key.Key, key.Name)
		}
		return

	case "SETUSER":
	case "SYNC":
	default:
		_, _ = fmt.Fprint(conn, "NOTFOUND\n")
	}

}
