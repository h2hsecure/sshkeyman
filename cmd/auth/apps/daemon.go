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
	"github.com/protosam/go-libnss/structs"
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
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: false})

		// Launch the application
		if err := NewDaemon(c); err != nil {
			log.Err(err).Send()
			os.Exit(1)
		}
	},
}

func NewDaemon(c chan os.Signal) error {
	cfg := domain.LoadConfig()

	_ = os.Remove(cfg.SocketPath)
	_ = os.Remove(cfg.ManagementSocketPath)

	l, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	mngntListen, err := net.Listen("unix", cfg.ManagementSocketPath)
	if err != nil {
		return fmt.Errorf("management listen: %v", err)
	}
	defer func() {
		_ = mngntListen.Close()
	}()

	// Correct permissions for NSS access
	if err := os.Chmod(cfg.SocketPath, 0o666); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Correct permissions for NSS access
	if err := os.Chmod(cfg.ManagementSocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	log.Info().Msg("myservice NSS daemon listening")

	db, err := adapter.NewBoldDB(cfg.DBPath, false)
	if err != nil {
		return fmt.Errorf("db open: %w", err)
	}

	keycloak := adapter.NewKeyCloakAdapter(cfg)

	srv := domain.NewService(cfg, db, keycloak)

	grp, ctx := errgroup.WithContext(context.Background())

	grp.Go(func() error {
		for {
			conn, err := l.Accept()
			if err != nil {
				return fmt.Errorf("accept: %w", err)
			}

			go handleConn(ctx, conn, srv)
		}
	})

	grp.Go(func() error {
		for {
			conn, err := mngntListen.Accept()
			if err != nil {
				return fmt.Errorf("mngntaccept: %w", err)
			}

			go handleManagementConn(ctx, conn, srv)
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

func handleManagementConn(ctx context.Context, conn net.Conn, srv domain.IService) {
	defer func() {
		_ = conn.Close()
	}()

	// Hard timeout: NSS must never block
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		log.Err(err).Msg("reading socket")
		return
	}

	line = strings.TrimSpace(line)
	fields := strings.Fields(line)

	log.Info().Str("command", fields[0]).Msg("handling")

	switch fields[0] {
	case "SETUSER":
		if len(fields) != 5 {
			log.Warn().Interface("params", fields).Msg("wrong data provided")
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		usernameOrId := fields[1]
		var keyDto domain.KeyDto

		keyDto.User = structs.Passwd{
			Username: usernameOrId,
			Password: "",
			UID:      500,
			Dir:      "/home/" + usernameOrId,
			Shell:    "/bin/bash",
			Gecos:    "test",
		}

		keyDto.SshKeys = append(keyDto.SshKeys, domain.SshKey{
			Aglo: fields[2],
			Key:  fields[3],
			Name: fields[4],
		})

		if err := srv.AddUser(ctx, keyDto); err != nil {
			log.Warn().Err(err).Msg("creating user")
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		_, _ = fmt.Fprint(conn, "OK\n")
	case "SYNC":
		err := srv.Sync(ctx)
		if err != nil {
			log.Err(err).Msg("syncing")
			_, _ = fmt.Fprint(conn, "NOTFOUND\n")
			return
		}

		_, _ = fmt.Fprint(conn, "OK\n")
	default:
		log.Warn().Interface("command", fields[0]).Msg("wrong request")
		_, _ = fmt.Fprint(conn, "NOTFOUND\n")
	}
}

func handleConn(ctx context.Context, conn net.Conn, srv domain.IService) {
	defer func() {
		_ = conn.Close()
	}()

	// Hard timeout: NSS must never block
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		log.Err(err).Msg("reading socket")
		return
	}

	line = strings.TrimSpace(line)
	fields := strings.Fields(line)

	log.Info().Str("command", fields[0]).Msg("handling")

	switch fields[0] {
	case "GETPWNAM":
		if len(fields) != 2 {
			log.Warn().Interface("params", fields).Msg("wrong data recieved")
			return
		}

		usernameOrId := fields[1]
		user, err := srv.FindUser(ctx, domain.WithUsername(usernameOrId))
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
		if len(fields) != 2 {
			log.Warn().Interface("params", fields).Msg("wrong data recieved")
			return
		}

		usernameOrId := fields[1]
		uid, _ := strconv.ParseUint(usernameOrId, 10, 32)
		user, err := srv.FindUser(ctx, domain.WithUserId(uint(uid)))
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			log.Err(err).Msg("fetch user has problem")
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
		if len(fields) != 2 {
			log.Warn().Interface("params", fields).Msg("wrong data recieved")
			return
		}

		usernameOrId := fields[1]
		keyDto, err := srv.FindUser(ctx, domain.WithUsername(usernameOrId))
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

	}
}
