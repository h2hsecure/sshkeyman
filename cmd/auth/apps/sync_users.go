package apps

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/protosam/go-libnss/structs"
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

		// Launch the application
		if err := SyncUser(c); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err.Error())
			os.Exit(1)
		}
	},
}

func SyncUser(c chan os.Signal) error {
	cfg := domain.LoadConfig()

	backend, err := adapter.NewBoldDB(cfg.DBPath, false)
	if err != nil {
		return err
	}

	return SyncUserInDB(cfg, backend)
}

func SyncUserInDB(cfg *domain.Config, backend domain.BoltDB) error {
	keycloak := adapter.NewKeyCloakAdapter(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	defer cancel()

	userDetails, err := keycloak.FetchUsers(ctx)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}

	for _, userDetail := range userDetails {

		if userDetail.SshPublicKey == "" {
			continue
		}
		_, err := backend.ReadUser(ctx, userDetail.Username)

		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("backend read: %w", err)
		}

		if err == nil {
			if !cfg.Nss.Override {
				log.Warn().Err(err).Str("user", userDetail.Username).Msgf("override disabled")
				continue
			}
		}

		log.Info().Str("user", userDetail.Username).Msgf("creating")

		key := strings.Split(userDetail.SshPublicKey, " ")
		if len(key) != 3 {
			log.Error().Str("user", userDetail.Username).Msg("key format error")
		}

		err = backend.CreateUser(ctx, userDetail.Username, domain.KeyDto{
			User: structs.Passwd{
				Username: userDetail.Username,
				UID:      cfg.Nss.MinUID + hash(userDetail.Id),
				GID:      cfg.Nss.GroupID,
				Dir:      fmt.Sprintf(cfg.Home, userDetail.Username),
				Shell:    cfg.Nss.Shell,
				Gecos:    userDetail.Fullname,
			},
			SshKeys: []domain.SshKey{
				{
					Aglo: key[0],
					Key:  key[1],
					Name: key[2],
				},
			},
		})
		if err != nil {
			return fmt.Errorf("backend write: %w", err)
		}
	}

	return nil
}

func hash(s string) uint {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(s))
	if err != nil {
		return 0
	}
	md := hasher.Sum(nil)
	i := big.NewInt(0).SetBytes(md)
	return i.Bit(32)
}
