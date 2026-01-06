package domain

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/protosam/go-libnss/structs"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
)

type Service struct {
	db       BoltDB
	keycloak Backend
	cfg      *Config
}

type SearchUser struct {
	username *string
	userId   *uint
}

type SearchUserOp func(*SearchUser)

func WithUsername(username string) SearchUserOp {
	return func(su *SearchUser) {
		su.username = lo.ToPtr(username)
	}
}

func WithUserId(userId uint) SearchUserOp {
	return func(su *SearchUser) {
		su.userId = lo.ToPtr(userId)
	}
}

type IService interface {
	FindUser(context.Context, ...SearchUserOp) (KeyDto, error)
	AddUser(context.Context, KeyDto) error
	Sync(context.Context) error
}

func NewService(cfg *Config, db BoltDB, keycloak Backend) IService {
	return &Service{
		db:       db,
		keycloak: keycloak,
		cfg:      cfg,
	}
}

// User implements IService.
func (s *Service) FindUser(ctx context.Context, ops ...SearchUserOp) (KeyDto, error) {
	var su SearchUser

	for _, op := range ops {
		op(&su)
	}
	switch {
	case su.username != nil:
		return s.db.ReadUser(ctx, *su.username)
	case su.userId != nil:
		return s.db.ReadUserById(ctx, uint(*su.userId))
	default:
		return KeyDto{}, ErrNotFound
	}
}

// AddUser implements IService.
func (s *Service) AddUser(ctx context.Context, user KeyDto) error {
	user.User.UID = s.cfg.Nss.MinUID + uint(hash(user.User.Username))
	user.User.GID = s.cfg.Nss.GroupID
	user.User.Dir = fmt.Sprintf(s.cfg.Home, user.User.Username)
	user.User.Password = "x"
	user.User.Gecos = user.User.Username

	if user.User.Shell == "" {
		user.User.Shell = s.cfg.Nss.Shell
	}
	if err := s.db.CreateUser(ctx, user.User.Username, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	log.Info().Str("user", user.User.Username).Msg("creating")

	return nil
}

// Sync implements IService.
func (s *Service) Sync(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)

	defer cancel()

	userDetails, err := s.keycloak.FetchUsers(ctx)
	if err != nil {
		return fmt.Errorf("fetch user: %w", err)
	}

	for _, userDetail := range userDetails {

		if userDetail.SshPublicKey == "" {
			continue
		}
		_, err := s.db.ReadUser(ctx, userDetail.Username)

		if err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("backend read: %w", err)
		}

		if err == nil {
			if !s.cfg.Nss.Override {
				log.Warn().Err(err).Str("user", userDetail.Username).Msgf("override disabled")
				continue
			}
		}

		log.Info().Str("user", userDetail.Username).Msgf("creating")

		key := strings.Split(userDetail.SshPublicKey, " ")
		if len(key) != 3 {
			log.Error().Str("user", userDetail.Username).Msg("key format error")
		}

		err = s.db.CreateUser(ctx, userDetail.Username, KeyDto{
			User: structs.Passwd{
				Username: userDetail.Username,
				UID:      s.cfg.Nss.MinUID + uint(hash(userDetail.Id)),
				GID:      s.cfg.Nss.GroupID,
				Dir:      fmt.Sprintf(s.cfg.Home, userDetail.Username),
				Shell:    s.cfg.Nss.Shell,
				Gecos:    userDetail.Fullname,
			},
			SshKeys: []SshKey{
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

func hash(s string) uint32 {
	hash := sha256.Sum256([]byte(s))
	// Take first 8 bytes for uint64
	u64 := binary.BigEndian.Uint64(hash[:8])
	return uint32(u64)
}
