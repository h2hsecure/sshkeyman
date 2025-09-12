package domain

import (
	"context"
)

type UserDetail struct {
	Username     string
	SshPublicKey string
}

type TokenDetail struct {
	AuthToken string
}

type Backend interface {
	FetchUser(ctx context.Context, username string) (UserDetail, error)
	FetchUsers(ctx context.Context) ([]UserDetail, error)
}
