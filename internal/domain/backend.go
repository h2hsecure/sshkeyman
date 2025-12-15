package domain

import (
	"context"
)

type UserDetail struct {
	Id           string
	Username     string
	Fullname     string
	SshPublicKey string
}

type TokenDetail struct {
	AuthToken string `json:"access_token"`
}

type Backend interface {
	FetchUser(ctx context.Context, username string) (UserDetail, error)
	FetchUsers(ctx context.Context) ([]UserDetail, error)
}
