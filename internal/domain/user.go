package domain

import (
	"context"

	nss "github.com/protosam/go-libnss/structs"
)

type KeyDto struct {
	User    nss.Passwd
	SshKeys []SshKey `json:"sshkeys"`
}

type SshKey struct {
	Aglo string `json:"algo"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type BoltDB interface {
	CreateUser(context.Context, string, KeyDto) error
	ReadUser(context.Context, string) (KeyDto, error)
	ReadUserById(context.Context, uint) (KeyDto, error)
	Close() error
}
