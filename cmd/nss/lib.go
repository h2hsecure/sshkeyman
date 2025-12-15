package main

import (
	"context"
	"errors"
	"strings"

	"github.com/h2hsecure/sshkeyman/internal/adapter"

	"github.com/h2hsecure/sshkeyman/internal/domain"
	nss "github.com/protosam/go-libnss"
	nssStructs "github.com/protosam/go-libnss/structs"
	"github.com/rs/zerolog/log"
)

func main() {}

func init() {
	nss.SetImpl(LibNssSshKeyMan{})
}

type LibNssSshKeyMan struct{ nss.LIBNSS }

func (libnss LibNssSshKeyMan) PasswdAll() (nss.Status, []nssStructs.Passwd) {
	return nss.StatusSuccess, []nssStructs.Passwd{}
}

func (libnss LibNssSshKeyMan) PasswdByName(name string) (nss.Status, nssStructs.Passwd) {
	cfg := domain.LoadConfig()
	// Accept only for usernames ending with @XXX XXX defined in config
	for _, suffix := range cfg.Nss.Suffix {
		if !strings.HasSuffix(name, suffix) {
			return nss.StatusNotfound, nssStructs.Passwd{}
		}
	}

	db, err := adapter.NewBoldDB(cfg.DBPath, true)
	if err != nil {
		return nss.StatusTryagain, nssStructs.Passwd{}
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Warn().Err(err).Msgf("db close")
		}
	}()

	user, err := db.ReadUser(context.Background(), name)

	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nss.StatusTryagain, nssStructs.Passwd{}
	}

	if errors.Is(err, domain.ErrNotFound) {
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	return nss.StatusSuccess, mapUserDetailToPsaswd(user)
}

// PasswdByUid returns a single entry by uid.
func (libnss LibNssSshKeyMan) PasswdByUid(uid uint) (nss.Status, nssStructs.Passwd) {
	// fmt.Printf("PasswdByUid %d skip\n", uid)
	cfg := domain.LoadConfig()
	db, err := adapter.NewBoldDB(cfg.DBPath, true)
	if err != nil {
		return nss.StatusTryagain, nssStructs.Passwd{}
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Warn().Err(err).Msgf("db close")
		}
	}()

	user, err := db.ReadUserById(context.Background(), uid)

	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nss.StatusTryagain, nssStructs.Passwd{}
	}

	if errors.Is(err, domain.ErrNotFound) {
		return nss.StatusNotfound, nssStructs.Passwd{}
	}

	return nss.StatusSuccess, mapUserDetailToPsaswd(user)
}

// GroupAll returns all groups, not managed here
func (libnss LibNssSshKeyMan) GroupAll() (nss.Status, []nssStructs.Group) {
	// fmt.Printf("GroupAll\n")
	return nss.StatusSuccess, []nssStructs.Group{}
}

// GroupByName returns a group, not managed here
func (libnss LibNssSshKeyMan) GroupByName(name string) (nss.Status, nssStructs.Group) {
	// fmt.Printf("GroupByName %s\n", name)
	return nss.StatusNotfound, nssStructs.Group{}
}

// GroupBuGid retusn group by id, not managed heresSS
func (libnss LibNssSshKeyMan) GroupByGid(gid uint) (nss.Status, nssStructs.Group) {
	// fmt.Printf("GroupByGid %d\n", gid)
	return nss.StatusNotfound, nssStructs.Group{}
}

// //////////////////////////////////////////////////////////////
// Shadow Methods
// //////////////////////////////////////////////////////////////
// ShadowAll return all shadow entries, not managed as no password are allowed here
func (libnss LibNssSshKeyMan) ShadowAll() (nss.Status, []nssStructs.Shadow) {
	// fmt.Printf("ShadowAll\n")
	return nss.StatusSuccess, []nssStructs.Shadow{}
}

// ShadowByName return shadow entry, not managed as no password are allowed here
func (libnss LibNssSshKeyMan) ShadowByName(name string) (nss.Status, nssStructs.Shadow) {
	// fmt.Printf("ShadowByName %s\n", name)
	return nss.StatusNotfound, nssStructs.Shadow{}
}

func mapUserDetailToPsaswd(user domain.KeyDto) nssStructs.Passwd {
	return user.User
}
