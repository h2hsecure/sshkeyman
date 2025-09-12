package adapter_test

import (
	"context"
	"testing"

	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	. "github.com/onsi/gomega"
	"github.com/protosam/go-libnss/structs"
)

const TMP_DB = "/tmp/user.db"

func TestCreateUser(t *testing.T) {
	RegisterTestingT(t)
	db, err := adapter.NewBoldDB(TMP_DB, false)
	Expect(err).To(BeNil())
	defer func() { _ = db.Close() }()
	err = db.CreateUser(context.Background(), "test", domain.KeyDto{
		User: structs.Passwd{
			Username: "test",
		},
		SshKeys: []domain.SshKey{
			{Aglo: "", Key: "", Name: ""},
		},
	})

	Expect(err).To(BeNil())
}

func TestReadUser(t *testing.T) {
	TestCreateUser(t)

	RegisterTestingT(t)
	db, err := adapter.NewBoldDB(TMP_DB, false)
	Expect(err).To(BeNil())
	user, err := db.ReadUser(context.Background(), "test")

	Expect(err).To(BeNil())
	Expect(user.User.Username).To(Equal("test"))
}
