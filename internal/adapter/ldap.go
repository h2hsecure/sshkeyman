package adapter

import (
	"context"
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"

	"github.com/h2hsecure/sshkeyman/internal/domain"
	"github.com/rs/zerolog/log"
)

// UserLogin struct represents the user credentials.
type UserLogin struct {
	Username string
	Password string
}

type LdapAdapter struct{}

func NewLdapAdapter(config *domain.Config) domain.Backend {
	return &LdapAdapter{}
}

func (a *LdapAdapter) FetchUser(ctx context.Context, username string) (domain.UserDetail, error) {
	conn, err := a.connect()
	if err != nil {
		return domain.UserDetail{}, fmt.Errorf("ldap connect: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", username),
		[]string{"dn"},
		nil,
	)

	searchResp, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("LDAP search failed for user %s, error details: %v", username, err)
		return domain.UserDetail{}, err
	}

	if len(searchResp.Entries) != 1 {
		log.Printf("User: %s not found or multiple entries found", username)
		err = fmt.Errorf("user: %s not found or multiple entries found", username)
		return domain.UserDetail{}, err
	}

	entry := searchResp.Entries[0]

	return domain.UserDetail{
		Username: entry.DN,
	}, nil
}

func (a *LdapAdapter) FetchUsers(ctx context.Context) ([]domain.UserDetail, error) {
	conn, err := a.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}

	searchRequest := ldap.NewSearchRequest(
		os.Getenv("LDAP_BASE_DN"),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"",
		[]string{"dn"},
		nil,
	)

	searchResp, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("LDAP search failed for users, error details: %v", err)
		return []domain.UserDetail{}, err
	}

	var ret []domain.UserDetail

	for _, entry := range searchResp.Entries {
		ret = append(ret, domain.UserDetail{Username: entry.DN})
	}

	return ret, nil
}

// Connect establishes a connection to the LDAP server.
func (a *LdapAdapter) connect() (*ldap.Conn, error) {
	conn, err := ldap.DialURL(os.Getenv("LDAP_ADDRESS"))
	if err != nil {
		log.Printf("LDAP connection failed, error details: %v", err)
		return nil, err
	}

	if err := conn.Bind(os.Getenv("BIND_USER"), os.Getenv("BIND_PASSWORD")); err != nil {
		log.Printf("LDAP bind failed while connecting, error details: %v", err)
		return nil, err
	}

	return conn, nil
}
