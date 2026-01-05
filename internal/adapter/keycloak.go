package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/samber/lo"

	"github.com/h2hsecure/sshkeyman/internal/domain"
)

const (
	ServerTokenUrl       = "/auth/realms/%s/protocol/openid-connect/token"
	ServerUserDetailsUrl = "/auth/admin/realms/%s/users"
	ServerUserDetailUrl  = "/auth/admin/realms/%s/users/%s"
)

type KeyCloakAdapter struct {
	ClientId       string
	Server         string
	Realm          string
	AccessUser     string
	AccessPassword string

	resty *resty.Client
}

type keycloakUser struct {
	Id         string              `json:"id"`
	Username   string              `json:"username"`
	Attributes map[string][]string `json:"attributes"`
	FirstName  string              `json:"firstName"`
	LastName   string              `json:"lastName"`
}

func (k keycloakUser) sshKey() string {
	key, has := k.Attributes["ssh-key"]
	if !has {
		return ""
	}

	if len(key) != 1 {
		return ""
	}
	return key[0]
}

func NewKeyCloakAdapter(config *domain.Config) domain.Backend {
	return &KeyCloakAdapter{
		ClientId:       config.Keycloak.ClientId,
		Realm:          config.Keycloak.Realm,
		AccessUser:     config.Keycloak.Username,
		AccessPassword: config.Keycloak.Password,
		resty:          resty.New().SetTimeout(3 * time.Second).SetBaseURL(config.Keycloak.Server),
	}
}

func (a *KeyCloakAdapter) auth(ctx context.Context) (string, error) {
	var ret domain.TokenDetail

	formData := map[string]string{
		"client_id":  a.ClientId,
		"username":   a.AccessUser,
		"password":   a.AccessPassword,
		"grant_type": "password",
	}

	postUrl := fmt.Sprintf(ServerTokenUrl, a.Realm)

	res, err := a.resty.R().
		EnableTrace().
		SetContext(ctx).
		SetFormData(formData).
		SetResult(&ret).
		Post(postUrl)

	if res.IsError() {
		return "", fmt.Errorf("auth request (%s): %v code: %d", postUrl, res.Error(), res.StatusCode())
	}
	if err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}

	return ret.AuthToken, nil
}

func (a *KeyCloakAdapter) FetchUser(ctx context.Context, username string) (domain.UserDetail, error) {
	token, err := a.auth(ctx)
	if err != nil {
		return domain.UserDetail{}, fmt.Errorf("authentication: %w", err)
	}

	var ret []keycloakUser

	res, err := a.resty.R().
		EnableTrace().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", fmt.Sprintf("bearer %s", token)).
		SetQueryParam("username", username).
		SetQueryParam("exact", "true").
		SetResult(&ret).
		Get(fmt.Sprintf(ServerUserDetailsUrl, a.Realm))

	if res.IsError() {
		return domain.UserDetail{}, fmt.Errorf("fetch user: %v code: %d", res.Error(), res.StatusCode())
	}
	if err != nil {
		return domain.UserDetail{}, fmt.Errorf("fetch user: %w", err)
	}

	detail, _ := lo.Find(ret, func(item keycloakUser) bool {
		return item.Username == username
	})

	var userRet keycloakUser

	userResp, err := a.resty.R().
		EnableTrace().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", fmt.Sprintf("bearer %s", token)).
		SetQueryParam("username", username).
		SetQueryParam("exact", "true").
		SetResult(&userRet).
		Get(fmt.Sprintf(ServerUserDetailUrl, a.Realm, detail.Id))

	if userResp.IsError() {
		return domain.UserDetail{}, fmt.Errorf("fetch user: %v code: %d", res.Error(), userResp.StatusCode())
	}
	if err != nil {
		return domain.UserDetail{}, fmt.Errorf("fetch user: %w", err)
	}

	return domain.UserDetail{
		Id:           detail.Id,
		Username:     detail.Username,
		SshPublicKey: detail.sshKey(),
	}, nil
}

func (a *KeyCloakAdapter) FetchUsers(ctx context.Context) ([]domain.UserDetail, error) {
	token, err := a.auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication: %w", err)
	}

	var ret []keycloakUser

	res, err := a.resty.R().
		EnableTrace().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", fmt.Sprintf("bearer %s", token)).
		SetQueryParam("exact", "true").
		SetResult(&ret).
		Get(fmt.Sprintf(ServerUserDetailsUrl, a.Realm))

	if res.IsError() || err != nil {
		return []domain.UserDetail{}, fmt.Errorf("auth request: %w", err)
	}

	return lo.Map(ret, func(item keycloakUser, _ int) domain.UserDetail {
		return domain.UserDetail{
			Username:     item.Username,
			SshPublicKey: item.sshKey(),
			Fullname:     item.FirstName + " " + item.LastName,
		}
	}), nil
}
