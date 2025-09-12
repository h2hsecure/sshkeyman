package adapter

import (
	"context"
	"fmt"

	"github.com/go-resty/resty/v2"

	"github.com/h2hsecure/sshkeyman/internal/domain"
)

const (
	ServerTokenUrl      = "%s/auth/realms/%s/protocol/openid-connect/token"
	ServerUserDetailUrl = "%s/auth/admin/realms/%s/users"
)

type KeyCloakAdapter struct {
	ClientId string
	Server   string
	Realm    string
}

func NewKeyCloakAdapter(config *domain.Config) domain.Backend {
	return &KeyCloakAdapter{}
}

func (a *KeyCloakAdapter) auth(ctx context.Context, username string) (string, error) {
	var ret domain.TokenDetail

	formData := map[string]string{
		"client_id":  a.ClientId,
		"username":   username,
		"password":   "",
		"grant_type": "password",
	}

	res, err := resty.New().R().
		EnableTrace().
		SetContext(ctx).
		SetFormData(formData).
		SetResult(&ret).
		Post(fmt.Sprintf(ServerTokenUrl, a.Server, a.Realm))

	if res.IsError() || err != nil {
		return "", fmt.Errorf("auth request: %w", err)
	}

	return ret.AuthToken, nil
}

func (a *KeyCloakAdapter) FetchUser(ctx context.Context, username string) (domain.UserDetail, error) {
	token, err := a.auth(ctx, username)
	if err != nil {
		return domain.UserDetail{}, fmt.Errorf("authentication: %w", err)
	}

	var ret domain.UserDetail

	res, err := resty.New().R().
		EnableTrace().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", fmt.Sprintf("bearer %s", token)).
		SetQueryParam("username", username).
		SetQueryParam("exact", "true").
		SetResult(&ret).
		Get(fmt.Sprintf(ServerUserDetailUrl, a.Server, a.Realm))

	if res.IsError() || err != nil {
		return domain.UserDetail{}, fmt.Errorf("auth request: %w", err)
	}

	return ret, nil
}

func (a *KeyCloakAdapter) FetchUsers(ctx context.Context) ([]domain.UserDetail, error) {
	token, err := a.auth(ctx, "username")
	if err != nil {
		return nil, fmt.Errorf("authentication: %w", err)
	}

	var ret []domain.UserDetail

	res, err := resty.New().R().
		EnableTrace().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", fmt.Sprintf("bearer %s", token)).
		SetQueryParam("exact", "true").
		SetResult(&ret).
		Get(fmt.Sprintf(ServerUserDetailUrl, a.Server, a.Realm))

	if res.IsError() || err != nil {
		return []domain.UserDetail{}, fmt.Errorf("auth request: %w", err)
	}

	return ret, nil
}
