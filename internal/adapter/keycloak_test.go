package adapter_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/docker/go-connections/nat"
	"github.com/h2hsecure/sshkeyman/internal/adapter"
	"github.com/h2hsecure/sshkeyman/internal/domain"
	keycloak "github.com/stillya/testcontainers-keycloak"
	"github.com/testcontainers/testcontainers-go"

	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	. "github.com/onsi/gomega"
)

var keycloakPort = 8080

func TestMain(m *testing.M) {
	defer func() {
		if err := recover(); err != nil {
			log.Error().Err(err.(error)).Send()
			os.Exit(-1)
		}
	}()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	tctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	keycloakContainer, err := keycloak.Run(tctx,
		"quay.io/keycloak/keycloak:21.1",
		testcontainers.WithWaitStrategy(wait.ForExposedPort()),
		testcontainers.WithLogger(&log.Logger),
		testcontainers.WithName("keycloak-test"),
		keycloak.WithContextPath("/auth"),
		keycloak.WithRealmImportFile("../../testdata/realm-export.json"),
		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
	if err != nil {
		panic(fmt.Errorf("keycloak run: %w", err))
	}

	port, err := keycloakContainer.MappedPort(tctx, nat.Port("8080/tcp"))
	if err != nil {
		panic(fmt.Errorf("keycloak port: %w", err))
	}
	keycloakPort = port.Int()
	code := m.Run()
	err = keycloakContainer.Stop(tctx, nil)
	if err != nil {
		panic(fmt.Errorf("keycloak stop: %w", err))
	}
	cancel()
	os.Exit(code)
}

func Test_keycloak_user(t *testing.T) {
	RegisterTestingT(t)
	k := adapter.NewKeyCloakAdapter(&domain.Config{
		Keycloak: domain.KeycloakConfig{
			Server:   fmt.Sprintf("http://localhost:%d", keycloakPort),
			ClientId: "admin-cli",
			Realm:    "test-realm",
			Username: "test-api-user",
			Password: "password",
		},
	})
	ctx := context.Background()
	user, err := k.FetchUser(ctx, "test-ssh-user")
	Expect(err).To(BeNil())
	Expect(user.Username).NotTo(BeEmpty())
}

func Test_keycloak_users(t *testing.T) {
	RegisterTestingT(t)
	k := adapter.NewKeyCloakAdapter(&domain.Config{
		Keycloak: domain.KeycloakConfig{
			Server:   fmt.Sprintf("http://localhost:%d", keycloakPort),
			ClientId: "admin-cli",
			Realm:    "test-realm",
			Username: "test-api-user",
			Password: "password",
		},
	})
	ctx := context.Background()
	user, err := k.FetchUsers(ctx)
	Expect(err).To(BeNil())
	Expect(user).NotTo(Equal(0))
}
