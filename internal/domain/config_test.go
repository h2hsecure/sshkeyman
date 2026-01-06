package domain_test

import (
	"testing"

	"github.com/h2hsecure/sshkeyman/internal/domain"
)

func TestConfigLoad(t *testing.T) {
	cfg := domain.LoadConfig()

	if cfg == nil {
		t.Fatalf("loading config error")
		return
	}

	if cfg.DBPath != "/var/lib/sshkeyman/user.db" {
		t.Fatalf("wrong db path: %s", cfg.DBPath)
	}
}
