package domain

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is base config in /etc/nss_sshkeyman.conf
type Config struct {
	Nss        NSSConfig      `yaml:"nss"`
	Keycloak   KeycloakConfig `yaml:"keycloak"`
	Home       string         `yaml:"home"`
	DBPath     string         `yaml:"db_path"`
	SocketPath string         `yaml:"socket_path"`
}

type NSSConfig struct {
	MinUID   uint     `yaml:"minuid"`
	GroupID  uint     `yaml:"groupid"`
	Override bool     `yaml:"override"`
	Suffix   []string `yaml:"suffix"`
	Shell    string   `yaml:"shell"`
}

type KeycloakConfig struct {
	Server   string `yaml:"server"`
	ClientId string `yaml:"client_id"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Realm    string `yaml:"realm"`
}

func LoadConfig() *Config {
	cfgfile, cfgErr := os.ReadFile("/etc/nss_sshkeyman.conf")
	if cfgErr != nil {
		fmt.Printf("open config file, using defaults: %s\n", cfgErr.Error())
		cfg := Config{}
		cfg.Nss = NSSConfig{}
		cfg.Nss.GroupID = 1000
		cfg.Nss.MinUID = 10000
		cfg.Nss.Override = true
		cfg.Home = "/home/%s"
		cfg.Nss.Shell = "/bin/bash"
		cfg.DBPath = "/tmp/users.db"
		cfg.SocketPath = "/var/lib/sshkeyman/daemon.sock"
		return &cfg
	}
	config := Config{}
	cfgErr = yaml.Unmarshal([]byte(cfgfile), &config)
	if cfgErr != nil {
		fmt.Printf("open config file, using defaults: %s\n", cfgErr.Error())
	}

	return &config
}
