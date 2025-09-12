package domain

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is base config in /etc/nss_external.conf
type Config struct {
	Nss      NSSConfig      `yaml:"nss"`
	Keycloak KeycloakConfig `yaml:"keycloak"`
	Home     string         `yaml:"home"`
	DBPath   string         `yaml:"db_path"`
	Shell    string         `yaml:"shell"`
}

type NSSConfig struct {
	MinUID   uint     `yaml:"minuid"`
	GroupIP  uint     `yaml:"groupid"`
	Override bool     `yaml:"override"`
	Suffix   []string `yaml:"suffix"`
}

type KeycloakConfig struct {
	Server   string `yaml:"server"`
	ClientId string `yaml:"client_id"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Realm    string `yaml:"realm"`
}

func LoadConfig() *Config {
	cfgfile, cfgErr := os.ReadFile("/etc/nss_external.conf")
	if cfgErr != nil {
		fmt.Printf("open config file, using defaults: %s\n", cfgErr.Error())
		cfg := Config{}
		cfg.Nss = NSSConfig{}
		cfg.Nss.GroupIP = 1000
		cfg.Nss.MinUID = 10000
		cfg.Home = "/home/%s"
		cfg.Shell = "/bin/bash"
		cfg.DBPath = "/tmp/users.db"
		return &cfg
	}
	config := Config{}
	cfgErr = yaml.Unmarshal([]byte(cfgfile), &config)
	if cfgErr != nil {
		fmt.Printf("open config file, using defaults: %s\n", cfgErr.Error())
	}
	// fmt.Fprintf(os.Stderr, "dump config: %v\n", config)
	return &config
}
