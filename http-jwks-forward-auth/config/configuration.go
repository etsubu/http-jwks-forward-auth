package config

import (
	"context"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"sort"
	"time"
)

type Config struct {
	Jwt struct {
		JwksUrl            string `yaml:"jwks_url"`
		Alg                string `yaml:"algorithm"`
		Issuer             string `yaml:"issuer"`
		Audience           string `yaml:"audience"`
		TrimPrefixInScopes bool   `yaml:"trim_prefix"`
		RoleClaim          string `yaml:"role_claim"`
	} `yaml:"jwt"`
	Paths []struct {
		Path    string   `yaml:"path"`
		Scopes  []string `yaml:"scopes"`
		Methods []string `yaml:"methods"`
	} `yaml:"paths"`
}

type SyncedConfig struct {
	Config *Config
}

func CreateConfigSync() (*SyncedConfig, *context.CancelFunc) {
	config := SyncedConfig{Config: nil}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	path, present := os.LookupEnv("CONFIG_PATH")
	if !present {
		path = "config.yaml"
	}
	c, err := parseConfig(path)
	if err != nil {
		log.Fatal("Couldn't parse initial config")
	}
	config.Config = c

	// Run two operations: one in a different go routine
	go func() {
		lastModified := time.Time{}
		for {
			select {
			case <-ctx.Done():
				log.Println("Exiting config sync loop.")
				return
			default:
				// Check for modifications
				modified, err := os.Stat(path)
				if err != nil {
					log.Printf("Failed to stat config %s", err.Error())
				} else {
					if modified.ModTime().After(lastModified) {
						// read config
						c, err := parseConfig(path)
						if err == nil {
							log.Println("Updated config")
							config.Config = c
						}
						lastModified = modified.ModTime()
					}
				}
				time.Sleep(5 * time.Second)
			}
		}
	}()
	return &config, &cancel
}

func parseConfig(path string) (*Config, error) {
	t := Config{}
	bytes, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Failed to read file %s", err.Error())
		return nil, err
	}

	err = yaml.Unmarshal(bytes, &t)
	if err != nil {
		log.Printf("Failed to parse yaml %s", err.Error())
		return nil, err
	}
	// Sort paths by length is descending order
	sort.Slice(t.Paths, func(i, j int) bool {
		return len(t.Paths[i].Path) > len(t.Paths[j].Path)
	})
	return &t, nil
}
