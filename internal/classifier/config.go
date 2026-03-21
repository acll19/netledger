package classifier

import (
	"os"

	"gopkg.in/yaml.v3"
)

type DirectClassification struct {
	Region string   `yaml:"region"`
	Zone   string   `yaml:"zone"`
	IPs    []string `yaml:"ips"`
}

type Destinations struct {
	InZone               []string               `yaml:"in-zone"`
	InRegion             []string               `yaml:"in-region"`
	CrossRegion          []string               `yaml:"cross-region"`
	Internet             []string               `yaml:"internet"`
	DirectClassification []DirectClassification `yaml:"direct-classification"`
}

type Config struct {
	Destinations Destinations `yaml:"destinations"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}
