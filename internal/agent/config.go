package agent

import (
	"os"
	"time"

	"github.com/stretchr/testify/assert/yaml"
)

// Configures the http.Client that will send stats to classifier
type HttpClient struct {
	Timeout   time.Duration `yaml:"timeout"`
	KeepAlive bool          `yaml:"keepAlive"`
}

type Config struct {
	ClassifierEndpoint string        `yaml:"classifierEndpoint"`
	Node               string        `yaml:"node"`
	StatsPollInterval  time.Duration `yaml:"statsPollInternval"`
	HttpClient         HttpClient    `yaml:"httpClient"`
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
