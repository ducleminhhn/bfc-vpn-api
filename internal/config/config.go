package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Keycloak KeycloakConfig `mapstructure:"keycloak"`
	TOTP     TOTPConfig     `mapstructure:"totp"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	CORS     CORSConfig     `mapstructure:"cors"`
}

type ServerConfig struct {
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	HTTPS           bool          `mapstructure:"https"`
}

type DatabaseConfig struct {
	Host             string        `mapstructure:"host"`
	Port             int           `mapstructure:"port"`
	Name             string        `mapstructure:"name"`
	User             string        `mapstructure:"user"`
	Password         string        `mapstructure:"password"`
	MaxOpenConns     int           `mapstructure:"max_open_conns"`
	MaxIdleConns     int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime  time.Duration `mapstructure:"conn_max_lifetime"`
	StatementTimeout time.Duration `mapstructure:"statement_timeout"`
	SSLMode          string        `mapstructure:"ssl_mode"`
	SSLRootCert      string        `mapstructure:"ssl_root_cert"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	DB       int    `mapstructure:"db"`
	Password string `mapstructure:"password"`
	PoolSize int    `mapstructure:"pool_size"`
}

type KeycloakConfig struct {
	IssuerURL      string   `mapstructure:"issuer_url"`
	ClientID       string   `mapstructure:"client_id"`
	ClientSecret   string   `mapstructure:"client_secret"`
	RedirectURL    string   `mapstructure:"redirect_url"`
	Scopes         []string `mapstructure:"scopes"`
	TimeoutSeconds int      `mapstructure:"timeout_seconds"`
}

type TOTPConfig struct {
	Issuer        string `mapstructure:"issuer"`
	EncryptionKey string `mapstructure:"encryption_key"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type CORSConfig struct {
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	AllowedMethods []string `mapstructure:"allowed_methods"`
	AllowedHeaders []string `mapstructure:"allowed_headers"`
	MaxAge         int      `mapstructure:"max_age"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/bfc-vpn/")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("BFC")
	viper.BindEnv("database.password", "DB_PASSWORD")
	viper.BindEnv("redis.password", "REDIS_PASSWORD")
	viper.BindEnv("keycloak.client_secret", "KEYCLOAK_CLIENT_SECRET")
	viper.BindEnv("totp.encryption_key", "TOTP_ENCRYPTION_KEY")

	// Set defaults
	viper.SetDefault("keycloak.timeout_seconds", 10)
	viper.SetDefault("totp.issuer", "BFC-VPN")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Load from env if not in config
	if cfg.Database.Password == "" {
		cfg.Database.Password = os.Getenv("DB_PASSWORD")
	}
	if cfg.Redis.Password == "" {
		cfg.Redis.Password = os.Getenv("REDIS_PASSWORD")
	}
	if cfg.Keycloak.ClientSecret == "" {
		cfg.Keycloak.ClientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	}
	if cfg.TOTP.EncryptionKey == "" {
		cfg.TOTP.EncryptionKey = os.Getenv("TOTP_ENCRYPTION_KEY")
	}

	// CRITICAL: Validate required credentials
	if cfg.Database.Password == "" {
		return nil, fmt.Errorf("DB_PASSWORD environment variable is required")
	}
	if cfg.Redis.Password == "" {
		return nil, fmt.Errorf("REDIS_PASSWORD environment variable is required")
	}
	if cfg.Keycloak.ClientSecret == "" {
		return nil, fmt.Errorf("KEYCLOAK_CLIENT_SECRET environment variable is required")
	}
	if cfg.TOTP.EncryptionKey == "" {
		return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY environment variable is required")
	}

	// Default SSL mode
	if cfg.Database.SSLMode == "" {
		cfg.Database.SSLMode = "require"
	}

	// Default timeout
	if cfg.Keycloak.TimeoutSeconds == 0 {
		cfg.Keycloak.TimeoutSeconds = 10
	}

	// Default TOTP issuer
	if cfg.TOTP.Issuer == "" {
		cfg.TOTP.Issuer = "BFC-VPN"
	}

	return &cfg, nil
}

// DSN returns PostgreSQL connection string
func (c *DatabaseConfig) DSN() string {
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.Name, c.SSLMode,
	)
	if c.SSLRootCert != "" {
		dsn += "&sslrootcert=" + c.SSLRootCert
	}
	return dsn
}
