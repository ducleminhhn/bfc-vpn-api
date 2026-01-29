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
	DualAuth DualAuthConfig `mapstructure:"dual_auth"`
	Security SecurityConfig `mapstructure:"security"` // Story 2.7: Security settings
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

// SecurityConfig holds security-related configuration (Story 2.7)
type SecurityConfig struct {
	InternalServiceSecret string `mapstructure:"internal_service_secret"` // JWT secret for internal service-to-service calls
}

// DualAuthConfig holds dual auth configuration
type DualAuthConfig struct {
	Enabled                  bool   `mapstructure:"enabled"`
	HealthCheckIntervalSecs  int    `mapstructure:"health_check_interval_seconds"`
	FailureThreshold         int    `mapstructure:"failure_threshold"`
	RecoveryThreshold        int    `mapstructure:"recovery_threshold"`
	MaxFailoversPerHour      int    `mapstructure:"max_failovers_per_hour"`
	HealthCheckTimeoutSecs   int    `mapstructure:"health_check_timeout_seconds"`
	PasswordSyncIntervalMins int    `mapstructure:"password_sync_interval_minutes"`
	UseTLS                   bool   `mapstructure:"use_tls"`        // Use HTTPS for health checks
	TLSSkipVerify            bool   `mapstructure:"tls_skip_verify"` // Skip TLS certificate verification
	TLSCACertPath            string `mapstructure:"tls_ca_cert_path"` // Path to CA certificate
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
	viper.BindEnv("security.internal_service_secret", "INTERNAL_SERVICE_SECRET")

	// Set defaults
	viper.SetDefault("keycloak.timeout_seconds", 10)
	viper.SetDefault("totp.issuer", "BFC-VPN")

	// DualAuth defaults
	viper.SetDefault("dual_auth.enabled", true)
	viper.SetDefault("dual_auth.health_check_interval_seconds", 10)
	viper.SetDefault("dual_auth.failure_threshold", 3)
	viper.SetDefault("dual_auth.recovery_threshold", 3)
	viper.SetDefault("dual_auth.max_failovers_per_hour", 3)
	viper.SetDefault("dual_auth.health_check_timeout_seconds", 5)
	viper.SetDefault("dual_auth.password_sync_interval_minutes", 5)
	viper.SetDefault("dual_auth.use_tls", true) // Default to TLS for production
	viper.SetDefault("dual_auth.tls_skip_verify", false)

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
	if cfg.Security.InternalServiceSecret == "" {
		cfg.Security.InternalServiceSecret = os.Getenv("INTERNAL_SERVICE_SECRET")
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

	// Generate internal service secret if not provided (dev only)
	if cfg.Security.InternalServiceSecret == "" {
		cfg.Security.InternalServiceSecret = "dev-internal-secret-change-in-production"
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
