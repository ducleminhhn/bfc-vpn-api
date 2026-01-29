package repository

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bfc-vpn/api/internal/config"
)

type DB struct {
	Pool *pgxpool.Pool
}

func NewDB(ctx context.Context, cfg config.DatabaseConfig) (*DB, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	
	// Set connection timeout
	poolConfig.ConnConfig.ConnectTimeout = 10 * time.Second

	// Connection retry with backoff
	var pool *pgxpool.Pool
	var lastErr error
	
	for attempt := 1; attempt <= 5; attempt++ {
		slog.Info("Attempting database connection",
			slog.Int("attempt", attempt),
			slog.String("host", cfg.Host),
			slog.Int("port", cfg.Port),
		)
		
		pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			lastErr = err
			slog.Warn("Database pool creation failed",
				slog.Int("attempt", attempt),
				slog.Any("error", err))
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		
		// Pool created, try ping
		pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		pingErr := pool.Ping(pingCtx)
		cancel()
		
		if pingErr != nil {
			lastErr = pingErr
			pool.Close()
			pool = nil
			slog.Warn("Database ping failed",
				slog.Int("attempt", attempt),
				slog.Any("error", pingErr))
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		
		// Success - clear lastErr
		lastErr = nil
		break
	}
	
	if lastErr != nil {
		return nil, fmt.Errorf("connect after 5 attempts: %w", lastErr)
	}
	
	if pool == nil {
		return nil, fmt.Errorf("pool is nil after connection attempts")
	}

	slog.Info("Database connected",
		slog.String("host", cfg.Host),
		slog.Int("port", cfg.Port),
		slog.String("database", cfg.Name),
		slog.String("ssl_mode", cfg.SSLMode),
	)

	return &DB{Pool: pool}, nil
}

func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// SetTenant sets RLS context - MUST call before tenant-scoped queries
// Uses true parameter for PgBouncer transaction mode compatibility
func (db *DB) SetTenant(ctx context.Context, tenantID string) error {
	_, err := db.Pool.Exec(ctx,
		"SELECT set_config('app.current_tenant_id', $1, true)",
		tenantID)
	return err
}

func (db *DB) HealthCheck(ctx context.Context) error {
	var ok int
	return db.Pool.QueryRow(ctx, "SELECT 1").Scan(&ok)
}
