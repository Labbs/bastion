package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upHost, downHost)
}

func upHost(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS host (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			hostname TEXT NOT NULL,
			port INTEGER DEFAULT 22,
			username TEXT NOT NULL,
			auth_method TEXT CHECK(auth_method IN ('password', 'key', 'both')) DEFAULT 'password',
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_host_active ON host(active);
		CREATE INDEX IF NOT EXISTS idx_host_hostname ON host(hostname);
		`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS host (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			hostname TEXT NOT NULL,
			port INTEGER DEFAULT 22,
			username TEXT NOT NULL,
			auth_method TEXT CHECK(auth_method IN ('password', 'key', 'both')) DEFAULT 'password',
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_host_active ON host(active);
		CREATE INDEX IF NOT EXISTS idx_host_hostname ON host(hostname);
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downHost(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS host;`)
	return err
}

