package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upWebApp, downWebApp)
}

func upWebApp(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS web_app (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			url TEXT NOT NULL,
			icon TEXT,
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_web_app_active ON web_app(active);
		`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS web_app (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			url TEXT NOT NULL,
			icon TEXT,
			active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_web_app_active ON web_app(active);
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downWebApp(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS web_app;`)
	return err
}

