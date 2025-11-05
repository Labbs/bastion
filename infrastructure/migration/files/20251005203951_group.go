package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upGroup, downGroup)
}

func upGroup(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS "group" (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT,
			role TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			members JSONB,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_group_owner_id ON "group"(owner_id);
		CREATE INDEX IF NOT EXISTS idx_group_role ON "group"(role);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_group_name ON "group"(name);
		`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS "group" (
			id UUID PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT,
			role TEXT NOT NULL,
			owner_id UUID NOT NULL,
			members JSONB,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		);
		CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_group_owner_id ON "group"(owner_id);
		CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_group_role ON "group"(role);
		CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_group_name ON "group"(name);
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downGroup(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS "group";`)
	return err
}
