package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upPermissions, downPermissions)
}

func upPermissions(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS user_host_permission (
			user_id TEXT NOT NULL,
			host_id TEXT NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (user_id, host_id),
			FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
			FOREIGN KEY (host_id) REFERENCES host(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_host_permission_user ON user_host_permission(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_host_permission_host ON user_host_permission(host_id);
		
		CREATE TABLE IF NOT EXISTS user_app_permission (
			user_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (user_id, app_id),
			FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_user ON user_app_permission(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_app ON user_app_permission(app_id);
		
		CREATE TABLE IF NOT EXISTS group_app_permission (
			group_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (group_id, app_id),
			FOREIGN KEY (group_id) REFERENCES "group"(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_group ON group_app_permission(group_id);
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_app ON group_app_permission(app_id);
		`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS user_host_permission (
			user_id UUID NOT NULL,
			host_id UUID NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (user_id, host_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (host_id) REFERENCES host(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_host_permission_user ON user_host_permission(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_host_permission_host ON user_host_permission(host_id);
		
		CREATE TABLE IF NOT EXISTS user_app_permission (
			user_id UUID NOT NULL,
			app_id UUID NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (user_id, app_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_user ON user_app_permission(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_app ON user_app_permission(app_id);
		
		CREATE TABLE IF NOT EXISTS group_app_permission (
			group_id UUID NOT NULL,
			app_id UUID NOT NULL,
			permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read',
			PRIMARY KEY (group_id, app_id),
			FOREIGN KEY (group_id) REFERENCES "group"(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_group ON group_app_permission(group_id);
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_app ON group_app_permission(app_id);
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downPermissions(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS group_app_permission;`)
	if err != nil {
		// Try postgres
		_, _ = tx.ExecContext(ctx, `DROP TABLE IF EXISTS group_app_permission;`)
	}
	_, err = tx.ExecContext(ctx, `DROP TABLE IF EXISTS user_app_permission;`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DROP TABLE IF EXISTS user_host_permission;`)
	return err
}

