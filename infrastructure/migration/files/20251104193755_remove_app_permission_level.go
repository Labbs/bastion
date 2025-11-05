package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upRemoveAppPermissionLevel, downRemoveAppPermissionLevel)
}

func upRemoveAppPermissionLevel(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		-- Supprimer la colonne permission de user_app_permission
		CREATE TABLE IF NOT EXISTS user_app_permission_new (
			user_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			PRIMARY KEY (user_id, app_id),
			FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		INSERT INTO user_app_permission_new (user_id, app_id) 
		SELECT user_id, app_id FROM user_app_permission;
		DROP TABLE user_app_permission;
		ALTER TABLE user_app_permission_new RENAME TO user_app_permission;
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_user ON user_app_permission(user_id);
		CREATE INDEX IF NOT EXISTS idx_user_app_permission_app ON user_app_permission(app_id);
		
		-- Supprimer la colonne permission de group_app_permission
		CREATE TABLE IF NOT EXISTS group_app_permission_new (
			group_id TEXT NOT NULL,
			app_id TEXT NOT NULL,
			PRIMARY KEY (group_id, app_id),
			FOREIGN KEY (group_id) REFERENCES "group"(id) ON DELETE CASCADE,
			FOREIGN KEY (app_id) REFERENCES web_app(id) ON DELETE CASCADE
		);
		INSERT INTO group_app_permission_new (group_id, app_id) 
		SELECT group_id, app_id FROM group_app_permission;
		DROP TABLE group_app_permission;
		ALTER TABLE group_app_permission_new RENAME TO group_app_permission;
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_group ON group_app_permission(group_id);
		CREATE INDEX IF NOT EXISTS idx_group_app_permission_app ON group_app_permission(app_id);
		`
	case "postgres":
		query = `
		-- Supprimer la colonne permission de user_app_permission
		ALTER TABLE user_app_permission DROP COLUMN IF EXISTS permission;
		
		-- Supprimer la colonne permission de group_app_permission
		ALTER TABLE group_app_permission DROP COLUMN IF EXISTS permission;
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downRemoveAppPermissionLevel(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		// Pour sqlite, on ne peut pas facilement re-ajouter une colonne, donc on laisse vide
		// Si nécessaire, on peut recréer la table avec la colonne
		return nil
	case "postgres":
		query = `
		ALTER TABLE user_app_permission ADD COLUMN permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read';
		ALTER TABLE group_app_permission ADD COLUMN permission TEXT CHECK(permission IN ('read', 'write', 'admin')) DEFAULT 'read';
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}


