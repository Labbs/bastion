package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upSSHSessionRecord, downSSHSessionRecord)
}

func upSSHSessionRecord(ctx context.Context, tx *sql.Tx) error {
	var query string
	dialect, _ := ctx.Value("dbDialect").(string)
	switch dialect {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS ssh_session_record (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			host_id TEXT NOT NULL,
			started_at TIMESTAMP NOT NULL,
			ended_at TIMESTAMP,
			recording_path TEXT,
			format TEXT CHECK(format IN ('text', 'json', 'binary')) DEFAULT 'text',
			client_ip TEXT,
			client_user TEXT,
			session_id TEXT,
			FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
			FOREIGN KEY (host_id) REFERENCES host(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_user ON ssh_session_record(user_id);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_host ON ssh_session_record(host_id);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_started ON ssh_session_record(started_at);
		`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS ssh_session_record (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL,
			host_id UUID NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			ended_at TIMESTAMPTZ,
			recording_path TEXT,
			format TEXT CHECK(format IN ('text', 'json', 'binary')) DEFAULT 'text',
			client_ip TEXT,
			client_user TEXT,
			session_id TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (host_id) REFERENCES host(id) ON DELETE CASCADE
		);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_user ON ssh_session_record(user_id);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_host ON ssh_session_record(host_id);
		CREATE INDEX IF NOT EXISTS idx_ssh_session_record_started ON ssh_session_record(started_at);
		`
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	_, err := tx.ExecContext(ctx, query)
	return err
}

func downSSHSessionRecord(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS ssh_session_record;`)
	return err
}
