package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	goose.AddMigrationContext(upAdminUser, downAdminUser)
}

func upAdminUser(ctx context.Context, tx *sql.Tx) error {
	dialect, _ := ctx.Value("dbDialect").(string)

	// Check if admin account should be disabled via config
	// For now, we'll create it by default and it can be disabled later via the API

	// Default admin credentials
	adminEmail := "admin@bastion.local"
	adminUsername := "admin"
	adminPassword := "admin123" // Should be changed on first login
	adminID := "00000000-0000-0000-0000-000000000001"

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	now := time.Now()

	var query string
	var checkQuery string
	switch dialect {
	case "sqlite":
		// Check if admin already exists
		checkQuery = `SELECT COUNT(*) FROM user WHERE email = ?`
		var count int
		err = tx.QueryRowContext(ctx, checkQuery, adminEmail).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to check admin user: %w", err)
		}

		if count == 0 {
			query = `
			INSERT INTO user (id, username, email, password, active, role, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`
			_, err = tx.ExecContext(ctx, query, adminID, adminUsername, adminEmail, string(hashedPassword), true, "admin", now, now)
		}
	case "postgres":
		// Check if admin already exists
		checkQuery = `SELECT COUNT(*) FROM users WHERE email = $1`
		var count int
		err = tx.QueryRowContext(ctx, checkQuery, adminEmail).Scan(&count)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to check admin user: %w", err)
		}

		if count == 0 {
			query = `
			INSERT INTO users (id, username, email, password, active, role, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			`
			_, err = tx.ExecContext(ctx, query, adminID, adminUsername, adminEmail, string(hashedPassword), true, "admin", now, now)
		}
	default:
		return fmt.Errorf("unsupported dialect: %s", dialect)
	}

	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	return nil
}

func downAdminUser(ctx context.Context, tx *sql.Tx) error {
	// Remove admin user by email
	_, err := tx.ExecContext(ctx, `DELETE FROM user WHERE email = 'admin@bastion.local';`)
	if err != nil {
		// Try postgres table name
		_, err = tx.ExecContext(ctx, `DELETE FROM users WHERE email = 'admin@bastion.local';`)
	}
	return err
}
