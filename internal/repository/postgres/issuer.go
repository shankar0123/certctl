package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// IssuerRepository implements repository.IssuerRepository
type IssuerRepository struct {
	db *sql.DB
}

// NewIssuerRepository creates a new IssuerRepository
func NewIssuerRepository(db *sql.DB) *IssuerRepository {
	return &IssuerRepository{db: db}
}

// List returns all issuers
func (r *IssuerRepository) List(ctx context.Context) ([]*domain.Issuer, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, config, enabled, created_at, updated_at
		FROM issuers
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query issuers: %w", err)
	}
	defer rows.Close()

	var issuers []*domain.Issuer
	for rows.Next() {
		var issuer domain.Issuer
		if err := rows.Scan(&issuer.ID, &issuer.Name, &issuer.Type, &issuer.Config,
			&issuer.Enabled, &issuer.CreatedAt, &issuer.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan issuer: %w", err)
		}
		issuers = append(issuers, &issuer)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating issuer rows: %w", err)
	}

	return issuers, nil
}

// Get retrieves an issuer by ID
func (r *IssuerRepository) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	var issuer domain.Issuer
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, config, enabled, created_at, updated_at
		FROM issuers
		WHERE id = $1
	`, id).Scan(&issuer.ID, &issuer.Name, &issuer.Type, &issuer.Config,
		&issuer.Enabled, &issuer.CreatedAt, &issuer.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("issuer not found")
		}
		return nil, fmt.Errorf("failed to query issuer: %w", err)
	}

	return &issuer, nil
}

// Create stores a new issuer
func (r *IssuerRepository) Create(ctx context.Context, issuer *domain.Issuer) error {
	if issuer.ID == "" {
		issuer.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO issuers (id, name, type, config, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, issuer.ID, issuer.Name, issuer.Type, issuer.Config, issuer.Enabled,
		issuer.CreatedAt, issuer.UpdatedAt).Scan(&issuer.ID)

	if err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	return nil
}

// Update modifies an existing issuer
func (r *IssuerRepository) Update(ctx context.Context, issuer *domain.Issuer) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE issuers SET
			name = $1,
			type = $2,
			config = $3,
			enabled = $4,
			updated_at = $5
		WHERE id = $6
	`, issuer.Name, issuer.Type, issuer.Config, issuer.Enabled, issuer.UpdatedAt, issuer.ID)

	if err != nil {
		return fmt.Errorf("failed to update issuer: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("issuer not found")
	}

	return nil
}

// Delete removes an issuer
func (r *IssuerRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM issuers WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete issuer: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("issuer not found")
	}

	return nil
}
