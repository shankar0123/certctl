package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// TargetRepository implements repository.TargetRepository
type TargetRepository struct {
	db *sql.DB
}

// NewTargetRepository creates a new TargetRepository
func NewTargetRepository(db *sql.DB) *TargetRepository {
	return &TargetRepository{db: db}
}

// List returns all targets
func (r *TargetRepository) List(ctx context.Context) ([]*domain.DeploymentTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, type, agent_id, config, enabled, created_at, updated_at
		FROM deployment_targets
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query targets: %w", err)
	}
	defer rows.Close()

	var targets []*domain.DeploymentTarget
	for rows.Next() {
		var target domain.DeploymentTarget
		if err := rows.Scan(&target.ID, &target.Name, &target.Type, &target.AgentID,
			&target.Config, &target.Enabled, &target.CreatedAt, &target.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan target: %w", err)
		}
		targets = append(targets, &target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating target rows: %w", err)
	}

	return targets, nil
}

// Get retrieves a target by ID
func (r *TargetRepository) Get(ctx context.Context, id string) (*domain.DeploymentTarget, error) {
	var target domain.DeploymentTarget
	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, type, agent_id, config, enabled, created_at, updated_at
		FROM deployment_targets
		WHERE id = $1
	`, id).Scan(&target.ID, &target.Name, &target.Type, &target.AgentID,
		&target.Config, &target.Enabled, &target.CreatedAt, &target.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("target not found")
		}
		return nil, fmt.Errorf("failed to query target: %w", err)
	}

	return &target, nil
}

// Create stores a new target
func (r *TargetRepository) Create(ctx context.Context, target *domain.DeploymentTarget) error {
	if target.ID == "" {
		target.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO deployment_targets (id, name, type, agent_id, config, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, target.ID, target.Name, target.Type, target.AgentID, target.Config, target.Enabled,
		target.CreatedAt, target.UpdatedAt).Scan(&target.ID)

	if err != nil {
		return fmt.Errorf("failed to create target: %w", err)
	}

	return nil
}

// Update modifies an existing target
func (r *TargetRepository) Update(ctx context.Context, target *domain.DeploymentTarget) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE deployment_targets SET
			name = $1,
			type = $2,
			agent_id = $3,
			config = $4,
			enabled = $5,
			updated_at = $6
		WHERE id = $7
	`, target.Name, target.Type, target.AgentID, target.Config, target.Enabled, target.UpdatedAt, target.ID)

	if err != nil {
		return fmt.Errorf("failed to update target: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("target not found")
	}

	return nil
}

// Delete removes a target
func (r *TargetRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM deployment_targets WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete target: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("target not found")
	}

	return nil
}

// ListByCertificate returns all targets for a given certificate
func (r *TargetRepository) ListByCertificate(ctx context.Context, certID string) ([]*domain.DeploymentTarget, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT dt.id, dt.name, dt.type, dt.agent_id, dt.config, dt.enabled, dt.created_at, dt.updated_at
		FROM deployment_targets dt
		INNER JOIN certificate_target_mappings ctm ON dt.id = ctm.target_id
		WHERE ctm.certificate_id = $1
		ORDER BY dt.created_at DESC
	`, certID)

	if err != nil {
		return nil, fmt.Errorf("failed to query targets for certificate: %w", err)
	}
	defer rows.Close()

	var targets []*domain.DeploymentTarget
	for rows.Next() {
		var target domain.DeploymentTarget
		if err := rows.Scan(&target.ID, &target.Name, &target.Type, &target.AgentID,
			&target.Config, &target.Enabled, &target.CreatedAt, &target.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan target: %w", err)
		}
		targets = append(targets, &target)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating target rows: %w", err)
	}

	return targets, nil
}
