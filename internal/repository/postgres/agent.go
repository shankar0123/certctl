package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shankar0123/certctl/internal/domain"
)

// AgentRepository implements repository.AgentRepository
type AgentRepository struct {
	db *sql.DB
}

// NewAgentRepository creates a new AgentRepository
func NewAgentRepository(db *sql.DB) *AgentRepository {
	return &AgentRepository{db: db}
}

// List returns all agents
func (r *AgentRepository) List(ctx context.Context) ([]*domain.Agent, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash
		FROM agents
		ORDER BY registered_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to query agents: %w", err)
	}
	defer rows.Close()

	var agents []*domain.Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating agent rows: %w", err)
	}

	return agents, nil
}

// Get retrieves an agent by ID
func (r *AgentRepository) Get(ctx context.Context, id string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash
		FROM agents
		WHERE id = $1
	`, id)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return agent, nil
}

// Create stores a new agent
func (r *AgentRepository) Create(ctx context.Context, agent *domain.Agent) error {
	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}

	err := r.db.QueryRowContext(ctx, `
		INSERT INTO agents (id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, agent.ID, agent.Name, agent.Hostname, agent.Status, agent.LastHeartbeatAt,
		agent.RegisteredAt, agent.APIKeyHash).Scan(&agent.ID)

	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	return nil
}

// Update modifies an existing agent
func (r *AgentRepository) Update(ctx context.Context, agent *domain.Agent) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE agents SET
			name = $1,
			hostname = $2,
			status = $3,
			last_heartbeat_at = $4,
			api_key_hash = $5
		WHERE id = $6
	`, agent.Name, agent.Hostname, agent.Status, agent.LastHeartbeatAt, agent.APIKeyHash, agent.ID)

	if err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found")
	}

	return nil
}

// Delete removes an agent
func (r *AgentRepository) Delete(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM agents WHERE id = $1", id)

	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found")
	}

	return nil
}

// UpdateHeartbeat updates the agent's last heartbeat timestamp
func (r *AgentRepository) UpdateHeartbeat(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE agents SET last_heartbeat_at = $1 WHERE id = $2
	`, time.Now(), id)

	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("agent not found")
	}

	return nil
}

// GetByAPIKey retrieves an agent by hashed API key
func (r *AgentRepository) GetByAPIKey(ctx context.Context, keyHash string) (*domain.Agent, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash
		FROM agents
		WHERE api_key_hash = $1
	`, keyHash)

	agent, err := scanAgent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("agent not found")
		}
		return nil, fmt.Errorf("failed to query agent: %w", err)
	}

	return agent, nil
}

// scanAgent scans an agent from a row or rows
func scanAgent(scanner interface {
	Scan(...interface{}) error
}) (*domain.Agent, error) {
	var agent domain.Agent
	err := scanner.Scan(&agent.ID, &agent.Name, &agent.Hostname, &agent.Status,
		&agent.LastHeartbeatAt, &agent.RegisteredAt, &agent.APIKeyHash)

	if err != nil {
		return nil, fmt.Errorf("failed to scan agent: %w", err)
	}

	return &agent, nil
}
