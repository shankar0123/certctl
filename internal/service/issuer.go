package service

import (
	"context"
	"fmt"

	"github.com/shankar0123/certctl/internal/domain"
	"github.com/shankar0123/certctl/internal/repository"
)

// IssuerService provides business logic for certificate issuer management.
type IssuerService struct {
	issuerRepo   repository.IssuerRepository
	auditService *AuditService
}

// NewIssuerService creates a new issuer service.
func NewIssuerService(
	issuerRepo repository.IssuerRepository,
	auditService *AuditService,
) *IssuerService {
	return &IssuerService{
		issuerRepo:   issuerRepo,
		auditService: auditService,
	}
}

// List returns a paginated list of issuers.
func (s *IssuerService) List(ctx context.Context, page, perPage int) ([]*domain.Issuer, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	offset := int64((page - 1) * perPage)
	issuers, total, err := s.issuerRepo.List(ctx, offset, int64(perPage))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list issuers: %w", err)
	}
	return issuers, total, nil
}

// Get retrieves an issuer by ID.
func (s *IssuerService) Get(ctx context.Context, id string) (*domain.Issuer, error) {
	issuer, err := s.issuerRepo.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer %s: %w", id, err)
	}
	return issuer, nil
}

// Create validates and stores a new issuer.
func (s *IssuerService) Create(ctx context.Context, issuer *domain.Issuer, actor string) error {
	if issuer.Name == "" {
		return fmt.Errorf("issuer name is required")
	}

	issuer.ID = generateID("issuer")
	if err := s.issuerRepo.Create(ctx, issuer); err != nil {
		return fmt.Errorf("failed to create issuer: %w", err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "create_issuer", "issuer", issuer.ID, nil)
	}

	return nil
}

// Update modifies an existing issuer.
func (s *IssuerService) Update(ctx context.Context, id string, issuer *domain.Issuer, actor string) error {
	if issuer.Name == "" {
		return fmt.Errorf("issuer name is required")
	}

	issuer.ID = id
	if err := s.issuerRepo.Update(ctx, issuer); err != nil {
		return fmt.Errorf("failed to update issuer %s: %w", id, err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "update_issuer", "issuer", id, nil)
	}

	return nil
}

// Delete removes an issuer.
func (s *IssuerService) Delete(ctx context.Context, id string, actor string) error {
	if err := s.issuerRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete issuer %s: %w", id, err)
	}

	if s.auditService != nil {
		_ = s.auditService.RecordEvent(ctx, actor, domain.ActorTypeUser, "delete_issuer", "issuer", id, nil)
	}

	return nil
}

// TestConnection verifies the issuer connection.
func (s *IssuerService) TestConnection(ctx context.Context, id string) error {
	issuer, err := s.issuerRepo.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("issuer not found: %w", err)
	}

	// TODO: Implement actual connection test based on issuer type
	if issuer == nil {
		return fmt.Errorf("issuer not found")
	}

	return nil
}

// ListIssuers returns paginated issuers (handler interface method).
func (s *IssuerService) ListIssuers(page, perPage int) ([]domain.Issuer, int64, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}

	offset := int64((page - 1) * perPage)
	issuers, total, err := s.issuerRepo.List(context.Background(), offset, int64(perPage))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list issuers: %w", err)
	}

	// Convert pointers to values for the handler interface
	var result []domain.Issuer
	for _, i := range issuers {
		if i != nil {
			result = append(result, *i)
		}
	}

	return result, total, nil
}

// GetIssuer returns a single issuer (handler interface method).
func (s *IssuerService) GetIssuer(id string) (*domain.Issuer, error) {
	return s.issuerRepo.Get(context.Background(), id)
}

// CreateIssuer creates a new issuer (handler interface method).
func (s *IssuerService) CreateIssuer(issuer domain.Issuer) (*domain.Issuer, error) {
	issuer.ID = generateID("issuer")
	if err := s.issuerRepo.Create(context.Background(), &issuer); err != nil {
		return nil, fmt.Errorf("failed to create issuer: %w", err)
	}
	return &issuer, nil
}

// UpdateIssuer modifies an issuer (handler interface method).
func (s *IssuerService) UpdateIssuer(id string, issuer domain.Issuer) (*domain.Issuer, error) {
	issuer.ID = id
	if err := s.issuerRepo.Update(context.Background(), &issuer); err != nil {
		return nil, fmt.Errorf("failed to update issuer: %w", err)
	}
	return &issuer, nil
}

// DeleteIssuer removes an issuer (handler interface method).
func (s *IssuerService) DeleteIssuer(id string) error {
	return s.issuerRepo.Delete(context.Background(), id)
}
