# PostgreSQL Repository Implementation

## Overview
Complete PostgreSQL implementation for the certctl certificate control plane using `database/sql` and `lib/pq` driver. All 71 interface methods across 11 repositories have been implemented.

## File Structure

```
internal/repository/postgres/
├── db.go               # Database connection and migration setup
├── certificate.go      # CertificateRepository (8 methods)
├── issuer.go          # IssuerRepository (5 methods)
├── target.go          # TargetRepository (6 methods)
├── agent.go           # AgentRepository (7 methods)
├── job.go             # JobRepository (9 methods)
├── policy.go          # PolicyRepository (7 methods)
├── audit.go           # AuditRepository (2 methods)
├── notification.go    # NotificationRepository (3 methods)
├── team.go            # TeamRepository (5 methods)
└── owner.go           # OwnerRepository (5 methods)
```

## Key Implementation Details

### Database Connection (db.go)
- `NewDB(connStr string)` - Opens PostgreSQL connection with connection pooling
  - Max open connections: 25
  - Max idle connections: 5
  - Verifies connection with Ping()

- `RunMigrations(db, migrationsPath)` - Executes SQL migration files
  - Reads all `.sql` files from migrations directory
  - Executes files in alphabetical order
  - Simple approach without external migration library

### Data Patterns Used

1. **UUID Generation**: Using `github.com/google/uuid` for ID generation
2. **Parameterized Queries**: All queries use `$1, $2, etc.` parameter placeholders
3. **Context Propagation**: All database operations use `*Context` variants
4. **Nullable Types**:
   - `sql.NullTime` for optional timestamps
   - `sql.NullString` for optional strings
5. **JSON Handling**:
   - `json.Marshal/Unmarshal` for JSONB columns
   - Config fields stored as `json.RawMessage`
6. **Array Handling**:
   - `pq.Array()` for storing Go slices in PostgreSQL arrays
   - `pq.StringArray` for scanning string arrays
7. **RETURNING Clauses**: Used in CREATE operations to retrieve generated IDs

### Error Handling
- All errors wrapped with `fmt.Errorf` for context
- Specific error messages for not found cases
- Row count verification for UPDATE/DELETE operations

## Repository Implementations

### CertificateRepository (8 methods)
- Manages certificate lifecycle with filtering by status, environment, owner, team, issuer
- Pagination support (default 50, max 500 per page)
- Certificate versioning with history tracking
- Expiration tracking and notifications
- Tags stored as JSON

### IssuerRepository (5 methods)
- Manages certificate authorities (ACME, GenericCA)
- Configuration stored as JSON for flexibility
- Enable/disable issuers

### TargetRepository (6 methods)
- Manages deployment targets (NGINX, F5, IIS)
- Lists targets associated with certificates via join table
- Configuration stored as JSON

### AgentRepository (7 methods)
- Manages control plane agents with status tracking
- Heartbeat update functionality
- API key hash lookup for authentication
- Last heartbeat timestamp tracking

### JobRepository (9 methods)
- Manages renewal, deployment, issuance, and validation jobs
- Status tracking with error messages
- Attempt counters for retry logic
- Pending job retrieval by type
- Filtering by status and certificate

### PolicyRepository (7 methods)
- Policy rules with multiple enforcement types
- Policy violation recording and querying
- Configurable rules stored as JSON
- Severity levels for violations (Warning, Error, Critical)

### AuditRepository (2 methods)
- Records all control plane actions
- Filtering by actor, resource type, time range
- Pagination support
- Details stored as JSON

### NotificationRepository (3 methods)
- Notification event tracking
- Multiple channels (Email, Webhook, Slack)
- Delivery status tracking
- Certificate-specific notification filtering

### TeamRepository (5 methods)
- Organizational unit management
- Basic CRUD operations
- Team descriptions for organization

### OwnerRepository (5 methods)
- Certificate owner management
- Email field for notifications
- Team affiliation tracking
- Basic CRUD operations

## Database Assumptions

The implementation expects the following table structures:

**certificates**
- id, name, common_name, sans (array), environment, owner_id, team_id, issuer_id
- status, expires_at, tags (json), last_renewal_at, last_deployment_at
- created_at, updated_at

**certificate_versions**
- id, certificate_id, serial_number, not_before, not_after
- fingerprint_sha256, pem_chain, csr_pem, created_at

**certificate_target_mappings** (join table)
- certificate_id, target_id

**issuers**
- id, name, type, config (json), enabled, created_at, updated_at

**deployment_targets**
- id, name, type, agent_id, config (json), enabled, created_at, updated_at

**agents**
- id, name, hostname, status, last_heartbeat_at, registered_at, api_key_hash

**jobs**
- id, type, certificate_id, target_id, status, attempts, max_attempts
- last_error, scheduled_at, started_at, completed_at, created_at

**policy_rules**
- id, name, type, config (json), enabled, created_at, updated_at

**policy_violations**
- id, certificate_id, rule_id, message, severity, created_at

**audit_events**
- id, actor, actor_type, action, resource_type, resource_id, details (json), timestamp

**notifications**
- id, type, certificate_id, channel, recipient, message, sent_at, status, error, created_at

**teams**
- id, name, description, created_at, updated_at

**owners**
- id, name, email, team_id, created_at, updated_at

## Integration Points

Constructor functions for each repository:
```go
NewCertificateRepository(db *sql.DB) *CertificateRepository
NewIssuerRepository(db *sql.DB) *IssuerRepository
NewTargetRepository(db *sql.DB) *TargetRepository
NewAgentRepository(db *sql.DB) *AgentRepository
NewJobRepository(db *sql.DB) *JobRepository
NewPolicyRepository(db *sql.DB) *PolicyRepository
NewAuditRepository(db *sql.DB) *AuditRepository
NewNotificationRepository(db *sql.DB) *NotificationRepository
NewTeamRepository(db *sql.DB) *TeamRepository
NewOwnerRepository(db *sql.DB) *OwnerRepository
```

## Dependencies
- `database/sql` (stdlib)
- `github.com/lib/pq` v1.10.9
- `github.com/google/uuid` v1.6.0

## Notes

1. All list operations support pagination with configurable page size (default 50, max 500)
2. Filtering is dynamic - only conditions with non-empty values are added to WHERE clause
3. Timestamps use `time.Time` for CreatedAt/UpdatedAt with automatic Now() on updates
4. Array fields use `pq.Array()` for proper PostgreSQL array handling
5. Nullable fields use `sql.Null*` types for proper NULL handling
6. All operations are context-aware and respect cancellation signals
7. Error messages are descriptive and wrapped for debugging
