# PostgreSQL Implementation Patterns

## Consistent Patterns Across All Repositories

### 1. Package Structure
```go
package postgres

import (
    "context"
    "database/sql"
    "fmt"
    "github.com/google/uuid"
    "github.com/lib/pq"
)
```

### 2. Repository Constructor Pattern
```go
type CertificateRepository struct {
    db *sql.DB
}

func NewCertificateRepository(db *sql.DB) *CertificateRepository {
    return &CertificateRepository{db: db}
}
```

### 3. UUID Generation Pattern
```go
if cert.ID == "" {
    cert.ID = uuid.New().String()
}
```

### 4. Parameterized Queries Pattern
All queries use `$1, $2, $3...` placeholders:
```go
err := r.db.QueryRowContext(ctx, `
    SELECT id, name FROM table WHERE id = $1
`, id).Scan(&result.ID, &result.Name)
```

### 5. Context Propagation Pattern
```go
// QueryContext for SELECT
rows, err := r.db.QueryContext(ctx, query, args...)

// QueryRowContext for single row
row := r.db.QueryRowContext(ctx, query, args...)

// ExecContext for INSERT/UPDATE/DELETE
result, err := r.db.ExecContext(ctx, query, args...)
```

### 6. NULL Handling Pattern
```go
// For nullable types, use sql.Null*
var agent.LastHeartbeatAt *time.Time

// Scan handles NULL automatically
err := row.Scan(&agent.LastHeartbeatAt)
```

### 7. Array Handling Pattern (pq)
```go
import "github.com/lib/pq"

// Storing arrays
pq.Array(cert.SANs)  // Converts []string to PostgreSQL array

// Scanning arrays
var sans pq.StringArray
row.Scan(&sans)
cert.SANs = []string(sans)
```

### 8. JSON Handling Pattern
```go
import "encoding/json"

// For JSONB config columns (stored as json.RawMessage)
issuer.Config  // type: json.RawMessage

// For tags (stored as JSON string)
tagsJSON, err := json.Marshal(cert.Tags)
row.Scan(&tagsJSON)
json.Unmarshal(tagsJSON, &cert.Tags)
```

### 9. Pagination Pattern
```go
// Set defaults
if filter.Page < 1 {
    filter.Page = 1
}
if filter.PerPage == 0 || filter.PerPage > 500 {
    filter.PerPage = 50
}

// Calculate offset
offset := (filter.Page - 1) * filter.PerPage

// Add to query
query += fmt.Sprintf("LIMIT $%d OFFSET $%d", argCount, argCount+1)
args = append(args, filter.PerPage, offset)
```

### 10. Dynamic WHERE Clause Pattern
```go
var whereConditions []string
var args []interface{}
argCount := 1

if filter.Status != "" {
    whereConditions = append(whereConditions, fmt.Sprintf("status = $%d", argCount))
    args = append(args, filter.Status)
    argCount++
}

whereClause := ""
if len(whereConditions) > 0 {
    whereClause = "WHERE " + strings.Join(whereConditions, " AND ")
}
```

### 11. Row Count Verification Pattern
```go
result, err := r.db.ExecContext(ctx, query, args...)
if err != nil {
    return fmt.Errorf("failed to update: %w", err)
}

rows, err := result.RowsAffected()
if err != nil {
    return fmt.Errorf("failed to get rows affected: %w", err)
}

if rows == 0 {
    return fmt.Errorf("entity not found")
}
```

### 12. Not Found Error Pattern
```go
row := r.db.QueryRowContext(ctx, query, args...)
entity, err := scanEntity(row)
if err != nil {
    if err == sql.ErrNoRows {
        return nil, fmt.Errorf("entity not found")
    }
    return nil, fmt.Errorf("failed to query entity: %w", err)
}
```

### 13. Scanner Helper Pattern (for reusable scanning)
```go
func scanEntity(scanner interface {
    Scan(...interface{}) error
}) (*domain.Entity, error) {
    var e domain.Entity
    err := scanner.Scan(&e.ID, &e.Name, ...)
    if err != nil {
        return nil, fmt.Errorf("failed to scan entity: %w", err)
    }
    return &e, nil
}

// Used in both single row and multiple rows contexts
row := r.db.QueryRowContext(ctx, query)
entity, err := scanEntity(row)

for rows.Next() {
    entity, err := scanEntity(rows)
}
```

### 14. List Query Pattern
```go
// Get total count first
countQuery := fmt.Sprintf("SELECT COUNT(*) FROM table %s", whereClause)
var total int
r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)

// Then get paginated results
rows, err := r.db.QueryContext(ctx, paginatedQuery, args...)
defer rows.Close()

var results []*domain.Entity
for rows.Next() {
    entity, err := scanEntity(rows)
    results = append(results, entity)
}
```

### 15. Error Wrapping Pattern
```go
// All errors wrapped with context
if err != nil {
    return fmt.Errorf("failed to create entity: %w", err)
}
```

### 16. RETURNING Clause Pattern (for retrieving generated IDs)
```go
err := r.db.QueryRowContext(ctx, `
    INSERT INTO table (col1, col2)
    VALUES ($1, $2)
    RETURNING id
`, val1, val2).Scan(&entity.ID)
```

### 17. Join Table Pattern (for many-to-many)
```go
// ListByCertificate uses certificate_target_mappings join table
rows, err := r.db.QueryContext(ctx, `
    SELECT dt.id, dt.name, dt.type, dt.agent_id, dt.config, dt.enabled, dt.created_at, dt.updated_at
    FROM deployment_targets dt
    INNER JOIN certificate_target_mappings ctm ON dt.id = ctm.target_id
    WHERE ctm.certificate_id = $1
    ORDER BY dt.created_at DESC
`, certID)
```

## Type-Specific Patterns

### Certificate with Arrays and JSON
```go
// In certificate.go
var sans pq.StringArray
var tagsJSON []byte

err := scanner.Scan(&cert.ID, &cert.Name, &cert.CommonName, &sans, ...)
if err != nil {
    return nil, fmt.Errorf("failed to scan: %w", err)
}

cert.SANs = []string(sans)
json.Unmarshal(tagsJSON, &cert.Tags)
```

### Agent with Nullable Timestamp
```go
// In agent.go
var agent domain.Agent
err := scanner.Scan(&agent.ID, &agent.Name, &agent.Hostname, &agent.Status,
    &agent.LastHeartbeatAt, &agent.RegisteredAt, &agent.APIKeyHash)
// LastHeartbeatAt can be nil, automatically handled by sql.NullTime
```

### Job with Nullable String
```go
// In job.go
var job domain.Job
var lastError *string
err := scanner.Scan(&job.ID, ..., &lastError, ...)
// lastError can be nil for successful jobs
job.LastError = lastError
```

## Testing Considerations

These implementations expect:
1. PostgreSQL database with proper schema
2. Tables created with matching column names and types
3. Foreign key relationships established
4. Proper indexes on frequently queried columns

For testing, consider:
- Using `testcontainers-go` for PostgreSQL in Docker
- Running migrations before test suite
- Using transactions with rollback for test isolation
