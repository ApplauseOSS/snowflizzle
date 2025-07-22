// Copyright 2025 Applause App Quality, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package role provides types and logic for managing Snowflake roles, members, and permissions
// based on a YAML configuration file. It supports creation, removal, and permission grants for roles.
package role

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/applauseoss/snowflizzle/internal/logging"
	"gopkg.in/yaml.v3"
)

// System-defined roles for Snowflake
var systemRoles = map[string]struct{}{
	"ACCOUNTADMIN":  {},
	"PUBLIC":        {},
	"SECURITYADMIN": {},
	"SYSADMIN":      {},
}

// RoleMember represents a member of a role, identified by their email address.
// The Remove field indicates whether the member has to be removed from the role.
type RoleMember struct {
	Email  string `yaml:"email"`
	Remove bool   `yaml:"remove,omitempty"`
}

// DatabasePermission represents a database permission entry.
// Remove means to remove the grant from the database.
type DatabasePermission struct {
	Name   string   `yaml:"name"`
	Grants []string `yaml:"grants,omitempty"` // Grants to apply to the role for this database
	Remove bool     `yaml:"remove,omitempty"`
}

// SchemaPermission represents a schema permission entry.
// Example: { name: "MYDB.PUBLIC", grants: ["USAGE"] }
type SchemaPermission struct {
	Name   string   `yaml:"name"`
	Grants []string `yaml:"grants,omitempty"`
	Remove bool     `yaml:"remove,omitempty"`
}

// TablePermission represents a table permission entry.
// Example: { name: "MYDB.PUBLIC.MYTABLE", grants: ["SELECT"] }
type TablePermission struct {
	Name   string   `yaml:"name"`
	Grants []string `yaml:"grants,omitempty"`
	Remove bool     `yaml:"remove,omitempty"`
}

// ViewPermission represents a view permission entry.
// Example: { name: "MYDB.PUBLIC.MYVIEW", grants: ["SELECT"] }
type ViewPermission struct {
	Name   string   `yaml:"name"`
	Grants []string `yaml:"grants,omitempty"`
	Remove bool     `yaml:"remove,omitempty"`
}

// RolePermissions represents permissions for a role, including databases, schemas, tables, and views.
type RolePermissions struct {
	Databases []DatabasePermission `yaml:"databases,omitempty"`
	Schemas   []SchemaPermission   `yaml:"schemas,omitempty"`
	Tables    []TablePermission    `yaml:"tables,omitempty"`
	Views     []ViewPermission     `yaml:"views,omitempty"`
}

// Role represents a single role entry in the YAML configuration.
type Role struct {
	Name        string           `yaml:"name"`
	Members     []RoleMember     `yaml:"members"`
	Permissions *RolePermissions `yaml:"permissions,omitempty"`
	Remove      bool             `yaml:"remove,omitempty"` // Indicates if the role should be removed
}

// RolesConfig represents the structure of the rolesmap YAML file.
type RolesConfig struct {
	Roles []Role `yaml:"roles"`
}

// LoadRolesConfig parses the YAML file at filePath into a RolesConfig struct.
func LoadRolesConfig(filePath string) (*RolesConfig, error) {
	logger := logging.GetLogger()
	if filePath == "" {
		return nil, errors.New("no file provided")
	}

	file, openErr := os.Open(filePath)
	if openErr != nil {
		return nil, fmt.Errorf("failed to open file: %w", openErr)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			logger.ErrorContext(context.Background(), "failed to close file", "error", cerr)
		}
	}()

	var rolesConfig RolesConfig
	decoder := yaml.NewDecoder(file)
	if decodeErr := decoder.Decode(&rolesConfig); decodeErr != nil {
		return nil, fmt.Errorf("failed to parse file as YAML: %w", decodeErr)
	}
	return &rolesConfig, nil
}

// FetchShowRoles returns a set of role names from SHOW ROLES.
func FetchShowRoles(db *sql.DB) (map[string]struct{}, error) {
	logger := logging.GetLogger()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, "SHOW ROLES")
	if err != nil {
		logger.ErrorContext(context.Background(), "query SHOW ROLES failed", "error", err)
		return nil, fmt.Errorf("error querying SHOW ROLES: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns for SHOW ROLES: %w", err)
	}
	// find index of NAME column
	nameIdx := -1
	for i, col := range cols {
		if strings.EqualFold(col, "name") {
			nameIdx = i
			break
		}
	}
	if nameIdx < 0 {
		return nil, errors.New("NAME column not found in SHOW ROLES result")
	}

	// prepare scan destinations
	raw := make([]sql.NullString, len(cols))
	vals := make([]any, len(cols))
	for i := range raw {
		vals[i] = &raw[i]
	}

	roles := make(map[string]struct{})
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			logger.ErrorContext(context.Background(), "scanning SHOW ROLES row failed", "error", err)
			return nil, fmt.Errorf("error scanning SHOW ROLES: %w", err)
		}
		if raw[nameIdx].Valid {
			roles[raw[nameIdx].String] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iteration error on SHOW ROLES: %w", err)
	}
	return roles, nil
}

// FetchShowUsers returns a map from login_name to NAME from SHOW USERS.
func FetchShowUsers(db *sql.DB) (map[string]string, error) {
	logger := logging.GetLogger()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, "SHOW USERS")
	if err != nil {
		logger.ErrorContext(context.Background(), "query SHOW USERS failed", "error", err)
		return nil, fmt.Errorf("error querying SHOW USERS: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns for SHOW USERS: %w", err)
	}
	// find indices for LOGIN_NAME and NAME
	loginIdx, nameIdx := -1, -1
	for i, col := range cols {
		switch strings.ToLower(col) {
		case "login_name":
			loginIdx = i
		case "name":
			nameIdx = i
		}
	}
	if loginIdx < 0 || nameIdx < 0 {
		return nil, errors.New("LOGIN_NAME or NAME column not found in SHOW USERS result")
	}

	// prepare scan destinations
	raw := make([]sql.NullString, len(cols))
	vals := make([]any, len(cols))
	for i := range raw {
		vals[i] = &raw[i]
	}

	users := make(map[string]string)
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			logger.ErrorContext(context.Background(), "scanning SHOW USERS row failed", "error", err)
			return nil, fmt.Errorf("error scanning SHOW USERS: %w", err)
		}
		login := raw[loginIdx]
		name := raw[nameIdx]
		if login.Valid && name.Valid {
			users[strings.ToUpper(login.String)] = name.String
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iteration error on SHOW USERS: %w", err)
	}
	return users, nil
}

// FetchShowWarehouses returns a map from warehouse name to warehouse name from SHOW WAREHOUSES.
func FetchShowWarehouses(db *sql.DB) (map[string]string, error) {
	logger := logging.GetLogger()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, "SHOW WAREHOUSES")
	if err != nil {
		logger.ErrorContext(context.Background(), "query SHOW WAREHOUSES failed", "error", err)
		return nil, fmt.Errorf("error querying SHOW WAREHOUSES: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns for SHOW WAREHOUSES: %w", err)
	}
	nameIdx := -1
	for i, col := range cols {
		if strings.EqualFold(col, "name") {
			nameIdx = i
			break
		}
	}
	if nameIdx < 0 {
		return nil, errors.New("NAME column not found in SHOW WAREHOUSES result")
	}

	raw := make([]sql.NullString, len(cols))
	vals := make([]any, len(cols))
	for i := range raw {
		vals[i] = &raw[i]
	}

	warehouses := make(map[string]string)
	for rows.Next() {
		if err := rows.Scan(vals...); err != nil {
			logger.ErrorContext(context.Background(), "scanning SHOW WAREHOUSES row failed", "error", err)
			return nil, fmt.Errorf("error scanning SHOW WAREHOUSES: %w", err)
		}
		if raw[nameIdx].Valid {
			warehouses[strings.ToUpper(raw[nameIdx].String)] = raw[nameIdx].String
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iteration error on SHOW WAREHOUSES: %w", err)
	}
	return warehouses, nil
}

// RoleProcessor encapsulates dependencies and configuration for processing roles.
type RoleProcessor struct {
	db                 *sql.DB
	rc                 *RolesConfig
	dryRun             bool
	logger             *slog.Logger
	existingRoles      map[string]struct{}
	existingUsers      map[string]string
	existingWarehouses map[string]string

	qRole       string
	qUser       string
	roleName    string
	displayUser string

	currentGrants map[GrantKey]struct{} // holds current grants for the role
}

// NewRoleProcessor constructs a RoleProcessor and initializes its state.
// Returns an error if initialization fails (e.g., DB unavailable and not dryRun).
func NewRoleProcessor(db *sql.DB, rc *RolesConfig, dryRun bool) (*RoleProcessor, error) {
	rp := &RoleProcessor{
		db:     db,
		rc:     rc,
		dryRun: dryRun,
		logger: logging.GetLogger(),
	}
	if err := rp.Init(); err != nil {
		return nil, err
	}
	return rp, nil
}

// Init loads existing roles and users from Snowflake.
// Should only be called from NewRoleProcessor.
func (rp *RoleProcessor) Init() error {
	if rp.db == nil {
		if !rp.dryRun {
			return errors.New("database connection is nil")
		}
		rp.logger.WarnContext(context.Background(), "Dry run enabled with nil DB — skipping role/user fetch")
		rp.existingRoles = make(map[string]struct{})
		rp.existingUsers = make(map[string]string)
		return nil
	}
	var err error
	rp.existingRoles, err = FetchShowRoles(rp.db)
	if err != nil {
		rp.logger.ErrorContext(context.Background(), "Failed to fetch roles from Snowflake", "error", err)
		return err
	}
	rp.existingUsers, err = FetchShowUsers(rp.db)
	if err != nil {
		rp.logger.ErrorContext(context.Background(), "Failed to fetch users from Snowflake", "error", err)
		return err
	}
	rp.existingWarehouses, err = FetchShowWarehouses(rp.db)
	if err != nil {
		rp.logger.ErrorContext(context.Background(), "Failed to fetch warehouses from Snowflake", "error", err)
		return err
	}
	return nil
}

// quoteIdentifier escapes and quotes a Snowflake identifier
func quoteIdentifier(id string) string {
	esc := strings.ReplaceAll(id, `"`, `""`)
	return `"` + esc + `"`
}

func (rp *RoleProcessor) createRoleIfNotExists() error {
	createRoleQuery := "CREATE ROLE IF NOT EXISTS " + rp.qRole
	if err := rp.execQuery(createRoleQuery); err != nil {
		return fmt.Errorf("failed to create role %s: %w", rp.roleName, err)
	}
	return nil
}

// createWarehouseIfNotExists creates a warehouse with the same name as the role, uppercased and postfixed with _WH, if it does not exist.
func (rp *RoleProcessor) createWarehouseIfNotExists() (string, error) {
	warehouseName := rp.roleName + "_WAREHOUSE"
	qWarehouse := quoteIdentifier(warehouseName)

	// Use cached warehouses instead of fetching every time
	if _, exists := rp.existingWarehouses[warehouseName]; exists {
		rp.logger.InfoContext(context.Background(), "Warehouse already exists", "warehouse", warehouseName)
		return warehouseName, nil
	}

	createWarehouseQuery := fmt.Sprintf(
		`CREATE WAREHOUSE IF NOT EXISTS %s
	WITH
	WAREHOUSE_SIZE = XSMALL
	WAREHOUSE_TYPE = STANDARD
	AUTO_SUSPEND = 60
	AUTO_RESUME = TRUE
	INITIALLY_SUSPENDED = TRUE`,
		qWarehouse,
	)
	if err := rp.execQuery(createWarehouseQuery); err != nil {
		return warehouseName, fmt.Errorf("failed to create warehouse %s: %w", warehouseName, err)
	}
	// Add to cache so subsequent calls know it exists
	rp.existingWarehouses[warehouseName] = warehouseName
	return warehouseName, nil
}

func (rp *RoleProcessor) grantRoleToUser() error {
	query := fmt.Sprintf("GRANT ROLE %s TO USER %s", rp.qRole, rp.qUser)
	if err := rp.execQuery(query); err != nil {
		return fmt.Errorf("grant failed for %s -> %s: %w", rp.roleName, rp.displayUser, err)
	}
	return nil
}

func (rp *RoleProcessor) grantWarehouseToRole(warehouseName string) error {
	qWarehouse := quoteIdentifier(warehouseName)
	grantKey := GrantKey{
		Privilege:  "USAGE",
		ObjectType: "WAREHOUSE",
		ObjectName: strings.ToUpper(warehouseName),
	}
	// Check if the grant already exists
	if _, exists := rp.currentGrants[grantKey]; exists {
		rp.logger.InfoContext(context.Background(), "Warehouse usage already granted to role", "warehouse", warehouseName, "role", rp.roleName)
		return nil
	}

	grantQuery := fmt.Sprintf("GRANT USAGE ON WAREHOUSE %s TO ROLE %s", qWarehouse, rp.qRole)
	if err := rp.execQuery(grantQuery); err != nil {
		return fmt.Errorf("failed to grant USAGE on warehouse %s to role %s: %w", warehouseName, rp.roleName, err)
	}
	// update currentGrants to reflect the new grant because we are not fetching current grants again
	rp.currentGrants[grantKey] = struct{}{}
	return nil
}

func (rp *RoleProcessor) revokeRoleFromUser() error {
	//nolint:gosec // G202: Identifiers are quoted using quoteIdentifier
	query := "REVOKE ROLE " + rp.qRole + " FROM USER " + rp.qUser
	if err := rp.execQuery(query); err != nil {
		return fmt.Errorf("failed to revoke role %s from user %s: %w", rp.roleName, rp.displayUser, err)
	}
	return nil
}

// GrantKey uniquely identifies a privilege grant on an object
// Example: Privilege: "SELECT", ObjectType: "TABLE", ObjectName: "MYDB.PUBLIC.MYTABLE"
type GrantKey struct {
	Privilege  string
	ObjectType string // DATABASE, SCHEMA, TABLE, VIEW
	ObjectName string // e.g. MYDB, MYDB.PUBLIC, MYDB.PUBLIC.MYTABLE
}

// normalizeObjectName strips quotes and uppercases all parts for consistent diffing
func normalizeObjectName(objectName string) string {
	parts := strings.Split(objectName, ".")
	for i, part := range parts {
		part = strings.Trim(part, "\"")
		parts[i] = strings.ToUpper(part)
	}
	return strings.Join(parts, ".")
}

// memberProcess processes each member of the given Role, granting or revoking the role as needed.
// It returns the number of users skipped because they do not exist in rp.existingUsers, and an error if any operation fails.
func (rp *RoleProcessor) memberProcess(role Role) (usersSkipped int, err error) {
	for _, member := range role.Members {
		if len(rp.existingUsers) > 0 {
			upperMemberKey := strings.ToUpper(member.Email)
			memberName, ok := rp.existingUsers[upperMemberKey]
			if !ok {
				usersSkipped++
				rp.logger.WarnContext(context.Background(), "Skipping non-existent member", "member", member.Email)
				continue
			}
			rp.qUser = quoteIdentifier(memberName)
			rp.displayUser = memberName
		} else {
			rp.qUser = quoteIdentifier(member.Email)
			rp.displayUser = member.Email
		}

		if member.Remove {
			if err := rp.revokeRoleFromUser(); err != nil {
				return usersSkipped, err
			}
			continue
		}

		if err := rp.grantRoleToUser(); err != nil {
			return usersSkipped, err
		}
	}
	return
}

func (rp *RoleProcessor) execQuery(query string) error {
	ctx := context.Background()
	if rp.dryRun {
		rp.logger.InfoContext(context.Background(), "[DryRun]", "query", query)
		return nil
	}
	rp.logger.InfoContext(context.Background(), "[Executing]", "query", query)
	_, err := rp.db.ExecContext(ctx, query)
	return err
}

// Rename permissionProcess to applySpecialGrants for clarity
func (rp *RoleProcessor) applySpecialGrants(role Role) error {
	if role.Permissions == nil {
		return nil
	}

	// Helper to grant USAGE on all schemas in a database
	grantUsageOnAllSchemas := func(dbName string) error {
		schemas, err := rp.GetSchemasInDatabase(dbName)
		if err != nil {
			rp.logger.ErrorContext(context.Background(), "Could not fetch schemas for USAGE grant", "database", dbName, "error", err)
			return fmt.Errorf("failed to fetch schemas for USAGE grant on database %s: %w", dbName, err)
		}
		qDB := quoteIdentifier(dbName)
		for _, schemaName := range schemas {
			qSchema := quoteIdentifier(schemaName)
			objectName := fmt.Sprintf("%s.%s", dbName, schemaName)
			query := fmt.Sprintf("GRANT USAGE ON SCHEMA %s.%s TO ROLE %s", qDB, qSchema, rp.qRole)
			if err := rp.execQuery(query); err != nil {
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "not authorized") {
					rp.logger.WarnContext(context.Background(), "Schema does not exist or not authorized for USAGE grant, skipping", "schema", objectName, "error", err)
					continue
				}
				return fmt.Errorf("failed to grant USAGE on schema %s to role %s: %w", objectName, rp.roleName, err)
			}
		}
		return nil
	}

	// Tables: handle USAGE on all schemas and future grants
	for _, tbl := range role.Permissions.Tables {
		nameParts := strings.SplitN(tbl.Name, ".", 3)
		if len(nameParts) < 3 {
			rp.logger.WarnContext(context.Background(), "Table permission name must be in format DATABASE.SCHEMA.TABLE, DATABASE.SCHEMA.*, DATABASE.*.*", "name", tbl.Name)
			continue
		}
		dbName, schemaPattern, tablePattern := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]

		if schemaPattern == "*" && tablePattern == "*" {
			if err := grantUsageOnAllSchemas(dbName); err != nil {
				return err
			}
		}

		if tablePattern == "*" {
			schemas, err := rp.GetSchemasInDatabase(dbName)
			if err != nil {
				rp.logger.ErrorContext(context.Background(), "Could not fetch schemas for future grants", "database", dbName, "error", err)
				continue
			}
			qDB := quoteIdentifier(dbName)
			for _, schemaName := range schemas {
				if !patternMatches(schemaPattern, schemaName) {
					continue
				}
				qSchema := quoteIdentifier(schemaName)
				objectName := fmt.Sprintf("%s.%s", dbName, schemaName)
				for _, privilege := range tbl.Grants {
					privilege = strings.ToUpper(privilege)
					query := fmt.Sprintf("GRANT %s ON FUTURE TABLES IN SCHEMA %s.%s TO ROLE %s", privilege, qDB, qSchema, rp.qRole)
					if err := rp.execQuery(query); err != nil {
						rp.logger.WarnContext(context.Background(), "Failed to grant future privilege on tables", "schema", objectName, "privilege", privilege, "error", err)
					}
				}
			}
		}
	}

	// Views: handle USAGE on all schemas and future grants
	for _, vw := range role.Permissions.Views {
		nameParts := strings.SplitN(vw.Name, ".", 3)
		if len(nameParts) < 3 {
			rp.logger.WarnContext(context.Background(), "View permission name must be in format DATABASE.SCHEMA.VIEW, DATABASE.SCHEMA.*, DATABASE.*.*", "name", vw.Name)
			continue
		}
		dbName, schemaPattern, viewPattern := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]

		if schemaPattern == "*" && viewPattern == "*" {
			if err := grantUsageOnAllSchemas(dbName); err != nil {
				return err
			}
		}

		if viewPattern == "*" {
			schemas, err := rp.GetSchemasInDatabase(dbName)
			if err != nil {
				rp.logger.ErrorContext(context.Background(), "Could not fetch schemas for future grants (views)", "database", dbName, "error", err)
				continue
			}
			qDB := quoteIdentifier(dbName)
			for _, schemaName := range schemas {
				if !patternMatches(schemaPattern, schemaName) {
					continue
				}
				qSchema := quoteIdentifier(schemaName)
				objectName := fmt.Sprintf("%s.%s", dbName, schemaName)
				for _, privilege := range vw.Grants {
					privilege = strings.ToUpper(privilege)
					query := fmt.Sprintf("GRANT %s ON FUTURE VIEWS IN SCHEMA %s.%s TO ROLE %s", privilege, qDB, qSchema, rp.qRole)
					if err := rp.execQuery(query); err != nil {
						rp.logger.WarnContext(context.Background(), "Failed to grant future privilege on views", "schema", objectName, "privilege", privilege, "error", err)
					}
				}
			}
		}
	}

	// Explicitly revoke future grants if no wildcard pattern is present in config
	// Build a set of (db, schema) for which a wildcard future grant is desired for tables/views
	dbSchemaFutureTables := make(map[string]struct{})
	dbSchemaFutureViews := make(map[string]struct{})
	for _, tbl := range role.Permissions.Tables {
		nameParts := strings.SplitN(tbl.Name, ".", 3)
		if len(nameParts) == 3 {
			db, schema, table := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]
			if table == "*" {
				key := db + "." + schema
				dbSchemaFutureTables[key] = struct{}{}
			}
		}
	}
	for _, vw := range role.Permissions.Views {
		nameParts := strings.SplitN(vw.Name, ".", 3)
		if len(nameParts) == 3 {
			db, schema, view := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]
			if view == "*" {
				key := db + "." + schema
				dbSchemaFutureViews[key] = struct{}{}
			}
		}
	}

	// For each database in config, enumerate all schemas and explicitly revoke future grants if not desired
	current := rp.fetchCurrentGrants()
	dbSet := make(map[string]struct{})
	for _, tbl := range role.Permissions.Tables {
		nameParts := strings.SplitN(tbl.Name, ".", 3)
		if len(nameParts) == 3 {
			db := strings.ToUpper(nameParts[0])
			dbSet[db] = struct{}{}
		}
	}
	for _, vw := range role.Permissions.Views {
		nameParts := strings.SplitN(vw.Name, ".", 3)
		if len(nameParts) == 3 {
			db := strings.ToUpper(nameParts[0])
			dbSet[db] = struct{}{}
		}
	}
	for db := range dbSet {
		schemas, err := rp.GetSchemasInDatabase(db)
		if err != nil {
			rp.logger.WarnContext(context.Background(), "Could not enumerate schemas for explicit future grant revoke", "database", db, "error", err)
			continue
		}
		for _, schema := range schemas {
			key := db + "." + schema
			// FUTURE_TABLE
			if _, want := dbSchemaFutureTables[key]; !want {
				for gk := range current {
					if gk.ObjectType == "FUTURE_TABLE" && gk.ObjectName == key {
						query := rp.buildRevokeQuery(gk)
						err := rp.execQuery(query)
						if err != nil {
							rp.logger.WarnContext(context.Background(), "Explicitly revoked future table grant", "query", query, "error", err)
						}
					}
				}
			}
			// FUTURE_VIEW
			if _, want := dbSchemaFutureViews[key]; !want {
				for gk := range current {
					if gk.ObjectType == "FUTURE_VIEW" && gk.ObjectName == key {
						query := rp.buildRevokeQuery(gk)
						err := rp.execQuery(query)
						if err != nil {
							rp.logger.WarnContext(context.Background(), "Explicitly revoked future view grant", "query", query, "error", err)
						}
					}
				}
			}
		}
	}

	return nil
}

// Process executes the role processing logic.
func (rp *RoleProcessor) Process() error {
	ctx := context.Background()
	if rp.rc == nil || len(rp.rc.Roles) == 0 {
		return errors.New("invalid or empty roles config")
	}

	var rolesConsidered, usersSkipped, rolesCreated int

	for _, role := range rp.rc.Roles {
		rolesConsidered++ // Count each role processed

		upperRole := strings.ToUpper(role.Name)
		rp.qRole = quoteIdentifier(upperRole)
		rp.roleName = upperRole

		if role.Remove {
			// If the role exists, drop it
			if _, exists := rp.existingRoles[upperRole]; exists {
				dropRoleQuery := "DROP ROLE IF EXISTS " + rp.qRole
				if rp.dryRun {
					rp.logger.InfoContext(context.Background(), "[DryRun] Would drop role", "query", dropRoleQuery)
				} else {
					rp.logger.InfoContext(context.Background(), "Dropping role", "query", dropRoleQuery, "role", rp.roleName)
					if _, err := rp.db.ExecContext(ctx, dropRoleQuery); err != nil {
						return fmt.Errorf("failed to drop role %s: %w", rp.roleName, err)
					}
				}
				delete(rp.existingRoles, upperRole)
			}
			continue // Skip further processing for removed roles
		}

		if _, exists := rp.existingRoles[upperRole]; !exists {
			if err := rp.createRoleIfNotExists(); err != nil {
				return err
			}
			rp.existingRoles[upperRole] = struct{}{}
			rolesCreated++
		}

		// fetch current grants ONCE for this role
		rp.currentGrants = rp.fetchCurrentGrants()

		// process warehouse creation and grants, except for system-defined roles
		if _, isSystem := systemRoles[rp.roleName]; !isSystem {
			warehouseName, err := rp.createWarehouseIfNotExists()
			if err != nil {
				return err
			}
			if err := rp.grantWarehouseToRole(warehouseName); err != nil {
				return err
			}
		}

		// process members
		us, err := rp.memberProcess(role)
		usersSkipped += us
		if err != nil {
			return fmt.Errorf("failed to process members for role %s: %w", rp.roleName, err)
		}

		// process permissions
		if err := rp.applySpecialGrants(role); err != nil {
			return fmt.Errorf("failed to process permissions for role %s: %w", rp.roleName, err)
		}

		// sync grants/revokes based on config
		if err := rp.syncRoleGrants(role); err != nil {
			return fmt.Errorf("failed to sync grants for role %s: %w", rp.roleName, err)
		}
	}

	rp.logger.InfoContext(context.Background(), "Grant summary",
		"rolesConsidered", rolesConsidered,
		"usersSkipped", usersSkipped,
		"rolesCreated", rolesCreated,
	)

	return nil
}

// FindNonExistentRoles returns roles defined in the config but missing in Snowflake.
func (rp *RoleProcessor) FindNonExistentRoles() []string {
	var missing []string
	if rp.rc == nil || len(rp.rc.Roles) == 0 {
		return missing
	}
	for _, role := range rp.rc.Roles {
		if _, ok := rp.existingRoles[strings.ToUpper(role.Name)]; !ok {
			missing = append(missing, role.Name)
		}
	}
	return missing
}

// GetSchemasInDatabase fetches all schemas in a given database.
func (rp *RoleProcessor) GetSchemasInDatabase(dbName string) ([]string, error) {
	ctx := context.Background()
	query := "SHOW SCHEMAS IN DATABASE " + quoteIdentifier(dbName)
	rows, err := rp.db.QueryContext(ctx, query)
	if err != nil {
		rp.logger.ErrorContext(context.Background(), "SHOW SCHEMAS failed", "database", dbName, "error", err)
		return nil, fmt.Errorf("SHOW SCHEMAS failed for database %s: %w", dbName, err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	nameIdx := -1
	for i, col := range cols {
		if strings.EqualFold(col, "name") {
			nameIdx = i
			break
		}
	}
	if nameIdx < 0 {
		return nil, errors.New("NAME column not found in SHOW SCHEMAS")
	}
	var schemas []string
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		vals := make([]any, len(cols))
		for i := range raw {
			vals[i] = &raw[i]
		}
		if err := rows.Scan(vals...); err != nil {
			return nil, err
		}
		if raw[nameIdx].Valid {
			schemas = append(schemas, raw[nameIdx].String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return schemas, nil
}

func patternMatches(pattern, candidate string) bool {
	pattern, candidate = strings.ToUpper(pattern), strings.ToUpper(candidate)
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(candidate, strings.Trim(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(candidate, strings.TrimLeft(pattern, "*"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(candidate, strings.TrimRight(pattern, "*"))
	}
	return pattern == candidate
}

// GetTablesInDatabase fetches all tables in a given database, grouped by schema.
func (rp *RoleProcessor) GetTablesInDatabase(dbName string) (map[string][]string, error) {
	ctx := context.Background()
	query := "SHOW TABLES IN DATABASE " + quoteIdentifier(dbName)
	rows, err := rp.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	schemaIdx, nameIdx := -1, -1
	for i, col := range cols {
		switch strings.ToLower(col) {
		case "schema_name":
			schemaIdx = i
		case "name":
			nameIdx = i
		}
	}
	if schemaIdx < 0 || nameIdx < 0 {
		return nil, errors.New("schema_name or name column not found in SHOW TABLES")
	}
	result := make(map[string][]string)
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		vals := make([]any, len(cols))
		for i := range raw {
			vals[i] = &raw[i]
		}
		if err := rows.Scan(vals...); err != nil {
			return nil, err
		}
		schema, table := raw[schemaIdx].String, raw[nameIdx].String
		result[schema] = append(result[schema], table)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetViewsInDatabase fetches all views in a given database, grouped by schema.
func (rp *RoleProcessor) GetViewsInDatabase(dbName string) (map[string][]string, error) {
	ctx := context.Background()
	query := "SHOW VIEWS IN DATABASE " + quoteIdentifier(dbName)
	rows, err := rp.db.QueryContext(ctx, query)
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "not found") {
			// Database or schema does not exist, treat as empty
			return map[string][]string{}, nil
		}
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	schemaIdx, nameIdx := -1, -1
	for i, col := range cols {
		switch strings.ToLower(col) {
		case "schema_name":
			schemaIdx = i
		case "name":
			nameIdx = i
		}
	}
	if schemaIdx < 0 || nameIdx < 0 {
		return nil, errors.New("schema_name or name column not found in SHOW VIEWS")
	}
	result := make(map[string][]string)
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		vals := make([]any, len(cols))
		for i := range raw {
			vals[i] = &raw[i]
		}
		if err := rows.Scan(vals...); err != nil {
			return nil, err
		}
		schema, view := raw[schemaIdx].String, raw[nameIdx].String
		result[schema] = append(result[schema], view)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// ValidateRolesConfig ensures the YAML structure and content validity for roles config.
func ValidateRolesConfig(rc *RolesConfig) error {
	if len(rc.Roles) == 0 {
		return errors.New("roles must contain at least one role")
	}
	for _, role := range rc.Roles {
		if strings.TrimSpace(role.Name) == "" {
			return errors.New("role name cannot be empty")
		}
		if len(role.Members) == 0 {
			return fmt.Errorf("role '%s' must have at least one member", role.Name)
		}
		for _, m := range role.Members {
			if strings.TrimSpace(m.Email) == "" {
				return fmt.Errorf("member in role '%s' has empty email", role.Name)
			}
		}
		// TODO Optionally validate permissions structure here if needed
	}
	return nil
}

// VerifyRolesInSnowflake checks that all roles in YAML exist in Snowflake.
func (rp *RoleProcessor) VerifyRolesInSnowflake() error {
	missing := rp.FindNonExistentRoles()
	if len(missing) > 0 {
		return fmt.Errorf("missing roles: %v", missing)
	}
	return nil
}

// FetchedRoleGrant represents a single grant row from SHOW GRANTS TO ROLE or SHOW GRANTS ON ...
type FetchedRoleGrant struct {
	CreatedOn         string // Timestamp as string (can be parsed to time.Time if needed)
	Privilege         string
	GrantedOn         string
	Name              string
	GrantedTo         string
	GranteeName       string
	GrantOption       string // "true"/"false" as string
	GrantedByRoleType string
	GrantedBy         string
}

// FetchRoleGrants retrieves all grants assigned to a given role using SHOW GRANTS TO ROLE <name>.
// Returns a slice of FetchedRoleGrant for each grant.
func (rp *RoleProcessor) FetchRoleGrants(roleName string) ([]FetchedRoleGrant, error) {
	logger := rp.logger
	ctx := context.Background()
	qRole := quoteIdentifier(strings.ToUpper(roleName))
	query := "SHOW GRANTS TO ROLE " + qRole
	rows, err := rp.db.QueryContext(ctx, query)
	if err != nil {
		logger.ErrorContext(context.Background(), "query SHOW GRANTS TO ROLE failed", "error", err, "role", roleName)
		return nil, fmt.Errorf("error querying SHOW GRANTS TO ROLE %s: %w", roleName, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns for SHOW GRANTS TO ROLE: %w", err)
	}

	var results []FetchedRoleGrant
	for rows.Next() {
		raw := make([]sql.NullString, len(cols))
		vals := make([]any, len(cols))
		for i := range raw {
			vals[i] = &raw[i]
		}
		if err := rows.Scan(vals...); err != nil {
			logger.ErrorContext(context.Background(), "scanning SHOW GRANTS TO ROLE row failed", "error", err)
			return nil, fmt.Errorf("error scanning SHOW GRANTS TO ROLE: %w", err)
		}
		var grant FetchedRoleGrant
		for i, col := range cols {
			val := ""
			if raw[i].Valid {
				val = raw[i].String
			}
			switch strings.ToLower(col) {
			case "created_on":
				grant.CreatedOn = val
			case "privilege":
				grant.Privilege = val
			case "granted_on":
				grant.GrantedOn = val
			case "name":
				grant.Name = val
			case "granted_to":
				grant.GrantedTo = val
			case "grantee_name":
				grant.GranteeName = val
			case "grant_option":
				grant.GrantOption = val
			case "granted_by_role_type":
				grant.GrantedByRoleType = val
			case "granted_by":
				grant.GrantedBy = val
			}
		}
		results = append(results, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iteration error on SHOW GRANTS TO ROLE: %w", err)
	}
	return results, nil
}

// Compute set difference a - b
func difference(a, b map[GrantKey]struct{}) map[GrantKey]struct{} {
	result := make(map[GrantKey]struct{})
	for k := range a {
		if _, ok := b[k]; !ok {
			result[k] = struct{}{}
		}
	}
	return result
}

// Build GrantKey set from config, expanding wildcards for tables/views
func (rp *RoleProcessor) buildDesiredGrantsFromConfig(role Role) map[GrantKey]struct{} {
	rp.logger.InfoContext(context.Background(), "Building desired grants from config", "role", role.Name)
	grants := make(map[GrantKey]struct{})
	if role.Permissions == nil {
		return grants
	}
	// Databases
	for _, db := range role.Permissions.Databases {
		for _, priv := range db.Grants {
			gk := GrantKey{Privilege: strings.ToUpper(priv), ObjectType: "DATABASE", ObjectName: normalizeObjectName(db.Name)}
			grants[gk] = struct{}{}
		}
	}
	// Schemas
	for _, sch := range role.Permissions.Schemas {
		for _, priv := range sch.Grants {
			gk := GrantKey{Privilege: strings.ToUpper(priv), ObjectType: "SCHEMA", ObjectName: normalizeObjectName(sch.Name)}
			grants[gk] = struct{}{}
		}
	}

	// --- Caching for tables/views ---
	tablesCache := make(map[string]map[string][]string)
	viewsCache := make(map[string]map[string][]string)

	// Tables (expand wildcards to all real tables)
	for _, tbl := range role.Permissions.Tables {
		nameParts := strings.SplitN(tbl.Name, ".", 3)
		if len(nameParts) < 3 {
			continue
		}
		dbName, schemaPattern, tablePattern := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]
		var tablesBySchema map[string][]string
		var ok bool
		if tablesBySchema, ok = tablesCache[dbName]; !ok {
			t, err := rp.GetTablesInDatabase(dbName)
			if err != nil {
				continue
			}
			tablesBySchema = t
			tablesCache[dbName] = t
		}
		for schema, tables := range tablesBySchema {
			if !patternMatches(schemaPattern, schema) {
				continue
			}
			for _, table := range tables {
				if !patternMatches(tablePattern, table) {
					continue
				}
				objectName := normalizeObjectName(fmt.Sprintf("%s.%s.%s", dbName, schema, table))
				for _, priv := range tbl.Grants {
					gk := GrantKey{Privilege: strings.ToUpper(priv), ObjectType: "TABLE", ObjectName: objectName}
					grants[gk] = struct{}{}
				}
			}
		}
	}
	// Views (expand wildcards to all real views)
	for _, vw := range role.Permissions.Views {
		nameParts := strings.SplitN(vw.Name, ".", 3)
		if len(nameParts) < 3 {
			continue
		}
		dbName, schemaPattern, viewPattern := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]
		var viewsBySchema map[string][]string
		var ok bool
		if viewsBySchema, ok = viewsCache[dbName]; !ok {
			v, err := rp.GetViewsInDatabase(dbName)
			if err != nil {
				continue
			}
			viewsBySchema = v
			viewsCache[dbName] = v
		}
		for schema, views := range viewsBySchema {
			if !patternMatches(schemaPattern, schema) {
				continue
			}
			for _, view := range views {
				if !patternMatches(viewPattern, view) {
					continue
				}
				objectName := normalizeObjectName(fmt.Sprintf("%s.%s.%s", dbName, schema, view))
				for _, priv := range vw.Grants {
					gk := GrantKey{Privilege: strings.ToUpper(priv), ObjectType: "VIEW", ObjectName: objectName}
					grants[gk] = struct{}{}
				}
			}
		}
	}

	// Add warehouse usage grant as part of desired grants because it is a default requirement
	warehouseName := rp.roleName + "_WAREHOUSE"
	gk := GrantKey{
		Privilege:  "USAGE",
		ObjectType: "WAREHOUSE",
		ObjectName: strings.ToUpper(warehouseName),
	}
	grants[gk] = struct{}{}

	return grants
}

// Build GrantKey set from current grants
func (rp *RoleProcessor) fetchCurrentGrants() map[GrantKey]struct{} {
	result := make(map[GrantKey]struct{})
	grantRows, err := rp.FetchRoleGrants(rp.roleName)
	if err != nil {
		rp.logger.ErrorContext(context.Background(), "Failed to fetch current grants", "role", rp.roleName, "error", err)
		return result
	}
	for _, g := range grantRows {
		gk := GrantKey{Privilege: strings.ToUpper(g.Privilege), ObjectType: strings.ToUpper(g.GrantedOn), ObjectName: normalizeObjectName(g.Name)}
		result[gk] = struct{}{}
	}
	return result
}

// Build GRANT statement from GrantKey
func (rp *RoleProcessor) buildGrantStatement(g GrantKey) string {
	return fmt.Sprintf("GRANT %s ON %s %s TO ROLE %s", g.Privilege, g.ObjectType, g.ObjectName, rp.qRole)
}

// Build REVOKE statement from GrantKey
func (rp *RoleProcessor) buildRevokeQuery(g GrantKey) string {
	return fmt.Sprintf("REVOKE %s ON %s %s FROM ROLE %s", g.Privilege, g.ObjectType, g.ObjectName, rp.qRole)
}

// Main sync logic
func (rp *RoleProcessor) syncRoleGrants(role Role) error {
	// If no permissions in config, skip all revokes
	if (role.Name == "ACCOUNTADMIN" || role.Name == "ORGADMIN" ||
		role.Name == "SYSADMIN" || role.Name == "SECURITYADMIN" || role.Name == "USERADMIN") ||
		role.Permissions == nil || (len(role.Permissions.Databases) == 0 &&
		len(role.Permissions.Schemas) == 0 &&
		len(role.Permissions.Tables) == 0 &&
		len(role.Permissions.Views) == 0) {
		return nil
	}

	current := rp.currentGrants
	desired := rp.buildDesiredGrantsFromConfig(role)
	toAdd := difference(desired, current)
	toRevoke := difference(current, desired)

	// Filter out OWNERSHIP grants (cannot be revoked, only transferred)
	filteredToRevoke := make(map[GrantKey]struct{})
	for gk := range toRevoke {
		if strings.ToUpper(gk.Privilege) == "OWNERSHIP" {
			continue
		}
		filteredToRevoke[gk] = struct{}{}
	}
	toRevoke = filteredToRevoke

	for gk := range toAdd {
		stmt := rp.buildGrantStatement(gk)
		err := rp.execQuery(stmt)
		if err != nil {
			rp.logger.WarnContext(context.Background(), "Failed to grant", "stmt", stmt, "error", err)
			return err
		}
	}
	for gk := range toRevoke {
		stmt := rp.buildRevokeQuery(gk)
		err := rp.execQuery(stmt)
		if err != nil {
			rp.logger.WarnContext(context.Background(), "Failed to revoke", "stmt", stmt, "error", err)
			return err
		}
	}
	return nil
}
