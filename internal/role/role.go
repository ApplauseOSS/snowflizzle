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

// RolePermissions represents permissions for a role, including databases, schemas, and tables.
type RolePermissions struct {
	Databases []DatabasePermission `yaml:"databases,omitempty"`
	Schemas   []SchemaPermission   `yaml:"schemas,omitempty"`
	Tables    []TablePermission    `yaml:"tables,omitempty"`
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
			logger.Error("failed to close file", "error", cerr)
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
	rows, err := db.Query("SHOW ROLES")
	if err != nil {
		logger.Error("query SHOW ROLES failed", "error", err)
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
			logger.Error("scanning SHOW ROLES row failed", "error", err)
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
	rows, err := db.Query("SHOW USERS")
	if err != nil {
		logger.Error("query SHOW USERS failed", "error", err)
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
			logger.Error("scanning SHOW USERS row failed", "error", err)
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
	rows, err := db.Query("SHOW WAREHOUSES")
	if err != nil {
		logger.Error("query SHOW WAREHOUSES failed", "error", err)
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
			logger.Error("scanning SHOW WAREHOUSES row failed", "error", err)
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
		rp.logger.Warn("Dry run enabled with nil DB — skipping role/user fetch")
		rp.existingRoles = make(map[string]struct{})
		rp.existingUsers = make(map[string]string)
		return nil
	}
	var err error
	rp.existingRoles, err = FetchShowRoles(rp.db)
	if err != nil {
		rp.logger.Error("Failed to fetch roles from Snowflake", "error", err)
		return err
	}
	rp.existingUsers, err = FetchShowUsers(rp.db)
	if err != nil {
		rp.logger.Error("Failed to fetch users from Snowflake", "error", err)
		return err
	}
	rp.existingWarehouses, err = FetchShowWarehouses(rp.db)
	if err != nil {
		rp.logger.Error("Failed to fetch warehouses from Snowflake", "error", err)
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
	if rp.dryRun {
		rp.logger.Info("[DryRun] Would create role", "query", createRoleQuery, "role", rp.roleName)
		return nil
	}
	rp.logger.Info("Creating role", "query", createRoleQuery, "role", rp.roleName)
	if _, err := rp.db.Exec(createRoleQuery); err != nil {
		return fmt.Errorf("failed to create role %s: %w", rp.roleName, err)
	}
	return nil
}

// createWarehouseIfNotExists creates a warehouse with the same name as the role, uppercased and postfixed with _WH, if it does not exist.
func (rp *RoleProcessor) createWarehouseIfNotExists() error {
	warehouseName := rp.roleName + "_WAREHOUSE"
	qWarehouse := quoteIdentifier(warehouseName)

	// Use cached warehouses instead of fetching every time
	if _, exists := rp.existingWarehouses[warehouseName]; exists {
		rp.logger.Info("Warehouse already exists", "warehouse", warehouseName)
		return nil
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
	if rp.dryRun {
		rp.logger.Info("[DryRun] Would create warehouse", "query", createWarehouseQuery, "warehouse", warehouseName)
		return nil
	}
	rp.logger.Info("Creating warehouse", "query", createWarehouseQuery, "warehouse", warehouseName)
	if _, err := rp.db.Exec(createWarehouseQuery); err != nil {
		return fmt.Errorf("failed to create warehouse %s: %w", warehouseName, err)
	}
	// Add to cache so subsequent calls know it exists
	rp.existingWarehouses[warehouseName] = warehouseName
	return nil
}

func (rp *RoleProcessor) grantRoleToUser() error {
	query := fmt.Sprintf("GRANT ROLE %s TO USER %s", rp.qRole, rp.qUser)
	if rp.dryRun {
		rp.logger.Info("[DryRun] Would execute", "query", query, "role", rp.roleName, "user", rp.displayUser)
		return nil
	}
	rp.logger.Info("Executing query", "query", query, "role", rp.roleName, "user", rp.displayUser)
	if _, err := rp.db.Exec(query); err != nil {
		return fmt.Errorf("grant failed for %s -> %s: %w", rp.roleName, rp.displayUser, err)
	}
	return nil
}

func (rp *RoleProcessor) grantWarehouseToRole() error {
	warehouseName := rp.roleName + "_WH"
	qWarehouse := quoteIdentifier(warehouseName)
	grantQuery := fmt.Sprintf("GRANT USAGE ON WAREHOUSE %s TO ROLE %s", qWarehouse, rp.qRole)
	if rp.dryRun {
		rp.logger.Info("[DryRun] Would grant warehouse usage", "query", grantQuery, "warehouse", warehouseName, "role", rp.roleName)
		return nil
	}
	rp.logger.Info("Granting warehouse usage", "query", grantQuery, "warehouse", warehouseName, "role", rp.roleName)
	if _, err := rp.db.Exec(grantQuery); err != nil {
		return fmt.Errorf("failed to grant USAGE on warehouse %s to role %s: %w", warehouseName, rp.roleName, err)
	}
	return nil
}

func (rp *RoleProcessor) revokeRoleFromUser() error {
	//nolint:gosec // G202: Identifiers are quoted using quoteIdentifier
	query := "REVOKE ROLE " + rp.qRole + " FROM USER " + rp.qUser
	if rp.dryRun {
		rp.logger.Info("[DryRun] Would execute", "query", query, "role", rp.roleName, "user", rp.displayUser)
		return nil
	}
	rp.logger.Info("Executing revoke", "query", query, "role", rp.roleName, "user", rp.displayUser)
	if _, err := rp.db.Exec(query); err != nil {
		return fmt.Errorf("failed to revoke role %s from user %s: %w", rp.roleName, rp.displayUser, err)
	}
	return nil
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
				rp.logger.Warn("Skipping non-existent member", "member", member.Email)
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

func (rp *RoleProcessor) execPrivilegeQuery(query, action, objectType, objectName, privilege string, dryRun bool) error {
	if dryRun {
		rp.logger.Info(fmt.Sprintf("[DryRun] Would %s %s privilege", action, objectType),
			"query", query, "object", objectName, "privilege", privilege, "role", rp.roleName)
		return nil
	}
	rp.logger.Info(fmt.Sprintf("%s %s privilege", action, objectType),
		"query", query, "object", objectName, "privilege", privilege, "role", rp.roleName)
	_, err := rp.db.Exec(query)
	return err
}

func (rp *RoleProcessor) permissionProcess(role Role) error {
	if role.Permissions == nil {
		return nil
	}
	// Process database permissions
	for _, dbPerm := range role.Permissions.Databases {
		dbName := dbPerm.Name
		qDB := quoteIdentifier(strings.ToUpper(dbName))
		if dbPerm.Remove {
			if len(dbPerm.Grants) == 0 {
				revokeQuery := fmt.Sprintf("REVOKE ALL PRIVILEGES ON DATABASE %s FROM ROLE %s", qDB, rp.qRole)
				if err := rp.execPrivilegeQuery(revokeQuery, "revoke", "database", dbName, "ALL PRIVILEGES", rp.dryRun); err != nil {
					return fmt.Errorf("failed to revoke privileges on database %s from role %s: %w", dbName, rp.roleName, err)
				}
			} else {
				for _, grant := range dbPerm.Grants {
					revokeQuery := fmt.Sprintf("REVOKE %s ON DATABASE %s FROM ROLE %s", strings.ToUpper(grant), qDB, rp.qRole)
					if err := rp.execPrivilegeQuery(revokeQuery, "revoke", "database", dbName, grant, rp.dryRun); err != nil {
						return fmt.Errorf("failed to revoke %s on database %s from role %s: %w", grant, dbName, rp.roleName, err)
					}
				}
			}
		} else {
			if len(dbPerm.Grants) == 0 {
				continue
			}
			for _, grant := range dbPerm.Grants {
				grantQuery := fmt.Sprintf("GRANT %s ON DATABASE %s TO ROLE %s", strings.ToUpper(grant), qDB, rp.qRole)
				if err := rp.execPrivilegeQuery(grantQuery, "grant", "database", dbName, grant, rp.dryRun); err != nil {
					return fmt.Errorf("failed to grant %s on database %s to role %s: %w", grant, dbName, rp.roleName, err)
				}
			}
		}
	}
	// Process schema permissions
	for _, sch := range role.Permissions.Schemas {
		nameParts := strings.SplitN(sch.Name, ".", 2)
		if len(nameParts) < 2 {
			rp.logger.Warn("Schema permission name must be in format DATABASE.SCHEMA or wildcard", "name", sch.Name)
			continue
		}
		dbName := strings.ToUpper(nameParts[0])
		schemaPattern := nameParts[1]

		// Fetch all schemas in the database
		schemas, err := rp.GetSchemasInDatabase(dbName)
		if err != nil {
			rp.logger.Error("Could not fetch schemas", "database", dbName, "error", err)
			continue
		}

		// Grant/revoke on all matching schemas
		matched := 0
		for _, actualSchema := range schemas {
			if !patternMatches(schemaPattern, actualSchema) {
				continue
			}
			matched++
			qDB := quoteIdentifier(dbName)
			qSchema := quoteIdentifier(actualSchema)
			objectName := fmt.Sprintf("%s.%s", dbName, actualSchema)
			if sch.Remove && len(sch.Grants) == 0 {
				query := fmt.Sprintf("REVOKE ALL PRIVILEGES ON SCHEMA %s.%s FROM ROLE %s", qDB, qSchema, rp.qRole)
				action := "revoke"
				if err := rp.execPrivilegeQuery(query, action, "schema", objectName, "ALL PRIVILEGES", rp.dryRun); err != nil {
					return fmt.Errorf("failed to revoke all privileges on schema %s from role %s: %w", objectName, rp.roleName, err)
				}
			} else {
				for _, grant := range sch.Grants {
					grant = strings.ToUpper(grant)
					var query, action string
					if sch.Remove {
						query = fmt.Sprintf("REVOKE %s ON SCHEMA %s.%s FROM ROLE %s", grant, qDB, qSchema, rp.qRole)
						action = "revoke"
					} else {
						query = fmt.Sprintf("GRANT %s ON SCHEMA %s.%s TO ROLE %s", grant, qDB, qSchema, rp.qRole)
						action = "grant"
					}
					if err := rp.execPrivilegeQuery(query, action, "schema", objectName, grant, rp.dryRun); err != nil {
						return fmt.Errorf("failed to %s %s on schema %s from/to role %s: %w", action, grant, objectName, rp.roleName, err)
					}
				}
			}
		}
		if matched == 0 {
			rp.logger.Warn("No schemas matched pattern", "pattern", schemaPattern, "database", dbName)
		}
	}

	// Process table permissions
	for _, tbl := range role.Permissions.Tables {
		nameParts := strings.SplitN(tbl.Name, ".", 3)
		if len(nameParts) < 3 {
			rp.logger.Warn("Table permission name must be in format DATABASE.SCHEMA.TABLE, DATABASE.SCHEMA.*, DATABASE.*.*", "name", tbl.Name)
			continue
		}
		dbName, schemaPattern, tablePattern := strings.ToUpper(nameParts[0]), nameParts[1], nameParts[2]
		tablesBySchema, err := rp.GetTablesInDatabase(dbName)
		if err != nil {
			rp.logger.Error("Could not fetch tables", "database", dbName, "error", err)
			continue
		}

		matched := 0
		for schema, tables := range tablesBySchema {
			if !patternMatches(schemaPattern, schema) {
				continue
			}
			for _, table := range tables {
				if !patternMatches(tablePattern, table) {
					continue
				}
				matched++
				qDB := quoteIdentifier(dbName)
				qSchema := quoteIdentifier(schema)
				qTable := quoteIdentifier(table)
				objectName := fmt.Sprintf("%s.%s.%s", dbName, schema, table)
				if tbl.Remove && len(tbl.Grants) == 0 {
					query := fmt.Sprintf("REVOKE ALL PRIVILEGES ON TABLE %s.%s.%s FROM ROLE %s", qDB, qSchema, qTable, rp.qRole)
					action := "revoke"
					if err := rp.execPrivilegeQuery(query, action, "table", objectName, "ALL PRIVILEGES", rp.dryRun); err != nil {
						return fmt.Errorf("failed to revoke all privileges on table %s from role %s: %w", objectName, rp.roleName, err)
					}
				} else {
					for _, grant := range tbl.Grants {
						grant = strings.ToUpper(grant)
						var query, action string
						if tbl.Remove {
							query = fmt.Sprintf("REVOKE %s ON TABLE %s.%s.%s FROM ROLE %s", grant, qDB, qSchema, qTable, rp.qRole)
							action = "revoke"
						} else {
							query = fmt.Sprintf("GRANT %s ON TABLE %s.%s.%s TO ROLE %s", grant, qDB, qSchema, qTable, rp.qRole)
							action = "grant"
						}
						if err := rp.execPrivilegeQuery(query, action, "table", objectName, grant, rp.dryRun); err != nil {
							return fmt.Errorf("failed to %s %s on table %s from/to role %s: %w", action, grant, objectName, rp.roleName, err)
						}
					}
				}
			}
		}
		if matched == 0 {
			rp.logger.Warn("No tables matched pattern", "pattern", tbl.Name, "database", dbName)
		}
	}
	return nil
}

// Process executes the role processing logic.
func (rp *RoleProcessor) Process() error {
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
					rp.logger.Info("[DryRun] Would drop role", "query", dropRoleQuery, "role", rp.roleName)
				} else {
					rp.logger.Info("Dropping role", "query", dropRoleQuery, "role", rp.roleName)
					if _, err := rp.db.Exec(dropRoleQuery); err != nil {
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

		// process warehouse creation and grants, except for system-defined roles
		if _, isSystem := systemRoles[rp.roleName]; !isSystem {
			if err := rp.createWarehouseIfNotExists(); err != nil {
				return err
			}
			if err := rp.grantWarehouseToRole(); err != nil {
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
		if err := rp.permissionProcess(role); err != nil {
			return fmt.Errorf("failed to process permissions for role %s: %w", rp.roleName, err)
		}
	}

	rp.logger.Info("Grant summary",
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
	query := "SHOW SCHEMAS IN DATABASE " + quoteIdentifier(dbName)
	rows, err := rp.db.Query(query)
	if err != nil {
		rp.logger.Error("SHOW SCHEMAS failed", "database", dbName, "error", err)
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
	query := "SHOW TABLES IN DATABASE " + quoteIdentifier(dbName)
	rows, err := rp.db.Query(query)
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
		// Optionally validate permissions structure here if needed
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
	qRole := quoteIdentifier(strings.ToUpper(roleName))
	query := "SHOW GRANTS TO ROLE " + qRole
	rows, err := rp.db.Query(query)
	if err != nil {
		logger.Error("query SHOW GRANTS TO ROLE failed", "error", err, "role", roleName)
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
			logger.Error("scanning SHOW GRANTS TO ROLE row failed", "error", err)
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
