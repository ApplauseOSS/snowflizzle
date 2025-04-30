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

package role

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/applauseoss/snowflizzle/internal/logging"
	"gopkg.in/yaml.v3"
)

// RoleMap represents the structure of the rolesmap YAML file
type RoleMap struct {
	Roles map[string][]string `yaml:"roles"`
}

// LoadRoleMap parses the YAML file into a RoleMap struct
func LoadRoleMap(filePath string) (*RoleMap, error) {
	logger := logging.GetLogger()
	if filePath == "" {
		return nil, errors.New("no file provided")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("failed to close file", "error", err)
		}
	}()

	var roleMap RoleMap
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&roleMap); err != nil {
		return nil, fmt.Errorf("failed to parse file as YAML: %w", err)
	}
	return &roleMap, nil
}

// FetchShowRoles returns a set of role names from SHOW ROLES
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
	vals := make([]interface{}, len(cols))
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

// FetchShowUsers returns a map from login_name to NAME from SHOW USERS
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
	vals := make([]interface{}, len(cols))
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
			users[login.String] = name.String
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iteration error on SHOW USERS: %w", err)
	}
	return users, nil
}

// FindNonExistentRoles returns roles defined in map but missing in Snowflake
func FindNonExistentRoles(rm *RoleMap, existing map[string]struct{}) []string {
	var missing []string
	if rm == nil || rm.Roles == nil {
		return missing
	}
	for role := range rm.Roles {
		if _, ok := existing[role]; !ok {
			missing = append(missing, role)
		}
	}
	return missing
}

// ValidateRolesFile ensures YAML structure and content validity
func ValidateRolesFile(filePath string) (*RoleMap, error) {
	rm, err := LoadRoleMap(filePath)
	if err != nil {
		return nil, err
	}
	if len(rm.Roles) == 0 {
		return nil, errors.New("roles must contain at least one role")
	}
	for role, users := range rm.Roles {
		if role == "" {
			return nil, errors.New("role name cannot be empty")
		}
		if len(users) == 0 {
			return nil, fmt.Errorf("role '%s' must have at least one user", role)
		}
		for _, u := range users {
			if u == "" {
				return nil, fmt.Errorf("user in role '%s' cannot be empty", role)
			}
		}
	}
	return rm, nil
}

// quoteIdentifier escapes and quotes a Snowflake identifier
func quoteIdentifier(id string) string {
	esc := strings.ReplaceAll(id, `"`, `""`)
	return `"` + esc + `"`
}

// GrantRolesToUsers grants roles to users; accepts *sql.DB
func GrantRolesToUsers(db *sql.DB, rm *RoleMap, dryRun bool) error {
	logger := logging.GetLogger()
	if rm == nil || rm.Roles == nil {
		return errors.New("invalid or empty role map")
	}

	existingRoles, err := FetchShowRoles(db)
	if err != nil {
		return err
	}
	existingUsers, err := FetchShowUsers(db)
	if err != nil {
		return err
	}

	var considered, skipped, executed int
	for role, users := range rm.Roles {
		upperRole := strings.ToUpper(role)
		if _, ok := existingRoles[upperRole]; !ok {
			skipped += len(users)
			logger.Warn("skipping non-existent role", "role", role)
			continue
		}
		qRole := quoteIdentifier(role)
		for _, userKey := range users {
			considered++
			upperUserKey := strings.ToUpper(userKey)
			userName, ok := existingUsers[upperUserKey]
			if !ok {
				skipped++
				logger.Warn("skipping non-existent user", "user", userKey)
				continue
			}
			qUser := quoteIdentifier(userName)
			query := fmt.Sprintf("GRANT ROLE %s TO USER %s", qRole, qUser)
			if dryRun {
				logger.Info("[DryRun]", "query", query)
				continue
			}
			logger.Info("executing query", "query", query)
			if _, err := db.Exec(query); err != nil {
				return fmt.Errorf("grant failed for %s->%s: %w", role, userName, err)
			}
			executed++
		}
	}
	logger.Info("grant summary", "considered", considered, "skipped", skipped, "executed", executed)
	return nil
}

// VerifyRolesInSnowflake checks that all roles in YAML exist in Snowflake
func VerifyRolesInSnowflake(db *sql.DB, rm *RoleMap) error {
	existing, err := FetchShowRoles(db)
	if err != nil {
		return err
	}
	missing := FindNonExistentRoles(rm, existing)
	if len(missing) > 0 {
		return fmt.Errorf("missing roles: %v", missing)
	}
	return nil
}
