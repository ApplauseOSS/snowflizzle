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
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestValidateRolesFile(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectedError bool
		errorContains string
	}{
		{
			name: "valid_roles_file",
			content: `roles:
  - name: ANALYST
    members:
      - email: user1@example.com
      - email: user2@example.com
  - name: DEVELOPER
    members:
      - email: user3@example.com
`,
			expectedError: false,
		},
		{
			name:          "empty_file",
			content:       `roles: []`,
			expectedError: true,
			errorContains: "roles must contain at least one role",
		},
		{
			name: "empty_role_name",
			content: `roles:
  - name: ""
    members:
      - email: user1@example.com
`,
			expectedError: true,
			errorContains: "role name cannot be empty",
		},
		{
			name: "role_with_no_users",
			content: `roles:
  - name: ANALYST
    members: []
`,
			expectedError: true,
			errorContains: "must have at least one member",
		},
		{
			name: "role_with_empty_user",
			content: `roles:
  - name: ANALYST
    members:
      - email: ""
`,
			expectedError: true,
			errorContains: "member in role 'ANALYST' has empty email",
		},
		{
			name: "invalid_yaml",
			content: `roles:
  - name: ANALYST
    members:
      - email: user1@example.com
  - name: DEVELOPER
    members: invalid
`,
			expectedError: true,
			errorContains: "failed to parse file as YAML",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "roles.yaml")

			err := os.WriteFile(tmpFile, []byte(tc.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			rc, err := LoadRolesConfig(tmpFile)
			if err != nil {
				if tc.expectedError {
					if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
						t.Errorf("Error message doesn't contain expected text. Got: %v, Want: %v", err.Error(), tc.errorContains)
					}
				} else {
					t.Fatalf("Failed to load roles config: %v", err)
				}
				return
			}

			err = ValidateRolesConfig(rc)
			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tc.errorContains != "" && !strings.Contains(err.Error(), tc.errorContains) {
					t.Errorf("Error message doesn't contain expected text. Got: %v, Want: %v", err.Error(), tc.errorContains)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if rc == nil {
					t.Errorf("Expected non-nil rolesConfig but got nil")
				}
			}
		})
	}

	// Test with non-existent file
	t.Run("non_existent_file", func(t *testing.T) {
		_, err := LoadRolesConfig("/path/to/nonexistent/file.yaml")
		if err == nil {
			t.Errorf("Expected error for non-existent file but got nil")
		}
	})
}

func TestFetchShowRoles(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error creating sqlmock: %v", err)
	}
	defer db.Close()

	// SHOW ROLES returns columns like (created_on, name, ...).
	// We only care that "name" appears somewhere.
	columns := []string{"ignored1", "name", "ignored2"}
	rows := sqlmock.NewRows(columns).
		AddRow("2025-01-01", "ADMIN", "X").
		AddRow("2025-01-02", "USER", "Y")

	mock.ExpectQuery(`SHOW ROLES`).WillReturnRows(rows)

	got, err := FetchShowRoles(db)
	if err != nil {
		t.Fatalf("FetchShowRoles returned error: %v", err)
	}

	want := map[string]struct{}{
		"ADMIN": {},
		"USER":  {},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got roles %v; want %v", got, want)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFetchShowUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error creating sqlmock: %v", err)
	}
	defer db.Close()

	columns := []string{"name", "disabled", "login_name"}
	rows := sqlmock.NewRows(columns).
		AddRow("john", "true", "john@example.com").
		AddRow("sandra", "false", "sandra@example.com")

	mock.ExpectQuery(`SHOW USERS`).WillReturnRows(rows)

	got, err := FetchShowUsers(db)
	if err != nil {
		t.Fatalf("FetchShowUsers returned error: %v", err)
	}

	want := map[string]string{
		"JOHN@EXAMPLE.COM":   "john",
		"SANDRA@EXAMPLE.COM": "sandra",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got users %v; want %v", got, want)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestFindNonExistentRoles(t *testing.T) {
	existing := map[string]struct{}{
		"ADMIN":     {},
		"DEVELOPER": {},
	}

	tests := []struct {
		name     string
		rolesCfg *RolesConfig
		expected []string
	}{
		{
			name: "all roles exist",
			rolesCfg: &RolesConfig{
				Roles: []Role{
					{Name: "ADMIN", Members: []RoleMember{{Email: "user1"}}},
				},
			},
			expected: []string{},
		},
		{
			name: "some roles missing",
			rolesCfg: &RolesConfig{
				Roles: []Role{
					{Name: "ADMIN", Members: []RoleMember{{Email: "user1"}}},
					{Name: "ANALYST", Members: []RoleMember{{Email: "user2"}}},
					{Name: "REPORTER", Members: []RoleMember{{Email: "user3"}}},
				},
			},
			expected: []string{"ANALYST", "REPORTER"},
		},
		{
			name:     "nil roles config",
			rolesCfg: nil,
			expected: []string{},
		},
		{
			name:     "empty roles",
			rolesCfg: &RolesConfig{Roles: []Role{}},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rp := &RoleProcessor{
				rc:            tc.rolesCfg,
				existingRoles: existing,
			}
			result := rp.FindNonExistentRoles()

			// Sort for consistent comparison
			sortedResult := make([]string, len(result))
			copy(sortedResult, result)
			sort.Strings(sortedResult)

			sortedExpected := make([]string, len(tc.expected))
			copy(sortedExpected, tc.expected)
			sort.Strings(sortedExpected)

			if !reflect.DeepEqual(sortedResult, sortedExpected) {
				t.Errorf("Expected non-existent roles %v, but got %v", tc.expected, result)
			}
		})
	}
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		pattern   string
		candidate string
		want      bool
	}{
		{"*", "ANYTHING", true},
		{"FOO", "FOO", true},
		{"FOO", "foo", true},
		{"FOO", "BAR", false},
		{"FO*", "FOOBAR", true},
		{"*BAR", "FOOBAR", true},
		{"*BAR*", "FOOBARBAZ", true},
		{"*BAR*", "BAZ", false},
		{"*FOO*", "FOO", true},
		{"*FOO*", "BARFOOBAZ", true},
		{"*FOO", "BARFOO", true},
		{"FOO*", "FOOBAR", true},
		{"FOO*", "BARFOO", false},
		{"*FOO", "FOOBAR", false},
	}
	for _, tc := range tests {
		t.Run(tc.pattern+"_"+tc.candidate, func(t *testing.T) {
			got := patternMatches(tc.pattern, tc.candidate)
			if got != tc.want {
				t.Errorf("patternMatches(%q, %q) = %v; want %v", tc.pattern, tc.candidate, got, tc.want)
			}
		})
	}
}

func TestYAMLParsingAndValidation(t *testing.T) {
	const validYAML = `
roles:
  - name: TEST
    members:
      - email: user@example.com
    permissions:
      databases:
        - name: MYDB
          grants: [USAGE]
      schemas:
        - name: MYDB.PUBLIC
          grants: [USAGE]
      tables:
        - name: MYDB.PUBLIC.MYTABLE
          grants: [SELECT]
`
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "roles.yaml")
	if err := os.WriteFile(tmpFile, []byte(validYAML), 0644); err != nil {
		t.Fatalf("Failed to write temp YAML: %v", err)
	}
	rc, err := LoadRolesConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadRolesConfig failed: %v", err)
	}
	if rc == nil || len(rc.Roles) != 1 {
		t.Fatalf("Expected 1 role, got %v", rc)
	}
	if err := ValidateRolesConfig(rc); err != nil {
		t.Errorf("ValidateRolesConfig failed: %v", err)
	}

	// Invalid YAML
	const invalidYAML = `
roles:
  - name: TEST
    members:
      - email: user@example.com
    permissions:
      databases:
        - name: MYDB
          grants: [USAGE
`
	tmpFile2 := filepath.Join(tmpDir, "invalid.yaml")
	if err := os.WriteFile(tmpFile2, []byte(invalidYAML), 0644); err != nil {
		t.Fatalf("Failed to write temp YAML: %v", err)
	}
	_, err = LoadRolesConfig(tmpFile2)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}
