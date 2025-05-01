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
  ANALYST:
    - user1@example.com
    - user2@example.com
  DEVELOPER:
    - user3@example.com`,
			expectedError: false,
		},
		{
			name:          "empty_file",
			content:       `roles: {}`,
			expectedError: true,
			errorContains: "roles must contain at least one role",
		},
		{
			name: "empty_role_name",
			content: `roles:
  "":
    - user1@example.com`,
			expectedError: true,
			errorContains: "role name cannot be empty",
		},
		{
			name: "role_with_no_users",
			content: `roles:
  ANALYST: []`,
			expectedError: true,
			errorContains: "must have at least one user",
		},
		{
			name: "role_with_empty_user",
			content: `roles:
  ANALYST:
    - ""`,
			expectedError: true,
			errorContains: "user in role 'ANALYST' cannot be empty",
		},
		{
			name: "invalid_yaml",
			content: `roles:
  ANALYST:
  - user1@example.com
  DEVELOPER: invalid`,
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

			roleMap, err := ValidateRolesFile(tmpFile)

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
				if roleMap == nil {
					t.Errorf("Expected non-nil roleMap but got nil")
				}
			}
		})
	}

	// Test with non-existent file
	t.Run("non_existent_file", func(t *testing.T) {
		_, err := ValidateRolesFile("/path/to/nonexistent/file.yaml")
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
		"john@example.com":   "john",
		"sandra@example.com": "sandra",
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
		roleMap  *RoleMap
		expected []string
	}{
		{
			name: "all roles exist",
			roleMap: &RoleMap{
				Roles: map[string][]string{
					"ADMIN": {"user1"},
				},
			},
			expected: []string{},
		},
		{
			name: "some roles missing",
			roleMap: &RoleMap{
				Roles: map[string][]string{
					"ADMIN":    {"user1"},
					"ANALYST":  {"user2"},
					"REPORTER": {"user3"},
				},
			},
			expected: []string{"ANALYST", "REPORTER"},
		},
		{
			name:     "nil rolemap",
			roleMap:  nil,
			expected: []string{},
		},
		{
			name: "empty roles",
			roleMap: &RoleMap{
				Roles: map[string][]string{},
			},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := FindNonExistentRoles(tc.roleMap, existing)

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
