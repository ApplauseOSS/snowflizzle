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

package config

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/applauseoss/snowflizzle/internal/logging"
	"github.com/joho/godotenv"
	sf "github.com/snowflakedb/gosnowflake"
)

func ConnectToSnowflake() (*sql.DB, error) {
	logger := logging.GetLogger()

	cwd, _ := os.Getwd()
	logger.Debug("Working dir:", "dir", cwd)
	// Load environment variables from .env file if it exists
	_ = godotenv.Load(".env")

	account := os.Getenv("SNOWFLAKE_ACCOUNT")
	user := os.Getenv("SNOWFLAKE_USER")
	pkPath := os.Getenv("SNOWFLAKE_PRIVATE_KEY_PATH")

	var err error
	if account == "" {
		err = errors.New("SNOWFLAKE_ACCOUNT environment variable not set")
		logger.Error(err.Error())
		return nil, err
	}
	if user == "" {
		err = errors.New("SNOWFLAKE_USER environment variable not set")
		logger.Error(err.Error())
		return nil, err
	}
	if pkPath == "" {
		err = errors.New("SNOWFLAKE_PRIVATE_KEY_PATH environment variable not set")
		logger.Error(err.Error())
		return nil, err
	}

	rsaPrivateKey, err := parsePrivateKeyFromFile(pkPath)
	if err != nil {
		logger.Error("Failed to parse private key:", "error", err)
		return nil, err
	}

	// Do NOT specify a Role, so the user's default role is used
	cfg := &sf.Config{
		Account:       account,
		User:          user,
		Authenticator: sf.AuthTypeJwt,
		PrivateKey:    rsaPrivateKey,
	}

	dsn, err := sf.DSN(cfg)
	if err != nil {
		logger.Error("Failed to build DSN:", "error", err)
		return nil, err
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		logger.Error("Failed to connect to Snowflake:", "error", err)
		return nil, err
	}

	if err := db.Ping(); err != nil {
		logger.Error("Ping to Snowflake failed:", "error", err)
		return nil, err
	}

	logger.Info("Connected to Snowflake!")

	row := db.QueryRow("SELECT CURRENT_ROLE()")
	var currentRole string
	if err := row.Scan(&currentRole); err != nil {
		logger.Error("Failed to get current role:", "error", err)
		return nil, err
	}

	// Warn if role is not SYSADMIN or ACCOUNTADMIN
	if currentRole != "SYSADMIN" && currentRole != "ACCOUNTADMIN" {
		logger.Warn("Role needs to have privileges to manage users, warehouses, databases. Current role: " + currentRole)
	}

	logger.Debug("Current role:", "role", currentRole)
	return db, nil
}

func parsePrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("interface conversion: expected *rsa.PrivateKey, got %T", privateKey)
	}
	return pk, nil
}
