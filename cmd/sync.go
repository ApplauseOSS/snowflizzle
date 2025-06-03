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

package cmd

import (
	"fmt"
	"os"

	"github.com/applauseoss/snowflizzle/config"
	"github.com/applauseoss/snowflizzle/internal/logging"
	"github.com/applauseoss/snowflizzle/internal/role"
	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync [roles.yaml]",
	Short: "Sync roles.yaml file",
	Args:  cobra.ExactArgs(1),
	Long: `Sync the roles.yaml file to execute the actual mapping of roles from AD to Snowflake.
Use the --dry-run option to simulate the sync process without making any changes.`,
	Run: func(cmd *cobra.Command, args []string) {
		logger := logging.GetLogger()
		filePath := args[0]
		dryRun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			logger.Error("Error reading dry-run flag:", "error", err)
			return
		}
		SyncFile(filePath, dryRun)
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// syncCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	syncCmd.Flags().Bool("dry-run", false, "Simulate the sync process without making any changes")
}

func SyncFile(filePath string, dryRun bool) {
	logger := logging.GetLogger()
	logger.Info(fmt.Sprintf("Starting sync process with dryRun:%t", dryRun))
	logger.Info("Mapping file", "file", filePath)
	if filePath == "" {
		logger.Error("No file provided")
		logger.Error("Sync failed: no file provided")
		os.Exit(1)
	}

	rc, err := role.LoadRolesConfig(filePath)
	if err != nil {
		logger.Error("Failed to load roles config", "error", err)
		os.Exit(1)
	}

	err = role.ValidateRolesConfig(rc)
	if err != nil {
		logger.Error("Validation failed", "error", err)
		os.Exit(1)
	}
	logger.Info("Validation successful!")

	db, err := config.ConnectToSnowflake()
	if err != nil {
		logger.Error("Failed to connect to Snowflake", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close Snowflake connection", "error", err)
		}
	}()

	rp, err := role.NewRoleProcessor(db, rc, dryRun)
	if err != nil {
		logger.Error("Failed to initialize role processor", "error", err)
		os.Exit(1)
	}
	if err := rp.Process(); err != nil {
		logger.Error("Failed to grant roles to users", "error", err)
		os.Exit(1)
	}

	if dryRun {
		logger.Info("Dry run completed successfully!")
	} else {
		logger.Info("Sync process completed successfully!")
	}
}
