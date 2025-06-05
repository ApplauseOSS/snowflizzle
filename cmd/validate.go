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
	"os"

	"github.com/applauseoss/snowflizzle/internal/logging"
	"github.com/applauseoss/snowflizzle/internal/role"
	"github.com/spf13/cobra"
)

// validateCmd represents the validate command
var validateCmd = &cobra.Command{
	Use:   "validate [roles.yaml]",
	Short: "Validate roles.yaml file",
	Args:  cobra.ExactArgs(1),
	Long: `Validate the roles.yaml file to ensure it conforms to the expected format
and contains valid data for mapping roles from AD to Snowflake.`,
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		logger := logging.GetLogger()
		logger.Info("Validating", "filePath", filePath)

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
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// validateCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// validateCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
