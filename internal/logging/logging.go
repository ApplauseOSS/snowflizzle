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

package logging

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

var globalLogger *slog.Logger

func Configure() {
	logLevelEnv := strings.ToLower(os.Getenv("LOG_LEVEL"))
	var level slog.Level
	switch logLevelEnv {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Use text handler instead of JSON handler
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				// Format the time attribute to use RFC3339 or your custom format
				return slog.String(
					"timestamp",
					a.Value.Time().Format(time.RFC3339),
				)
			}
			return a
		},
		Level: level,
	})
	globalLogger = slog.New(handler)
}

func GetLogger() *slog.Logger {
	if globalLogger == nil {
		Configure()
	}
	return globalLogger
}
