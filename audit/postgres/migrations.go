package postgres

import (
	"embed"

	"github.com/mrheiz97/stumpfworks-framework/data/migrate"
)

//go:embed migrations/*.up.sql
var migrationFiles embed.FS

// Migrations returns the audit store's ordered schema migrations.
func Migrations() ([]migrate.Migration, error) { return migrate.Load(migrationFiles, "migrations") }
