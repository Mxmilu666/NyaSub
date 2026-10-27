package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabaseWALForeignKeysAndMigrations(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	require.NoError(t, err)
	require.NoError(t, Migrate(db))

	var journal string
	require.NoError(t, db.Raw("PRAGMA journal_mode").Scan(&journal).Error)
	require.Equal(t, "wal", journal)

	var foreignKeys int
	require.NoError(t, db.Raw("PRAGMA foreign_keys").Scan(&foreignKeys).Error)
	require.Equal(t, 1, foreignKeys)

	var migrations int64
	require.NoError(t, db.Model(&SchemaMigration{}).Count(&migrations).Error)
	require.Equal(t, int64(4), migrations)

	for _, table := range []string{"users", "sessions", "nodes", "node_tags", "chains", "profiles", "profile_nodes", "profile_chains", "subscription_tokens"} {
		require.True(t, db.Migrator().HasTable(table), "missing table %s", table)
	}

	info, err := os.Stat(filepath.Join(dir, "nyasub.db"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}
