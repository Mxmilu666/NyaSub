package store

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open opens (or creates) the SQLite database in dataDir and configures WAL,
// foreign keys and a busy timeout. The GORM logger is silenced so that SQL
// containing credential material can never reach application logs.
func Open(dataDir string) (*gorm.DB, error) {
	path := filepath.Join(dataDir, "nyasub.db")
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:                                   logger.Discard,
		DisableForeignKeyConstraintWhenMigrating: false,
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("obtain sql database: %w", err)
	}
	_ = os.Chmod(path, 0o600)
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(0)
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return db, nil
}

type migration struct {
	ID string
	Up func(*gorm.DB) error
}

var migrations = []migration{
	{
		ID: "0001_initial",
		Up: func(tx *gorm.DB) error {
			models := []any{
				&User{},
				&Node{},
				&NodeTag{},
				&Chain{},
				&Profile{},
				&ProfileNode{},
				&ProfileChain{},
				&SubscriptionToken{},
				&Session{},
				&AppSetting{},
			}
			for _, model := range models {
				if err := tx.AutoMigrate(model); err != nil {
					return fmt.Errorf("automigrate %T: %w", model, err)
				}
			}
			return nil
		},
	},
	{
		ID: "0002_node_country",
		Up: func(tx *gorm.DB) error {
			return tx.AutoMigrate(&Node{})
		},
	},
	{
		ID: "0003_subscription_token_plaintext",
		Up: func(tx *gorm.DB) error {
			return tx.AutoMigrate(&SubscriptionToken{})
		},
	},
	{
		ID: "0004_profile_template",
		Up: func(tx *gorm.DB) error {
			return tx.AutoMigrate(&Profile{})
		},
	},
}

// Migrate applies versioned migrations in order and records them in
// schema_migrations. Each migration runs in its own transaction.
func Migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&SchemaMigration{}); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	for _, m := range migrations {
		var count int64
		if err := db.Model(&SchemaMigration{}).Where("version = ?", m.ID).Count(&count).Error; err != nil {
			return fmt.Errorf("check migration %s: %w", m.ID, err)
		}
		if count > 0 {
			continue
		}
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := m.Up(tx); err != nil {
				return err
			}
			return tx.Create(&SchemaMigration{Version: m.ID, AppliedAt: time.Now().UTC()}).Error
		})
		if err != nil {
			return fmt.Errorf("apply migration %s: %w", m.ID, err)
		}
	}
	return nil
}
