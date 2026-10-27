package store

import (
	"time"
)

// User is the single administrator account (the schema allows more, the setup
// flow only creates one and the API treats the first user as the owner).
type User struct {
	ID           string    `gorm:"primaryKey;type:text"`
	Username     string    `gorm:"uniqueIndex;not null;type:text"`
	PasswordHash string    `gorm:"not null;type:text"`
	CreatedAt    time.Time `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

type Session struct {
	ID         string    `gorm:"primaryKey;type:text"`
	TokenHash  string    `gorm:"uniqueIndex;not null;type:text"`
	UserID     string    `gorm:"index;not null;type:text"`
	User       User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE"`
	ExpiresAt  time.Time `gorm:"index;not null"`
	LastSeenAt time.Time `gorm:"not null"`
	CreatedAt  time.Time `gorm:"not null"`
	IP         string    `gorm:"type:text"`
	UserAgent  string    `gorm:"type:text"`
}

type Node struct {
	ID        string    `gorm:"primaryKey;type:text"`
	Name      string    `gorm:"not null;type:text"`
	Country   string    `gorm:"type:text"`
	Protocol  string    `gorm:"not null;index;type:text"`
	Config    string    `gorm:"not null;type:text"` // JSON, validated by internal/mihomo
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null;index"`
	Tags      []NodeTag `gorm:"foreignKey:NodeID;constraint:OnDelete:CASCADE"`
}

type NodeTag struct {
	NodeID string `gorm:"primaryKey;type:text"`
	Tag    string `gorm:"primaryKey;type:text;index"`
	Node   Node   `gorm:"foreignKey:NodeID;constraint:OnDelete:CASCADE"`
}

type Chain struct {
	ID          string    `gorm:"primaryKey;type:text"`
	Name        string    `gorm:"not null;type:text"`
	EntryNodeID string    `gorm:"not null;index;type:text"`
	ExitNodeID  string    `gorm:"not null;index;type:text"`
	EntryNode   Node      `gorm:"foreignKey:EntryNodeID;constraint:OnDelete:RESTRICT"`
	ExitNode    Node      `gorm:"foreignKey:ExitNodeID;constraint:OnDelete:RESTRICT"`
	Enabled     bool      `gorm:"not null;default:true"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

type Profile struct {
	ID               string    `gorm:"primaryKey;type:text"`
	Name             string    `gorm:"not null;type:text"`
	Description      string    `gorm:"type:text"`
	Template         string    `gorm:"type:text"`
	DefaultExitType  string    `gorm:"type:text"` // "", "node" or "chain"
	DefaultExitID    string    `gorm:"type:text"`
	ForceDefaultExit bool      `gorm:"not null;default:false"`
	GroupsJSON       string    `gorm:"not null;type:text"`
	RulesJSON        string    `gorm:"not null;type:text"`
	DNSJSON          string    `gorm:"not null;type:text"`
	GeneralJSON      string    `gorm:"not null;type:text"`
	CreatedAt        time.Time `gorm:"not null"`
	UpdatedAt        time.Time `gorm:"not null;index"`
}

type ProfileNode struct {
	ProfileID string  `gorm:"primaryKey;type:text"`
	NodeID    string  `gorm:"primaryKey;type:text"`
	Profile   Profile `gorm:"foreignKey:ProfileID;constraint:OnDelete:CASCADE"`
	Node      Node    `gorm:"foreignKey:NodeID;constraint:OnDelete:CASCADE"`
}

type ProfileChain struct {
	ProfileID string  `gorm:"primaryKey;type:text"`
	ChainID   string  `gorm:"primaryKey;type:text"`
	Profile   Profile `gorm:"foreignKey:ProfileID;constraint:OnDelete:CASCADE"`
	Chain     Chain   `gorm:"foreignKey:ChainID;constraint:OnDelete:CASCADE"`
}

type SubscriptionToken struct {
	ID         string    `gorm:"primaryKey;type:text"`
	ProfileID  string    `gorm:"index;not null;type:text"`
	Profile    Profile   `gorm:"foreignKey:ProfileID;constraint:OnDelete:CASCADE"`
	TokenHash  string    `gorm:"uniqueIndex;not null;type:text"`
	Token      string    `gorm:"type:text"` // plaintext for viewing; lookup still uses TokenHash
	CreatedAt  time.Time `gorm:"not null"`
	LastUsedAt *time.Time
	RevokedAt  *time.Time `gorm:"index"`
}

type AppSetting struct {
	Key   string `gorm:"primaryKey;type:text"`
	Value string `gorm:"not null;type:text"`
}

type SchemaMigration struct {
	Version   string    `gorm:"primaryKey;type:text"`
	AppliedAt time.Time `gorm:"not null"`
}
