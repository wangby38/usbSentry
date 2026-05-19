package blackwhitelist

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

var BWdb *sql.DB

// InitBlackWhiteDB 初始化数据库表结构
func InitBlackWhiteDB(dbPath string) error {
	var err error
	BWdb, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// 联合主键 (vid, pid, serial) 防止重复
	schema := `
	CREATE TABLE IF NOT EXISTS blackwhitelist (
		vid TEXT,
		pid TEXT,
		serial TEXT,
		reason TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (vid, pid, serial)
	);
	`
	_, err = BWdb.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Migration: add list_type column for existing databases
	migrateSchema(BWdb)

	return nil
}

func migrateSchema(db *sql.DB) {
	var colExists int
	row := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('blackwhitelist') WHERE name='list_type'")
	if err := row.Scan(&colExists); err != nil || colExists == 0 {
		db.Exec("ALTER TABLE blackwhitelist ADD COLUMN list_type TEXT NOT NULL DEFAULT 'black'")
	}
}

func IsBlocked(vid, pid, serial string) (bool, string) {
	// Whitelist override: whitelisted devices are always allowed
	var whitelistExists int
	err := BWdb.QueryRow(
		"SELECT 1 FROM blackwhitelist WHERE vid=? AND pid=? AND serial=? AND list_type='white'",
		vid, pid, serial,
	).Scan(&whitelistExists)
	if err == nil && whitelistExists == 1 {
		return false, ""
	}

	// 无序列号直接阻断 (硬编码的高危规则)
	if serial == "" || serial == "000000000000" {
		return true, "Unknown or empty serial number"
	}

	// 查数据库黑名单
	var blacklistExists int
	err = BWdb.QueryRow(
		"SELECT 1 FROM blackwhitelist WHERE vid=? AND pid=? AND serial=? AND list_type='black'",
		vid, pid, serial,
	).Scan(&blacklistExists)

	if err == nil && blacklistExists == 1 {
		return true, "Device is in blacklist"
	}

	// 默认放行
	return false, ""

}

// AddBlockRule 添加黑名单工具函数
func AddBlockRule(vid, pid, serial, reason string) {
	if BWdb != nil {
		BWdb.Exec(
			"INSERT OR IGNORE INTO blackwhitelist(vid,pid,serial,reason,list_type) VALUES (?,?,?,?,'black')",
			vid, pid, serial, reason,
		)
	}
}

// AddWhiteRule 添加白名单工具函数
func AddWhiteRule(vid, pid, serial, reason string) {
	if BWdb != nil {
		BWdb.Exec(
			"INSERT OR IGNORE INTO blackwhitelist(vid,pid,serial,reason,list_type) VALUES (?,?,?,?,'white')",
			vid, pid, serial, reason,
		)
	}
}
