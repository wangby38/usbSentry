//go:build linux

package analysis

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Hara602/usbSentry/internal/sysutil"
	"go.uber.org/zap"
)

const DefaultQuarantineDir = "/var/lib/usbsentry/quarantine"

// QuarantineManager handles isolating detected masquerade files.
type QuarantineManager struct {
	QuarantineDir string
}

// NewQuarantineManager creates a quarantine manager, creating the directory if needed.
func NewQuarantineManager(dir string) (*QuarantineManager, error) {
	if dir == "" {
		dir = DefaultQuarantineDir
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create quarantine directory %s: %w", dir, err)
	}
	return &QuarantineManager{QuarantineDir: dir}, nil
}

// Quarantine moves a file into the quarantine directory with a timestamp prefix
// to avoid name collisions. Returns the new path or an error.
func (qm *QuarantineManager) Quarantine(srcPath string) (string, error) {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return "", fmt.Errorf("quarantine: cannot stat source %s: %w", srcPath, err)
	}
	if srcInfo.IsDir() {
		return "", fmt.Errorf("quarantine: refusing to quarantine directory %s", srcPath)
	}

	baseName := filepath.Base(srcPath)
	timestamp := time.Now().Format("20060102_150405")
	destName := fmt.Sprintf("%s_%s", timestamp, baseName)
	destPath := filepath.Join(qm.QuarantineDir, destName)

	if err := os.Rename(srcPath, destPath); err != nil {
		if err := copyFile(srcPath, destPath); err != nil {
			return "", fmt.Errorf("quarantine: failed to move %s: %w", srcPath, err)
		}
		os.Remove(srcPath)
	}

	os.Chmod(destPath, 0400)

	sysutil.Log.Warn("File quarantined",
		zap.String("original", srcPath),
		zap.String("quarantine_path", destPath),
		zap.Int64("size_bytes", srcInfo.Size()),
	)

	return destPath, nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("quarantine copy: open src: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("quarantine copy: create dst: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("quarantine copy: io error: %w", err)
	}

	return dstFile.Sync()
}
