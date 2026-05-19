//go:build linux

package watcher

import (
	"os"
	"path/filepath"
	"strings"
)

// USBDeviceInfo holds extended sysfs information about a USB device.
type USBDeviceInfo struct {
	Manufacturer    string
	Speed           string
	BcdDevice       string
	BDeviceClass    string
	BDeviceSubClass string
}

// CollectDeviceInfo reads extended USB device attributes from the sysfs tree.
func CollectDeviceInfo(usbRoot string) USBDeviceInfo {
	return USBDeviceInfo{
		Manufacturer:    readAttr(usbRoot, "manufacturer"),
		Speed:           readAttr(usbRoot, "speed"),
		BcdDevice:       readAttr(usbRoot, "bcdDevice"),
		BDeviceClass:    readAttr(usbRoot, "bDeviceClass"),
		BDeviceSubClass: readAttr(usbRoot, "bDeviceSubClass"),
	}
}

// readAttr reads a sysfs attribute file, trims whitespace, returns "unknown" on error.
func readAttr(sysPath, attr string) string {
	b, err := os.ReadFile(filepath.Join(sysPath, attr))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
