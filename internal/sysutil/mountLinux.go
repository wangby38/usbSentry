//go:build linux

package sysutil

import (
	"bufio"
	"os"
	"strings"
	"time"
)

// MountPollRetries and MountPollIntervalMs control the mount detection polling.
var MountPollRetries = 30
var MountPollIntervalMs = 100

// WaitForMount 轮询 /proc/mounts 等待设备挂载
func WaitForMount(devPath string) string {
	for i := 0; i < MountPollRetries; i++ {
		f, err := os.Open("/proc/mounts")
		if err != nil {
			LogSugar.Errorf("WaitForMount: cannot open /proc/mounts: %v", err)
			return ""
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == devPath {
				f.Close()
				return fields[1]
			}
		}
		f.Close()
		time.Sleep(time.Duration(MountPollIntervalMs) * time.Millisecond)
	}
	return ""
}
