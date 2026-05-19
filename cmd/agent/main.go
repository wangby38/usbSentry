package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/Hara602/usbSentry/internal/blackwhitelist"
	"github.com/Hara602/usbSentry/internal/monitor"
	"github.com/Hara602/usbSentry/internal/sysutil"
	"github.com/Hara602/usbSentry/internal/watcher"
	"go.uber.org/zap"
)

func main() {
	// CLI flags
	var (
		dbPath         = flag.String("db", "./internal/db/blacklist.db", "Path to SQLite blacklist/whitelist database")
		mountPollMs    = flag.Int("mount-poll-ms", 100, "Mount detection polling interval in milliseconds")
		mountRetries   = flag.Int("mount-retries", 30, "Number of mount detection retries")
		eventBufSize   = flag.Int("event-buf", 100, "File event channel buffer size")
		usbBufSize     = flag.Int("usb-buf", 10, "USB event channel buffer size")
	)
	flag.Parse()

	// Apply CLI flags to package-level config
	sysutil.MountPollIntervalMs = *mountPollMs
	sysutil.MountPollRetries = *mountRetries
	monitor.EventChannelSize = *eventBufSize
	watcher.EventChannelSize = *usbBufSize

	// 初始化日志
	sysutil.InitLogger()
	defer sysutil.Log.Sync()

	// 初始化黑白名单数据库
	if err := blackwhitelist.InitBlackWhiteDB(*dbPath); err != nil {
		sysutil.Log.Fatal("blackwhitelist database init failed!")
	}

	// Fanotify 需要 Root 权限
	if os.Geteuid() != 0 {
		sysutil.LogSugar.Fatal("Must run as root (required by Netlink/Fanotify).")
	}

	sysutil.Log.Info("🛡️ USB Sentry Agent Starting...")

	// 初始化核心模块 (依赖注入)
	devWatcher := watcher.New()
	fileMon, err := monitor.New()
	if err != nil {
		sysutil.Log.Fatal("Monitor init failed", zap.Error(err))
	}

	// 3. 启动
	fileMon.Start()
	fileMon.StartStatsReporter(60) // report every 60 seconds
	defer fileMon.Stop()

	usbEvents, err := devWatcher.Start()
	if err != nil {
		sysutil.Log.Fatal("Watcher init failed", zap.Error(err))
	}
	defer devWatcher.Stop()

	// 捕获操作系统信号，优雅关闭服务器或后台服务
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case dev := <-usbEvents:
			if dev.Action == "add" {
				sysutil.Log.Info("✅ USB Connected",
					zap.String("mount", dev.MountPoint),
					zap.String("vid", dev.IdVendor),
					zap.String("pid", dev.IdProduct),
					zap.String("product", dev.Product),
					zap.String("type", dev.DeviceType),
				)

				// BadUSB 告警
				if dev.DeviceType == "BADUSB_SUSPECT" {
					sysutil.Log.Error("🚨 BADUSB DETECTED", zap.String("serial", dev.Serial))
				}

				if err := fileMon.AddWatch(dev.MountPoint); err != nil {
					sysutil.Log.Error("Failed to watch mount", zap.Error(err))
				} else {
					sysutil.Log.Info("👀 Monitoring started", zap.String("path", dev.MountPoint))
				}
			} else if dev.Action == "remove" {
				sysutil.Log.Info("❌ USB Removed", zap.String("path", dev.DevicePath))
				if dev.MountPoint != "" {
					fileMon.RemoveWatch(dev.MountPoint)
				}
			}

		// --- 文件事件 ---
		case activity := <-fileMon.Events():
			sysutil.Log.Info("📂 File Activity",
				zap.String("op", activity.Operation),
				zap.String("file", activity.FilePath),
				zap.String("process", activity.ProcName), // 在操作的进程
				zap.Int32("pid", activity.PID),           // PID
			)

		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				sysutil.Log.Info("Received SIGHUP, config reload not yet implemented")
			default:
				sysutil.Log.Info("Shutting down...")
				return
			}
		}

	}

}
