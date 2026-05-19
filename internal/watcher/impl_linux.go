package watcher

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Hara602/usbSentry/internal/analysis"
	"github.com/Hara602/usbSentry/internal/blackwhitelist"
	"github.com/Hara602/usbSentry/internal/model"
	"github.com/Hara602/usbSentry/internal/sysutil"
	"github.com/pilebones/go-udev/netlink"
	"go.uber.org/zap"
)

type linuxWatcher struct {
	events chan model.USBEvent
	stop   chan struct{}
	wg     sync.WaitGroup
}

func newWatcher() DeviceWatcher {
	return &linuxWatcher{
		events: make(chan model.USBEvent, EventChannelSize),
		stop:   make(chan struct{}),
	}
}
func (w *linuxWatcher) Start() (<-chan model.USBEvent, error) {
	// 监听 UDEV 事件,连接 NETLINK_KOBJECT_UEVENT
	conn := new(netlink.UEventConn)
	if err := conn.Connect(netlink.UdevEvent); err != nil {
		return nil, err
	}
	// 创建一个队列用于接收事件
	queue := make(chan netlink.UEvent)
	errChan := make(chan error)

	quit := conn.Monitor(queue, errChan, nil)

	// 启动监听 goroutine
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		// 确保退出时关闭连接
		defer conn.Close()

		// 在处理新事件前，先扫描已存在的设备
		go w.scanExistingUSB()

		for {
			select {
			case <-w.stop:
				// 发送退出信号给 Monitor
				close(quit)
				return

			case <-errChan:
				// 忽略底层网络错误，继续尝试
				continue

			case uevent := <-queue:
				w.handleUdevEvent(uevent)
			}

		}

	}()
	return w.events, nil

}
func (w *linuxWatcher) Stop() {
	close(w.stop)
	w.wg.Wait()
}
func (w *linuxWatcher) handleAdd(uevent netlink.UEvent) {
	// 获取基础信息
	// UEvent Env 示例: DEVNAME=/dev/sdb1, DEVPATH=/devices/...
	// fmt.Println("uevent.Env", uevent.Env)

	devName := uevent.Env["DEVNAME"]
	if !strings.HasPrefix(devName, "/dev") {
		devName = "/dev/" + devName
	}

	sysPath := "/sys" + uevent.Env["DEVPATH"]

	// 信息采集：向上回溯找到 USB 物理设备根目录
	usbRoot := findUSBRoot(sysPath)
	vid := readFile(filepath.Join(usbRoot, "idVendor"))
	pid := readFile(filepath.Join(usbRoot, "idProduct"))
	serial := readFile(filepath.Join(usbRoot, "serial"))
	product := readFile(filepath.Join(usbRoot, "product"))
	sysutil.Log.Info("device information:",
		zap.String("vid", vid),
		zap.String("pid", pid),
		zap.String("serial", serial),
		zap.String("product", product))

	// BadUSB 分析
	isBad, devType := analysis.CheckBadUSB(usbRoot)

	// Extended device info from sysfs
	info := CollectDeviceInfo(usbRoot)
	sysutil.Log.Info("Extended device info:",
		zap.String("manufacturer", info.Manufacturer),
		zap.String("speed", info.Speed),
		zap.String("bcdDevice", info.BcdDevice),
		zap.String("bDeviceClass", info.BDeviceClass),
	)

	mountPoint := sysutil.WaitForMount(devName)
	if mountPoint == "" {
		sysutil.LogSugar.Warn("Device detected but mount point not found (timeout)", zap.String("dev", devName))
		return
	}

	w.events <- model.USBEvent{
		Action:          "add",
		DevicePath:      devName,
		MountPoint:      mountPoint,
		IdVendor:        vid,
		IdProduct:       pid,
		Serial:          serial,
		DeviceType:      devType,
		Manufacturer:    info.Manufacturer,
		Speed:           info.Speed,
		BcdDevice:       info.BcdDevice,
		BDeviceClass:    info.BDeviceClass,
		BDeviceSubClass: info.BDeviceSubClass,
		TimeStamp:       time.Now(),
	}

	if isBad {
		sysutil.LogSugar.Warn("🚨 POTENTIAL BADUSB DETECTED", zap.String("serial", serial))
	}
}

// findUSBRoot 递归向上查找包含 idVendor 的目录（即 USB Device 根目录）
func findUSBRoot(path string) string {
	dir := path

	// 向上回溯最多 10 层，通常 USB 设备在 sysfs 树的上层
	for i := 0; i < 10; i++ {
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}
		if _, err := os.Stat(filepath.Join(dir, "idVendor")); err == nil {
			return dir
		}
	}
	// 如果找不到，返回原始路径避免崩溃，后续读取会得到 "unknown"
	return path
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

// scanExisting 扫描当前已挂载的文件系统，寻找遗漏的 USB 设备
func (w *linuxWatcher) scanExistingUSB() {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		sysutil.LogSugar.Error("Failed to scan existing mounts", zap.Error(err))
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	foundCount := 0
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// e.g. /dev/sdb1
		devPath := fields[0]
		// e.g. /media/usb
		mountPoint := fields[1]

		// 只关心 /dev/ 开头的设备，且不是 loop 设备
		if !strings.HasPrefix(devPath, "/dev/") || strings.HasPrefix(devPath, "/dev/loop") {
			continue
		}

		// 判断/dev/sdb1是否为USB，通过 /sys/class/block/{name} 去回溯
		devName := filepath.Base(devPath)
		sysPath := "/sys/class/block/" + devName

		// 检查是否指向真实的 sysfs 路径
		realSysPath, err := filepath.EvalSymlinks(sysPath)
		if err != nil {
			continue
		}

		usbRoot := findUSBRoot(realSysPath)

		// 如果能找到 idVendor，说明它在 USB 总线上
		if _, err := os.Stat(filepath.Join(usbRoot, "idVendor")); err == nil {
			// 是 USB 设备,采集信息
			vid := readFile(filepath.Join(usbRoot, "idVendor"))
			pid := readFile(filepath.Join(usbRoot, "idProduct"))
			serial := readFile(filepath.Join(usbRoot, "serial"))
			product := readFile(filepath.Join(usbRoot, "product"))
			isBad, devType := analysis.CheckBadUSB(usbRoot)
			info := CollectDeviceInfo(usbRoot)
			foundCount++
			sysutil.Log.Info("🔍 Found existing USB device during scan",
				zap.String("mount", mountPoint),
				zap.String("dev", devPath))
			// 发送事件
			w.events <- model.USBEvent{
				Action:          "add",
				DevicePath:      devPath,
				MountPoint:      mountPoint,
				IdVendor:        vid,
				IdProduct:       pid,
				Product:         product,
				Serial:          serial,
				DeviceType:      devType,
				Manufacturer:    info.Manufacturer,
				Speed:           info.Speed,
				BcdDevice:       info.BcdDevice,
				BDeviceClass:    info.BDeviceClass,
				BDeviceSubClass: info.BDeviceSubClass,
				TimeStamp:       time.Now(),
			}
			if isBad {
				sysutil.Log.Warn("🚨 POTENTIAL BADUSB DETECTED (Existing)", zap.String("serial", serial))
			}
		}
	}
	if foundCount > 0 {
		sysutil.LogSugar.Infof("scanExistingUSB: found %d USB device(s)", foundCount)
	} else {
		sysutil.LogSugar.Info("no existed USB found during initial scan")
	}
}

func (w *linuxWatcher) handleUdevEvent(uevent netlink.UEvent) {
	// 获取设备的信息，裁定是否阻断设备的连接
	if uevent.Env["SUBSYSTEM"] == "usb" && uevent.Env["DEVTYPE"] == "usb_device" {
		if uevent.Action == "add" {
			// fmt.Println("usb_device uevent.Env:", uevent.Env)

			devPath := uevent.Env["DEVPATH"]
			usbRoot := filepath.Join("/sys", devPath)
			busID := filepath.Base(devPath)
			vid := readFile(filepath.Join(usbRoot, "idVendor"))
			pid := readFile(filepath.Join(usbRoot, "idProduct"))
			serial := readFile(filepath.Join(usbRoot, "serial"))
			sysutil.Log.Info("checking device information:",
				zap.String("vid", vid),
				zap.String("pid", pid),
				zap.String("serial", serial),
				zap.String("busID", busID))
			shouldBlock, reason := blackwhitelist.IsBlocked(vid, pid, serial)
			if shouldBlock {
				sysutil.Log.Warn("🚫 [拦截] 发现黑名单/高危设备! 原因:", zap.String("reason", reason))

				// 执行物理阻断
				if err := blackwhitelist.BlockDevice(busID); err != nil {
					sysutil.Log.Error("阻断失败", zap.Error(err))
				} else {
					sysutil.Log.Info("设备已成功阻断 (Authorized=0)")
				}

				// 阻断后直接 return，不要启动后面的文件监控了
				return
			}

		}
	}

	// 放行的usb设备
	if uevent.Env["SUBSYSTEM"] == "block" && uevent.Env["DEVTYPE"] == "partition" {
		if uevent.Action == "add" {
			go w.handleAdd(uevent)
		} else if uevent.Action == "remove" {
			mountPoint := sysutil.WaitForMount("/dev/" + uevent.Env["DEVNAME"])
				w.events <- model.USBEvent{Action: "remove", DevicePath: uevent.Env["DEVNAME"], MountPoint: mountPoint, TimeStamp: time.Now()}
		}
	}
}
