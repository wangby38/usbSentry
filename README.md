# usbSentry — USB 存储设备文件操作监控 Agent

usbSentry 是一个基于 Go 语言开发的 Linux 系统守护进程，用于实时监控 USB 移动存储设备的插拔状态，以及 USB 设备上的文件操作活动。它能够精准识别触发文件操作的进程、检测 BadUSB 攻击、发现文件类型伪装，并对可疑文件执行隔离。

## 特性

- **USB 热插拔检测** — 基于 netlink udev，自动识别 USB 存储设备的插入和拔出
- **文件操作监控** — 基于 fanotify，实时捕获文件创建、删除、写入关闭、移动、打开等事件
- **进程关联** — 通过 `/proc/<pid>/comm` 精准识别触发每个文件操作的进程名和 PID
- **设备信息采集** — 采集 VID、PID、序列号、制造商、USB 速度、设备版本等信息
- **BadUSB 检测** — 若设备同时具备存储接口（class 08）和 HID 接口（class 03），判定为可疑 BadUSB
- **文件类型伪装检测** — 基于魔数（magic bytes）检测文件真实类型，识别 .exe 改名为 .pdf 等伪装攻击
- **文件隔离（Quarantine）** — 检测到伪装文件后自动将其移至隔离目录
- **设备黑/白名单** — SQLite 数据库存储黑白名单，白名单设备无条件放行，黑名单设备物理阻断
- **物理阻断** — 通过 sysfs `authorized=0` 在 USB 总线层面禁用黑名单设备
- **事件统计** — 每 60 秒输出文件事件汇总，包含按类型和按进程的计数排名
- **结构化日志** — JSON 兼容的结构化日志输出，便于集成 ELK 等日志平台

## 环境要求

| 项目 | 说明 |
|------|------|
| 操作系统 | Linux（fanotify/netlink/sysfs 均需要 Linux 内核） |
| Go 版本 | 1.20+ |
| 权限 | **必须 root** — fanotify、netlink udev、sysfs 操作均需特权 |
| 文件系统 | 目前支持 FAT32 和 exFAT 格式的 U 盘 |

## 快速开始

```bash
# 下载依赖
go mod tidy

# 编译
go build -o usbSentry ./cmd/agent/main.go

# 查看帮助
./usbSentry -h

# 运行（需要 root）
sudo ./usbSentry
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-db` | `./internal/db/blacklist.db` | SQLite 数据库路径（黑白名单） |
| `-mount-poll-ms` | `100` | 挂载检测轮询间隔（毫秒） |
| `-mount-retries` | `30` | 挂载检测最大重试次数 |
| `-event-buf` | `100` | 文件事件通道缓冲区大小 |
| `-usb-buf` | `10` | USB 事件通道缓冲区大小 |

示例：

```bash
sudo ./usbSentry -db /var/lib/usbsentry/blacklist.db -mount-retries 50
```

## 设备黑白名单

usbSentry 使用 SQLite 数据库管理设备黑白名单，表结构：

```sql
CREATE TABLE blackwhitelist (
    vid         TEXT,
    pid         TEXT,
    serial      TEXT,
    reason      TEXT,
    list_type   TEXT DEFAULT 'black',  -- 'black' 或 'white'
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vid, pid, serial)
);
```

### 判断逻辑

1. **白名单优先** — 若设备匹配白名单记录，无条件放行（即使序列号为空也会被放行）
2. **序列号检查** — 序列号为空或为 `000000000000` 的设备直接阻断（硬编码高危规则）
3. **黑名单匹配** — 若设备匹配黑名单记录，阻断并执行物理禁用
4. **默认放行** — 未命中任何规则的设备正常放行

### 管理规则

可以通过 SQLite 客户端直接操作数据库，或调用代码中的函数：

```go
// 添加黑名单
blackwhitelist.AddBlockRule("0781", "5591", "4C530001191212345", "已知恶意设备")

// 添加白名单
blackwhitelist.AddWhiteRule("0781", "5567", "4C530001191267890", "公司配发U盘")
```

## 检测机制详解

### BadUSB 检测

遍历 USB 设备 sysfs 树中所有接口目录，读取 `bInterfaceClass` 文件：

- 接口类 `08` = Mass Storage（大容量存储）
- 接口类 `03` = HID（人机接口设备，可模拟键盘/鼠标）

一个 USB 设备下**同时存在**这两类接口时，判定为 `BADUSB_SUSPECT`。典型的 BadUSB 攻击设备会伪装为普通 U 盘，同时模拟键盘发送恶意按键。

### 文件类型伪装检测

通过 `h2non/filetype` 库读取文件头部 262 字节的魔数，与文件扩展名进行比对：

- **完全匹配** → `SAFE`
- **别名匹配** → `SAFE`（如 `.docx` 本质是 zip 格式，`.dll` 本质是 PE 格式，这些是合法的）
- **未知类型** → `SAFE`（纯文本文件如 `.txt`、`.go` 无魔数，默认信任）
- **类型不匹配** → `MEDIUM` 或 `HIGH`
  - `HIGH`：真实类型为 `exe`/`elf`/`dll` 等可执行文件伪装成其他后缀
  - `MEDIUM`：其他类型不匹配

内置别名兼容表涵盖 ZIP 家族（docx/xlsx/pptx/jar/apk）、XML 家族（svg/html）、PE 家族（dll/sys/scr）、媒体容器等。

### 文件隔离

当检测到文件类型伪装时，文件会被自动移至隔离目录：

- 默认路径：`/var/lib/usbsentry/quarantine/`
- 文件命名：`<时间戳>_<原文件名>`（如 `20260519_142305_report.pdf`）
- 隔离后权限：`0400`（仅 root 可读）
- 移动策略：优先 `rename`（同文件系统原子操作），跨文件系统时 fallback 为 `copy + delete`

## 监控架构

usbSentry 使用**双 fanotify 文件描述符**设计：

| FD | 类别 | 作用 | 监听事件 |
|----|------|------|----------|
| Blocker | `FAN_CLASS_PRE_CONTENT` | 权限拦截 + 路径解析 | CLOSE_WRITE, OPEN_PERM, OPEN_EXEC_PERM |
| Recorder | `FAN_CLASS_NOTIF` + `FAN_REPORT_DFID_NAME` | 文件名捕获 | CREATE, DELETE, MOVED_TO, MOVED_FROM, ONDIR |

- **Blocker** 获得文件描述符，通过 `/proc/self/fd/<N>` 解析绝对路径（FAT32 上也能正常工作）
- **Recorder** 从 fanotify buffer 解析 DFID_NAME 记录获取文件名（无需 FD，能捕获已删除文件的名称）

两个 FD 各自独立的 goroutine 读取事件，统一发送到事件通道，由主循环消费并输出日志。

## 项目结构

```
usbSentry/
├── cmd/agent/main.go                  # 入口：日志、DB、信号处理、事件分发
├── internal/
│   ├── analysis/
│   │   ├── badusb.go                  # BadUSB 检测（接口类别判断）
│   │   ├── filetype.go                # 文件类型伪装检测
│   │   └── quarantine.go             # 伪装文件隔离
│   ├── blackwhitelist/
│   │   ├── blackwhitedb.go            # SQLite 黑白名单数据库
│   │   └── enforcer.go               # sysfs authorized 物理阻断
│   ├── monitor/
│   │   ├── monitor.go                 # FileMonitor 接口定义
│   │   ├── impl_linux.go             # fanotify 双 FD 实现
│   │   ├── impl_windows.go           # Windows 桩（空实现）
│   │   └── stats.go                  # 事件统计与定期报告
│   ├── watcher/
│   │   ├── watcher.go                 # DeviceWatcher 接口定义
│   │   ├── impl_linux.go             # udev 热插拔 + 已挂载设备扫描
│   │   ├── impl_windows.go           # Windows 桩（空实现）
│   │   └── devinfo.go                # 扩展设备信息采集
│   ├── model/
│   │   ├── events.go                  # USBEvent / FileEvent 数据结构
│   │   └── fanotify.go               # fanotify 底层结构体定义
│   ├── sysutil/
│   │   ├── logger.go                  # zap 日志初始化
│   │   └── mountLinux.go             # 挂载点轮询检测
│   └── db/
│       └── blacklist.db               # SQLite 数据库文件
├── .vscode/launch.json                # VS Code 远程调试配置
├── debug.sh                           # Delve headless 调试启动脚本
├── go.mod
└── go.sum
```

## 日志示例

```
2025-12-16T16:31:38.157+0800  INFO  agent/main.go:42  🛡️ USB Sentry Agent Starting...
2025-12-16T16:31:38.158+0800  INFO  watcher/impl_linux.go  device information:  {"vid": "0781", "pid": "5591", "serial": "4C530001191212345", "product": "SanDisk Ultra"}
2025-12-16T16:31:38.158+0800  INFO  watcher/impl_linux.go  Extended device info:  {"manufacturer": "SanDisk", "speed": "480", "bcdDevice": "0100"}
2025-12-16T16:31:38.158+0800  INFO  agent/main.go:57  ✅ USB Connected  {"mount": "/media/user/USB", "vid": "0781", "pid": "5591", "type": "udisk"}
2025-12-16T16:31:38.158+0800  INFO  agent/main.go:57  👀 Monitoring started  {"path": "/media/user/USB"}
2025-12-16T16:31:42.301+0800  INFO  agent/main.go:99  📂 File Activity  {"op": "CREATE", "file": "/media/user/USB/.../report.pdf", "process": "nautilus", "pid": 2841}
2025-12-16T16:31:43.512+0800  INFO  agent/main.go:99  📂 File Activity  {"op": "CLOSE_WRITE", "file": "/media/user/USB/report.pdf", "process": "cp", "pid": 3120}
2025-12-16T16:31:43.513+0800  WARN  monitor/impl_linux.go  🚨 Masquerade detected! [HIGH] /media/user/USB/report.pdf
2025-12-16T16:31:43.514+0800  WARN  analysis/quarantine.go  File quarantined  {"original": "/media/user/USB/report.pdf", "quarantine_path": "/var/lib/usbsentry/quarantine/20260519_163143_report.pdf"}
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go  === File Event Statistics ===  {"total_events": 7, "elapsed": "1m0s"}
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    CLOSE_WRITE         : 2
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    CREATE              : 3
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    DELETE              : 1
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    OPEN_PERM           : 1
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go  Top processes by event count:
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    nautilus            : 4
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    cp                  : 2
2025-12-16T16:32:38.158+0800  INFO  monitor/stats.go    bash                : 1
```

## 远程调试

```bash
# 启动 Delve headless 服务（监听 :2345）
./debug.sh

# 在 VS Code 中使用 "USB Sentry Debug" 配置连接
```
