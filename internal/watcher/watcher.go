package watcher

import "github.com/Hara602/usbSentry/internal/model"

// EventChannelSize controls the buffer size of the USB event channel.
var EventChannelSize = 10

// DeviceWatcher 定义接口
type DeviceWatcher interface {
	Start() (<-chan model.USBEvent, error)
	Stop()
}

func New() DeviceWatcher {
	return newWatcher()
}
