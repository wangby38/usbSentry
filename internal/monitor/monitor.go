package monitor

import "github.com/Hara602/usbSentry/internal/model"

// EventChannelSize controls the buffer size of the file event channel.
var EventChannelSize = 100

type FileMonitor interface {
	Start()
	Stop()
	AddWatch(mountPath string) error
	RemoveWatch(mountPath string)
	Events() <-chan model.FileEvent
	StartStatsReporter(intervalSec int)
}

func New() (FileMonitor, error) {
	return newMonitor()
}
