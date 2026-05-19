//go:build windows

package monitor

import "github.com/Hara602/usbSentry/internal/model"

type winMonitor struct{}

func newMonitor() (FileMonitor, error)               { return &winMonitor{}, nil }
func (m *winMonitor) Start()                         {}
func (m *winMonitor) Stop()                          {}
func (m *winMonitor) AddWatch(p string) error        { return nil }
func (m *winMonitor) RemoveWatch(p string)           {}
func (m *winMonitor) Events() <-chan model.FileEvent { return nil }
func (m *winMonitor) StartStatsReporter(i int)       {}
