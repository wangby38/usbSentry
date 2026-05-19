//go:build windows

package watcher

import "github.com/Hara602/usbSentry/internal/model"

type winWatcher struct{}

func newWatcher() DeviceWatcher                             { return &winWatcher{} }
func (w *winWatcher) Start() (<-chan model.USBEvent, error) { return nil, nil }
func (w *winWatcher) Stop()                                 {}
