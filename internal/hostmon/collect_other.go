//go:build !linux

package hostmon

import "errors"

// readRaw reports that this platform has no host collector.
//
// Every deployment the installer creates is Linux, and this package reads /proc
// and /sys directly rather than through a portable abstraction. Other platforms
// still build and still run a relay; they report the panel as unavailable
// instead of inventing numbers, which is the same rule the rest of the console
// follows for a value it cannot obtain.
func readRaw() (*rawSample, error) {
	return nil, errors.New("此平台不支持主机资源采集（仅 Linux 提供 /proc 与 /sys）")
}
