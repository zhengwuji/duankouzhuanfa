//go:build !linux

package hostmon

import (
	"context"
	"errors"
	"time"
)

// icmpProbe is unavailable off Linux, so the caller falls back to a TCP
// handshake and reports that as the method.
func icmpProbe(ctx context.Context, host string, count int, timeout time.Duration) ([]float64, error) {
	return nil, errors.New("此平台不支持 ICMP 探测")
}
