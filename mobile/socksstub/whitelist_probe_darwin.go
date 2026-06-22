//go:build darwin

package socksstub

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func applyWhitelistProbeInterface(d *net.Dialer, ifaceIndex int) {
	if d == nil || ifaceIndex <= 0 {
		return
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			level := unix.IPPROTO_IP
			opt := 25 // IP_BOUND_IF; unix may not expose it on all darwin SDK snapshots.
			if network == "tcp6" || network == "udp6" {
				level = unix.IPPROTO_IPV6
				opt = unix.IPV6_BOUND_IF
			}
			controlErr = unix.SetsockoptInt(int(fd), level, opt, ifaceIndex)
		}); err != nil {
			return err
		}
		return controlErr
	}
}
