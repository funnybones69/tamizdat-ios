//go:build !darwin

package socksstub

import "net"

func applyWhitelistProbeInterface(_ *net.Dialer, _ int) {}
