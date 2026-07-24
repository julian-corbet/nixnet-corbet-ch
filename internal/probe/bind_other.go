//go:build !linux

package probe

import (
	"fmt"
	"net"
	"syscall"
)

// SO_BINDTODEVICE is Linux-only. nixnet's only shipped target is Linux
// (NixOS + system-manager hosts), but these stubs keep `go build`/`go vet`
// green on a contributor's non-Linux laptop instead of failing the whole
// module.
func bindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return fmt.Errorf("probe.bindToInterface (%s): SO_BINDTODEVICE is only implemented on Linux", iface)
	}
}

func bindIPConnToDevice(_ *net.IPConn, iface string) error {
	return fmt.Errorf("probe.bindToInterface (%s): SO_BINDTODEVICE is only implemented on Linux", iface)
}
