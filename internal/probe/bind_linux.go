//go:build linux

package probe

import (
	"net"
	"syscall"
)

// bindToDeviceControl returns a net.Dialer.Control func that applies
// SO_BINDTODEVICE before connect(2), so a TCP/HTTP probe genuinely
// exercises the named interface rather than whatever route the kernel
// would otherwise pick (design.md §1, "uplink probing correctness").
func bindToDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}
}

// bindIPConnToDevice applies SO_BINDTODEVICE to an already-open raw IP
// socket (used by the ICMP prober, which can't go through Dialer.Control).
func bindIPConnToDevice(conn *net.IPConn, iface string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	}); err != nil {
		return err
	}
	return sockErr
}
