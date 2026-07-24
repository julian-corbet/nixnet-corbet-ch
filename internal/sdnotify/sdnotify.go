// Package sdnotify implements the systemd sd_notify(3) protocol without a
// cgo dependency on libsystemd — it's a trivial datagram write, and pulling
// in cgo would undermine the "single static cross-compiled artifact" goal
// design.md §1 picked Go for in the first place.
package sdnotify

import (
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Notify sends a state string (e.g. "READY=1", "WATCHDOG=1") to
// $NOTIFY_SOCKET. It is a silent no-op when NOTIFY_SOCKET is unset (not
// running under systemd — e.g. local development), matching sd_notify's
// own documented behavior.
func Notify(state string) error {
	socketPath := os.Getenv("NOTIFY_SOCKET")
	if socketPath == "" {
		return nil
	}
	// Linux abstract-namespace sockets are spelled with a leading '@' in
	// the environment variable but a leading NUL on the wire.
	addr := socketPath
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}

	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(state))
	return err
}

// WatchdogInterval returns how often Notify("WATCHDOG=1") should be called
// to comfortably stay inside systemd's WatchdogSec (half of WATCHDOG_USEC,
// the conventional safety margin), or 0 if the unit has no watchdog
// configured (WATCHDOG_USEC unset — again, a plain no-op, not an error).
func WatchdogInterval() time.Duration {
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return 0
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}
