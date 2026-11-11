package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(conn *net.UnixConn) (peer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return peer{}, fmt.Errorf("peer credentials: %w", err)
	}
	var cred *unix.Xucred
	var pid int
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			pid, credErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		}
	}); err != nil {
		return peer{}, fmt.Errorf("peer credentials: %w", err)
	}
	if credErr != nil {
		return peer{}, fmt.Errorf("peer credentials: %w", credErr)
	}
	return peer{PID: uint32(pid), UID: cred.Uid}, nil //nolint:gosec // kernel pids are positive
}
