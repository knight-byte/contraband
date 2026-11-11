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
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peer{}, fmt.Errorf("peer credentials: %w", err)
	}
	if credErr != nil {
		return peer{}, fmt.Errorf("peer credentials: %w", credErr)
	}
	return peer{PID: uint32(cred.Pid), UID: cred.Uid}, nil //nolint:gosec // kernel pids are positive
}
