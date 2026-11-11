package daemon

import (
	"context"
	"net"
)

type peer struct {
	PID uint32
	UID uint32
	ok  bool
}

func (caller peer) isRoot() bool { return caller.ok && caller.UID == 0 }

func (caller peer) canAccess(owner uint32) bool {
	return caller.ok && (caller.UID == 0 || caller.UID == owner)
}

type peerKey struct{}

func withPeer(ctx context.Context, conn net.Conn) context.Context {
	unixConn, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return ctx
	}
	caller, err := peerCredentials(unixConn)
	if err != nil {
		return ctx
	}
	caller.ok = true
	return context.WithValue(ctx, peerKey{}, caller)
}

// peerFrom returns a zero peer, which can access nothing, when the
// connection's credentials could not be read.
func peerFrom(ctx context.Context) peer {
	caller, _ := ctx.Value(peerKey{}).(peer)
	return caller
}
