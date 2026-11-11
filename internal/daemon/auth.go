package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var (
	ErrBadPassword  = errors.New("password not accepted")
	ErrTooManyTries = errors.New("too many failed approvals; try again later")
)

const (
	maxFailures   = 3
	failureWindow = 5 * time.Minute
	verifyTimeout = 10 * time.Second
)

// limiter caps failed approvals per user so an agent or script cannot guess
// the password; each failure also counts toward the OS account lockout.
type limiter struct {
	mu       sync.Mutex
	failures map[uint32][]time.Time
}

func newLimiter() *limiter { return &limiter{failures: map[uint32][]time.Time{}} }

func (limit *limiter) allowed(uid uint32, now time.Time) bool {
	limit.mu.Lock()
	defer limit.mu.Unlock()
	recent := limit.failures[uid][:0]
	for _, when := range limit.failures[uid] {
		if now.Sub(when) < failureWindow {
			recent = append(recent, when)
		}
	}
	limit.failures[uid] = recent
	return len(recent) < maxFailures
}

func (limit *limiter) fail(uid uint32, now time.Time) {
	limit.mu.Lock()
	defer limit.mu.Unlock()
	limit.failures[uid] = append(limit.failures[uid], now)
}

// verifyPassword asks the OS whether password belongs to the account with
// uid. The password travels on stdin, never argv, and the checker runs in a
// new session so it cannot prompt on the daemon's terminal.
func verifyPassword(ctx context.Context, uid uint32, password string) error {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	path, args, input := passwordChecker(account.Username, password)
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // fixed checker path; the username comes from the OS account database
	cmd.Stdin = input
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return ErrBadPassword
	}
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	return nil
}
