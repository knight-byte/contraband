package daemon

import (
	"context"
	"os/exec"
	"strconv"
)

// desktopNotify shows a Notification Center banner in the user's GUI session.
// Title and message are passed as osascript arguments, never spliced into the
// script, so their content cannot inject AppleScript.
func desktopNotify(ctx context.Context, uid uint32, title, message string) error {
	id := strconv.FormatUint(uint64(uid), 10)
	return exec.CommandContext(ctx, "/bin/launchctl", "asuser", id, "/usr/bin/sudo", "-u", "#"+id, //nolint:gosec // fixed binaries; title and message are argv, not script
		"/usr/bin/osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run",
		title, message).Run()
}
