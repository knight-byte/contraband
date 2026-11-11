package daemon

import (
	"io"
	"strings"
)

// unix_chkpwd is the setgid helper pam_unix itself uses; it reads a
// NUL-terminated password on stdin.
func passwordChecker(username, password string) (string, []string, io.Reader) {
	return "/usr/sbin/unix_chkpwd", []string{username, "nonull"}, strings.NewReader(password + "\x00")
}
