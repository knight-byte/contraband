package daemon

import (
	"io"
	"strings"
)

func passwordChecker(username, password string) (string, []string, io.Reader) {
	return "/usr/bin/dscl", []string{"/Local/Default", "-authonly", username}, strings.NewReader(password + "\n")
}
