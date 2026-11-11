package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/knight-byte/contraband/internal/policy"
)

// policyStore keeps the approved policy per user and project directory in a
// root-only directory. The repository's .contraband.yml is only a proposal:
// anything that can write it, including the code being audited, gains
// nothing until its owner approves it with their password.
type policyStore struct {
	dir string
}

func (policies policyStore) path(uid uint32, cwd string) string {
	sum := sha256.Sum256([]byte(strconv.FormatUint(uint64(uid), 10) + "\x00" + cwd))
	return filepath.Join(policies.dir, hex.EncodeToString(sum[:16])+".yml")
}

// approved returns the approved policy, or an empty one when nothing has been
// approved for this directory yet.
func (policies policyStore) approved(uid uint32, cwd string) (*policy.Policy, []byte, error) {
	content, err := os.ReadFile(policies.path(uid, cwd))
	if errors.Is(err, fs.ErrNotExist) {
		content, err = nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("approved policy: %w", err)
	}
	parsed, err := policy.Parse(content)
	if err != nil {
		return nil, nil, fmt.Errorf("approved policy: %w", err)
	}
	return parsed, content, nil
}

func (policies policyStore) approve(uid uint32, cwd string, content []byte) error {
	if err := os.MkdirAll(policies.dir, 0o700); err != nil {
		return fmt.Errorf("approve policy: %w", err)
	}
	target := policies.path(uid, cwd)
	temp := target + ".tmp"
	if err := os.WriteFile(temp, content, 0o600); err != nil {
		return fmt.Errorf("approve policy: %w", err)
	}
	if err := os.Rename(temp, target); err != nil {
		return fmt.Errorf("approve policy: %w", err)
	}
	return nil
}
