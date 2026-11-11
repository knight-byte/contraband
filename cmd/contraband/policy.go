package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/knight-byte/contraband/internal/daemon"
	"github.com/knight-byte/contraband/internal/policy"
)

// allow adds a rule to the project's policy file, then asks for approval.
// Editing the file alone changes nothing; that is what keeps agents and
// audited code from allowing themselves.
func allow(ctx context.Context, client *daemon.Client, host, pkg string) error {
	content, err := readPolicy()
	if err != nil {
		return err
	}
	updated, err := policy.AddRule(content, policy.Rule{Domain: host, Package: pkg})
	if err != nil {
		return err
	}
	if err := os.WriteFile(policy.FileName, updated, 0o644); err != nil { //nolint:gosec // the policy file is meant to be committed and shared
		return fmt.Errorf("write %s: %w", policy.FileName, err)
	}
	return approve(ctx, client)
}

// revoke removes a rule. Tightening needs no password, so it applies at once.
func revoke(ctx context.Context, client *daemon.Client, host, pkg string) error {
	content, err := readPolicy()
	if err != nil {
		return err
	}
	updated, removed, err := policy.RemoveRule(content, policy.Rule{Domain: host, Package: pkg})
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("%s is not in %s", describeRule(policy.Rule{Domain: host, Package: pkg}), policy.FileName)
	}
	if err := os.WriteFile(policy.FileName, updated, 0o644); err != nil { //nolint:gosec // the policy file is meant to be committed and shared
		return fmt.Errorf("write %s: %w", policy.FileName, err)
	}
	return approve(ctx, client)
}

func approve(ctx context.Context, client *daemon.Client) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	proposed, err := readPolicy()
	if err != nil {
		return err
	}
	if proposed == nil {
		return fmt.Errorf("no %s in %s", policy.FileName, cwd)
	}
	after, err := policy.Parse(proposed)
	if err != nil {
		return err
	}
	current, err := client.ApprovedPolicy(ctx, cwd)
	if err != nil {
		return err
	}
	before, err := policy.Parse(current.Approved)
	if err != nil {
		return err
	}
	added, removed := policy.Diff(before, after)
	if len(added) == 0 && len(removed) == 0 {
		fmt.Fprintln(os.Stderr, "contraband: policy already approved")
		return nil
	}

	out := styleFor(os.Stderr)
	fmt.Fprintf(os.Stderr, "contraband: approve policy for %s\n", cwd)
	for _, rule := range added {
		fmt.Fprintf(os.Stderr, "  %s %s\n", out.warn("+ allow"), describeRule(rule))
	}
	for _, rule := range removed {
		fmt.Fprintf(os.Stderr, "  %s %s\n", out.good("- allow"), describeRule(rule))
	}
	var password string
	if len(added) > 0 {
		if password, err = readPassword("Password to approve: "); err != nil {
			return err
		}
	}
	if err := client.Approve(ctx, daemon.ApproveRequest{Cwd: cwd, Policy: proposed, Password: password}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "contraband: %s\n", out.good(out.check()+" approved"))
	return nil
}

func describeRule(rule policy.Rule) string {
	if rule.Package == "" {
		return rule.Domain + " for any package"
	}
	return rule.Domain + " for " + rule.Package
}

// readPassword reads from the controlling terminal only. Agents and scripts
// that run commands without a terminal cannot answer it, and nothing can
// pipe a password in.
func readPassword(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("approval needs an interactive terminal; run it yourself, not through a script or agent")
	}
	defer tty.Close() //nolint:errcheck // terminal handle
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	password, err := term.ReadPassword(int(tty.Fd()))
	if _, printErr := fmt.Fprintln(tty); printErr != nil && err == nil {
		err = printErr
	}
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(string(password), "\r\n"), nil
}
