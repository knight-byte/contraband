package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/knight-byte/contraband/internal/correlate"
	"github.com/knight-byte/contraband/internal/daemon"
	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
	"github.com/knight-byte/contraband/internal/sensor/replay"
)

const usage = `Usage: contraband <command> [flags]

Commands:
  daemon              run the privileged monitoring daemon
  run -- <cmd> ...    run a command and audit its network activity
  watch               stream your connections live
  show <session>      what a session did: evidence and every connection
  allow [-package p] <host>
                      allow a destination (asks for your password)
  revoke [-package p] <host>
                      remove an allowed destination
  approve             approve edits to .contraband.yml (asks for your password)
  diff <a> <b>        compare destinations between two sessions
  export              write the verified event log as JSON Lines (root)
`

const defaultSocket = "/var/run/contraband.sock"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "contraband:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2, nil
	}
	command, args := args[0], args[1:]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	socket := flags.String("socket", defaultSocket, "daemon socket path")

	switch command {
	case "daemon":
		db := flags.String("db", defaultDB(), "event log path")
		rulesPath := flags.String("rules", defaultRules(), "root-owned file that extends the built-in detection rules")
		replayPath := flags.String("replay", "", "replay events from a JSON Lines file instead of the platform sensor")
		var level slog.Level
		flags.TextVar(&level, "log-level", slog.LevelInfo, "log level: debug logs every sensor event")
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		return 0, runDaemon(ctx, *socket, *db, *rulesPath, *replayPath, level)
	case "run":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		if flags.NArg() == 0 {
			return 2, errors.New("run: missing command, e.g. contraband run -- npm install")
		}
		return runSession(ctx, daemon.NewClient(*socket), flags.Args())
	case "watch":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		return 0, watch(ctx, daemon.NewClient(*socket))
	case "diff":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		if flags.NArg() != 2 {
			return 2, errors.New("diff: want two session ids")
		}
		return 0, diff(ctx, daemon.NewClient(*socket), flags.Arg(0), flags.Arg(1))
	case "show":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		if flags.NArg() != 1 {
			return 2, errors.New("show: want a session id")
		}
		return 0, show(ctx, daemon.NewClient(*socket), flags.Arg(0))
	case "allow":
		pkg := flags.String("package", "", "allow only for this package; empty allows it for any package")
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		if flags.NArg() != 1 {
			return 2, errors.New("allow: want one host or IP, e.g. contraband allow -package esbuild registry.npmjs.org")
		}
		return 0, allow(ctx, daemon.NewClient(*socket), flags.Arg(0), *pkg)
	case "revoke":
		pkg := flags.String("package", "", "the package the rule was for; empty for an any-package rule")
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		if flags.NArg() != 1 {
			return 2, errors.New("revoke: want one host or IP")
		}
		return 0, revoke(ctx, daemon.NewClient(*socket), flags.Arg(0), *pkg)
	case "approve":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		return 0, approve(ctx, daemon.NewClient(*socket))
	case "export":
		if err := flags.Parse(args); err != nil {
			return 2, nil
		}
		return 0, daemon.NewClient(*socket).Export(ctx, os.Stdout)
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
		return 0, nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2, fmt.Errorf("unknown command %q", command)
	}
}

func defaultDB() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Contraband/events.db"
	}
	return "/var/lib/contraband/events.db"
}

func defaultRules() string {
	if runtime.GOOS == "darwin" {
		return "/Library/Application Support/Contraband/rules.yml"
	}
	return "/etc/contraband/rules.yml"
}

func runDaemon(ctx context.Context, socket, db, rulesPath, replayPath string, level slog.Level) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	rules, err := score.LoadRules(rulesPath)
	if err != nil {
		return err
	}
	var sensor daemon.Sensor = replay.Sensor{Path: replayPath}
	if replayPath == "" {
		platform, err := platformSensor(logger)
		if err != nil {
			return err
		}
		sensor = platform
	}
	return daemon.Run(ctx, daemon.Config{Socket: socket, DB: db, Sensor: sensor, Rules: rules, Log: logger})
}

func runSession(ctx context.Context, client *daemon.Client, argv []string) (int, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	policyBytes, err := readPolicy()
	if err != nil {
		return 1, err
	}
	session, err := client.StartSession(ctx, daemon.StartRequest{Command: strings.Join(argv, " "), Cwd: cwd, Policy: policyBytes})
	if err != nil {
		return 1, err
	}
	if session.PolicyPending {
		out := styleFor(os.Stderr)
		fmt.Fprintf(os.Stderr, "contraband: %s\n", out.warn(policy.FileName+" has unapproved changes; run `contraband approve` to apply them"))
	}

	streamCtx, stopStream := context.WithCancel(ctx)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		_ = client.Stream(streamCtx, session.ID, func(msg daemon.Message) { printAlert(msg, filepath.Base(argv[0])) })
	}()

	// The child shares our terminal and receives Ctrl-C itself; we stay alive
	// to close the session and print the summary.
	signal.Ignore(os.Interrupt)
	child := exec.CommandContext(context.WithoutCancel(ctx), argv[0], argv[1:]...) //nolint:gosec // running the user's own command is the purpose of run
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	runErr := child.Run()
	signal.Reset(os.Interrupt)

	// Keep printing live alerts until the session closes: the daemon still
	// handles late sensor events after the child exits.
	policyAfter, err := readPolicy()
	if err != nil {
		stopStream()
		return 1, err
	}
	summary, err := client.EndSession(context.WithoutCancel(ctx), session.ID, daemon.EndRequest{PolicyHash: policy.Hash(policyAfter)})
	stopStream()
	<-streamDone
	if err != nil {
		return 1, err
	}
	printSummary(os.Stderr, session.ID, filepath.Base(argv[0]), summary)

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		fmt.Fprintf(os.Stderr, "contraband: %s\n", styleFor(os.Stderr).warn(fmt.Sprintf("%s exited with status %d", filepath.Base(argv[0]), exitErr.ExitCode())))
		return exitErr.ExitCode(), nil
	}
	return 0, runErr
}

func readPolicy() ([]byte, error) {
	content, err := os.ReadFile(policy.FileName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", policy.FileName, err)
	}
	return content, nil
}

// printAlert labels alerts outside any package with command, or
// "(command)" when the command is unknown, as in watch.
func printAlert(msg daemon.Message, command string) {
	alert := msg.Alert
	if alert == nil {
		return
	}
	out := styleFor(os.Stderr)
	if alert.Level == "health" {
		fmt.Fprintf(os.Stderr, "contraband: %s\n", out.warn(alert.Msg))
		return
	}
	tag := fmt.Sprintf("%s %s (score %d)", strings.ToUpper(alert.Level), labelOr(alert.Package, command), alert.Score)
	fmt.Fprintf(os.Stderr, "contraband: %s: %s\n", out.level(alert.Level, tag), shortenHome(alert.Msg))
}

// printSummary labels activity outside any package with command, the name of
// the program that was run.
func printSummary(file *os.File, id, command string, summary daemon.EndResponse) {
	label := func(pkg string) string {
		if pkg == "" {
			return command
		}
		return pkg
	}
	out := styleFor(file)
	flagged := 0
	for _, pkg := range summary.Packages {
		if pkg.Level != score.Log {
			flagged++
		}
	}
	session := out.dim("(session " + id + ")")
	active := false
	for _, pkg := range summary.Packages {
		active = active || len(pkg.SentTo) > 0 || len(pkg.Read) > 0 || len(pkg.Ran) > 0
	}
	switch {
	case flagged == 0 && !active:
		fmt.Fprintf(file, "\ncontraband: no network activity seen %s\n", session)
	case flagged == 0:
		fmt.Fprintf(file, "\ncontraband: %s %s\n", out.good(out.check()+" no issues"), session)
	case flagged == 1:
		fmt.Fprintf(file, "\ncontraband: %s %s\n", out.alert("1 package needs review"), session)
	default:
		fmt.Fprintf(file, "\ncontraband: %s %s\n", out.alert(fmt.Sprintf("%d packages need review", flagged)), session)
	}
	if summary.PolicyChanged {
		fmt.Fprintf(file, "  %s\n", out.warn("warning: "+policy.FileName+" changed during the session; the starting policy was kept"))
	}
	for _, pkg := range summary.Packages {
		if pkg.Level == score.Log {
			if len(pkg.SentTo) > 0 {
				fmt.Fprintf(file, "  %s %s  %s\n", out.good(fmt.Sprintf("%-9s", out.check())), label(pkg.Package), out.dim(hostList(pkg.SentTo)))
			}
			continue
		}
		tag := fmt.Sprintf("%-5s %-3d", strings.ToUpper(string(pkg.Level)), pkg.Score)
		fmt.Fprintf(file, "\n  %s %s\n", out.level(string(pkg.Level), tag), out.paint(ansiBold, label(pkg.Package)))
		for _, path := range pkg.Read {
			fmt.Fprintf(file, "            %s %s\n", out.dim("read    "), shortenHome(path))
		}
		for _, exe := range pkg.Ran {
			fmt.Fprintf(file, "            %s %s\n", out.dim("ran     "), exe)
		}
		for _, destination := range pkg.SentTo {
			line := destination.Host
			if destination.Note != "" {
				line += " " + out.level(string(pkg.Level), "("+destination.Note+")")
			}
			fmt.Fprintf(file, "            %s %s\n", out.dim("sent to "), line)
		}
	}
	if flagged > 0 {
		printNextSteps(file, out, id, summary.Packages)
	}
}

func printNextSteps(file *os.File, out style, id string, packages []correlate.PackageSummary) {
	fmt.Fprintf(file, "\n  %s contraband show %s\n", out.dim("inspect:     "), id)
	for _, pkg := range packages {
		if pkg.Level == score.Log {
			continue
		}
		for _, destination := range pkg.SentTo {
			if destination.Note == "allowed" {
				continue
			}
			command := "contraband allow " + destination.Host
			if pkg.Package != "" {
				command = "contraband allow -package " + pkg.Package + " " + destination.Host
			}
			fmt.Fprintf(file, "  %s %s\n", out.dim("if expected: "), command)
			return
		}
	}
}

func show(ctx context.Context, client *daemon.Client, id string) error {
	session, err := client.Show(ctx, id)
	if err != nil {
		return err
	}
	out := styleFor(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s %s\n", out.paint(ansiBold, "session "+id), out.dim(session.Cwd))
	fmt.Fprintf(os.Stdout, "  %s\n", session.Command)
	if session.Packages != nil {
		printSummary(os.Stdout, id, commandName(session.Command), daemon.EndResponse{Packages: session.Packages})
	}
	if len(session.Flows) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stdout, "\n%s\n", out.paint(ansiBold, "connections"))
	for _, flow := range session.Flows {
		fmt.Fprintf(os.Stdout, "  %s  %s\n", formatFlow(out, flow), out.dim(strings.Join(chainNames(flow.Chain), out.from())))
	}
	return nil
}

func chainNames(chain []string) []string {
	names := make([]string, 0, len(chain))
	for _, exe := range chain {
		names = append(names, filepath.Base(exe))
	}
	return names
}

func hostList(destinations []correlate.Destination) string {
	const shown = 3
	hosts := make([]string, 0, shown)
	for index, destination := range destinations {
		if index == shown {
			return fmt.Sprintf("%s +%d more", strings.Join(hosts, ", "), len(destinations)-shown)
		}
		host := destination.Host
		if destination.Note != "" {
			host += " (" + destination.Note + ")"
		}
		hosts = append(hosts, host)
	}
	return strings.Join(hosts, ", ")
}

func commandName(command string) string {
	first, _, _ := strings.Cut(command, " ")
	return filepath.Base(first)
}

func shortenHome(text string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return text
	}
	return strings.ReplaceAll(text, home+"/", "~/")
}

func labelOr(pkg, command string) string {
	switch {
	case pkg != "":
		return pkg
	case command != "":
		return command
	default:
		return "(command)"
	}
}

func watch(ctx context.Context, client *daemon.Client) error {
	return client.Stream(ctx, "", func(msg daemon.Message) {
		if msg.Alert != nil {
			printAlert(msg, "")
			return
		}
		fmt.Fprintln(os.Stdout, formatFlow(styleFor(os.Stdout), *msg.Flow))
	})
}

func formatFlow(out style, flow event.Flow) string {
	exe := "?"
	if len(flow.Chain) > 0 && flow.Chain[0] != "" {
		exe = filepath.Base(flow.Chain[0])
	}
	destination := flow.Dst.String()
	if flow.Domain != "" {
		destination = flow.Domain + " (" + destination + ")"
	}
	line := fmt.Sprintf("%s  %-6d %-24.24s %-4s %s %s",
		out.dim(flow.Time.Format("15:04:05")), flow.PID, exe, flow.Proto, out.arrow(), destination)
	if flow.Package != "" {
		line += "  " + out.paint(ansiBold, "["+flow.Package+"]")
	}
	if flow.Verdict == policy.Warn {
		line += "  " + out.warn("not in policy")
	}
	return line
}

func diff(ctx context.Context, client *daemon.Client, before, after string) error {
	result, err := client.Diff(ctx, before, after)
	if err != nil {
		return err
	}
	for _, added := range result.Added {
		fmt.Fprintln(os.Stdout, "+ "+added)
	}
	for _, removed := range result.Removed {
		fmt.Fprintln(os.Stdout, "- "+removed)
	}
	return nil
}
