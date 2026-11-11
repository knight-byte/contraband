package daemon

import (
	"context"
	"encoding/json"
	"time"

	"github.com/knight-byte/contraband/internal/event"
	"github.com/knight-byte/contraband/internal/policy"
	"github.com/knight-byte/contraband/internal/score"
	"github.com/knight-byte/contraband/internal/store"
)

type sessionSettings struct {
	profile  string
	enforce  string
	research bool
	policy   *policy.Policy
}

// settingsFor applies the first matching profile. A profile's enforcement
// replaces baseEnforce; requested, from `run -enforce`, can only add to it.
func (daemon *Daemon) settingsFor(exe string, args []string, cwd string, approved *policy.Policy, baseEnforce, requested string) sessionSettings {
	settings := sessionSettings{enforce: baseEnforce, policy: approved}
	if profile := daemon.config.Rules.ProfileFor(exe, args, cwd); profile != nil {
		settings.profile, settings.research = profile.Name, profile.Research
		if profile.Enforce != "" {
			settings.enforce = profile.Enforce
		}
		settings.policy = approved.With(profile.Allow)
	}
	settings.enforce = score.Stronger(settings.enforce, requested)
	if settings.enforce == score.EnforceOff {
		settings.enforce = ""
	}
	return settings
}

type rulesLoaded struct {
	Hash string `json:"hash"`
}

// checkRules records which rules file the daemon runs with and raises a
// health alert when it changed since the previous start: rules widen what is
// allowed, so a change made by something holding cached sudo rights must be
// visible.
func (daemon *Daemon) checkRules(ctx context.Context) error {
	current := rulesLoaded{Hash: daemon.config.Rules.Hash}
	previous, err := daemon.store.Latest(ctx, store.KindRulesLoaded)
	if err != nil {
		return err
	}
	var last rulesLoaded
	if previous != nil && json.Unmarshal(previous, &last) == nil && last.Hash != current.Hash {
		daemon.record(ctx, store.KindHealth, "", Message{Alert: &event.Alert{
			Time: time.Now(), Level: "health", Msg: "detection rules changed since the daemon last started",
		}})
	}
	return daemon.store.Append(ctx, store.KindRulesLoaded, "", current)
}
