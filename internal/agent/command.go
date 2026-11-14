package agent

import (
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/guard"
)

// command makes plain `bordercheck` work in a terminal: the install folder is
// not on PATH. ensure is called on every hourly run, like launcher.ensure, so
// an install made by an older version gets it too; what changes a person's own
// settings (a line in their shell profile, their PATH on Windows) is done once
// (State.CommandSetUp), so undoing it by hand sticks. Tests replace it.
var command = struct {
	ensure func(env Env, st *State) error
	remove func(env Env) error
}{ensureCommand, removeCommand}

// removeGuard takes out the Claude Code hook `bordercheck guard install` set
// up with this install's program, which would fail once it is gone; a guard
// using another copy stays. Tests replace it.
var removeGuard = func(env Env) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	_, err = guard.Uninstall(guard.SettingsPath(home), filepath.Join(env.Dir, binName()))
	return err
}
