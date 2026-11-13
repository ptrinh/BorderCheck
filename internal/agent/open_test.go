package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOpenReportPage(t *testing.T) {
	var opened []string
	openURL = func(_ context.Context, link string) error { opened = append(opened, link); return nil }
	t.Cleanup(func() { openURL = func(context.Context, string) error { return errors.New("not in tests") } })

	if err := Open(t.Context(), Env{Dir: t.TempDir(), Out: &strings.Builder{}}); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("not installed: %v", err)
	}

	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	// Nothing sent yet, then a receiver that gives no page: say so, open nothing.
	if err := Open(t.Context(), env); err == nil || !strings.Contains(err.Error(), "no report has been sent") {
		t.Errorf("before the first report: %v", err)
	}
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if err := Open(t.Context(), env); err == nil || !strings.Contains(err.Error(), "gives this computer no report page") {
		t.Errorf("no page: %v", err)
	}
	if len(opened) != 0 {
		t.Fatalf("opened %v", opened)
	}

	p.reportPageURL = p.url() + "/r/secret-page-id"
	if err := Send(t.Context(), env, true); err != nil {
		t.Fatal(err)
	}
	if err := Open(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || opened[0] != p.reportPageURL {
		t.Errorf("opened %v", opened)
	}
	if strings.Contains(out.String(), "secret-page-id") {
		t.Errorf("the link is in the output: %s", out)
	}

	// No browser: the link goes to the terminal only.
	openURL = func(context.Context, string) error { return errNoDesktop }
	if err := Open(t.Context(), env); err == nil {
		t.Error("no terminal and no browser: want an error")
	}
	term := &strings.Builder{}
	env.Term = term
	if err := Open(t.Context(), env); err != nil || !strings.Contains(term.String(), p.reportPageURL) || strings.Contains(out.String(), "secret-page-id") {
		t.Errorf("err %v, term %q", err, term)
	}
}

func TestSetUpRunsEachPartAndSavesWhatItDid(t *testing.T) {
	var ran []string
	oldL, oldC := launcher.ensure, command.ensure
	t.Cleanup(func() { launcher.ensure, command.ensure = oldL, oldC })
	launcher.ensure = func(Env, Config) error { ran = append(ran, "launcher"); return errors.New("no room") }
	command.ensure = func(_ Env, st *State) error { ran = append(ran, "command"); st.CommandSetUp = true; return nil }

	if err := SetUp(t.Context(), Env{Dir: t.TempDir(), Out: &strings.Builder{}}); err == nil {
		t.Error("not installed: want an error")
	}
	p := newPortal(t)
	env, out := enrolledEnv(t, p)
	if err := SetUp(t.Context(), env); err != nil {
		t.Fatal(err)
	}
	// One part failing is logged and does not stop the next.
	if strings.Join(ran, ",") != "launcher,command" || !strings.Contains(out.String(), "no room") {
		t.Errorf("ran %v\n%s", ran, out)
	}
	if !readState(t, env).CommandSetUp {
		t.Error("what the set-up did was not saved")
	}
}
