package main

// `archon enroll` (docs/enroll.md §4): the statement and the policy refusal against the fixture
// all three lanes read, then the command itself against a sealed store key, with the terminal
// played by two pipes, and every refusal checked for where it lands: before the statement, or
// after a "no", and never with anything on stdout.

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/enroll"
)

type enrollFixture struct {
	Cases []struct {
		Name     string `json:"name"`
		Audience string `json:"audience"`
		Intent   struct {
			AccountID    string   `json:"account_id"`
			AccountName  string   `json:"account_name"`
			Restrictions []string `json:"restrictions"`
		} `json:"intent"`
		Key       string `json:"key"`
		Deadline  int64  `json:"deadline"`
		KeySource string `json:"keySource"`
		Statement string `json:"statement"`
		Prompt    string `json:"prompt"`
	} `json:"cases"`
	PolicyCases []struct {
		Name   string `json:"name"`
		Key    string `json:"key"`
		Policy struct {
			Contexts []string `json:"contexts"`
		} `json:"policy"`
		Refusal string `json:"refusal"`
	} `json:"policy_cases"`
}

func loadEnrollFixture(t *testing.T) enrollFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "enroll-statement.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f enrollFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 || len(f.PolicyCases) == 0 {
		t.Fatal("the fixture holds no cases")
	}
	return f
}

func TestEnrollStatementFixture(t *testing.T) {
	for _, c := range loadEnrollFixture(t).Cases {
		key, err := keytext.DecodeKey(c.Key)
		if err != nil {
			t.Fatal(err)
		}
		intent := &enroll.Intent{AccountID: c.Intent.AccountID, AccountName: c.Intent.AccountName, Purpose: "add-key", Restrictions: c.Intent.Restrictions}
		if got := renderEnrollStatement(c.Audience, intent, key, time.Unix(c.Deadline, 0), c.KeySource); got != c.Statement {
			t.Errorf("%s: statement\n got: %q\nwant: %q", c.Name, got, c.Statement)
		}
		if got := enrollPrompt(intent); got != c.Prompt {
			t.Errorf("%s: prompt\n got: %q\nwant: %q", c.Name, got, c.Prompt)
		}
	}
}

func TestEnrollPolicyRefusalFixture(t *testing.T) {
	for _, c := range loadEnrollFixture(t).PolicyCases {
		p := &keystore.Policy{Contexts: c.Policy.Contexts}
		if got := policyRefusal(c.Key, p); got != c.Refusal {
			t.Errorf("%s:\n got: %q\nwant: %q", c.Name, got, c.Refusal)
		}
	}
}

// enrollWorld is a store holding one sealed key, a clock, a terminal answering `answer`, and a
// challenge token for that key written to a file.
type enrollWorld struct {
	home, audience, tokenPath string
	key                       []byte
	terminal                  *strings.Builder
}

const enrollAudience = "https://bitshelf.dev/api"

var enrollNow = time.Date(2026, 10, 5, 10, 30, 0, 0, time.UTC)

func newEnrollWorld(t *testing.T, policy keystore.Policy, answer string) *enrollWorld {
	t.Helper()
	home := t.TempDir()
	t.Setenv("ARCHON_HOME", home)
	const password = "a password with a space"
	t.Setenv("ARCHON_KEY_PASSWORD", password)
	t.Setenv("ARCHON_AUDIENCE", "")
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 0x21)
	}
	if _, err := sealAndWrite(filepath.Join(home, "keys", "personal"), seed, []byte(password), policy); err != nil {
		t.Fatal(err)
	}
	savedClock, savedTerminal := clockNow, enrollTerminal
	t.Cleanup(func() { clockNow = savedClock; enrollTerminal = savedTerminal })
	clockNow = func() time.Time { return enrollNow }
	w := &enrollWorld{home: home, audience: enrollAudience, key: crypto.PublicKeyFromSeed(seed), terminal: &strings.Builder{}}
	enrollTerminal = func() (*os.File, *os.File, error) {
		inR, inW, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		inW.WriteString(answer)
		inW.Close()
		outR, outW, err := os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		done := make(chan struct{})
		go func() {
			b, _ := io.ReadAll(outR)
			w.terminal.Write(b)
			close(done)
		}()
		t.Cleanup(func() { <-done })
		return inR, outW, nil
	}
	return w
}

// token writes a challenge token for the world's key, edited by edit, and returns its path.
func (w *enrollWorld) token(t *testing.T, edit func(c *enroll.Challenge, i *enroll.Intent)) string {
	t.Helper()
	i := &enroll.Intent{Blind: make([]byte, 16), AccountID: "u_8f3c2a", AccountName: "julia (bitspark)", Purpose: "add-key"}
	c := &enroll.Challenge{
		Audience: w.audience, Transaction: []byte{0x8f, 0x3c}, Nonce: make([]byte, 16), NewKey: w.key,
		Deadline: enrollNow.Add(15 * time.Minute),
	}
	if edit != nil {
		edit(c, i)
	}
	intent, err := enroll.EncodeIntent(i)
	if err != nil {
		t.Fatal(err)
	}
	c.Intent = intent
	text, err := enroll.EncodeChallenge(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.home, "challenge.txt")
	if err := os.WriteFile(path, []byte(text+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnrollMakesTheProofForWhatItShowed(t *testing.T) {
	w := newEnrollWorld(t, keystore.Policy{Contexts: []string{enroll.Domain}}, "y\n")
	path := w.token(t, func(_ *enroll.Challenge, i *enroll.Intent) { i.Restrictions = []string{"read:projects"} })
	stdout, stderr, err := captureBoth(t, func() error {
		return runEnroll([]string{"--challenge-file", path, "--audience", w.audience, "--key", "personal"})
	})
	if err != nil {
		t.Fatalf("runEnroll: %v (stderr %q)", err, stderr)
	}
	// stdout is the proof token and nothing else.
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], enroll.ProofPrefix) {
		t.Fatalf("stdout %q: want one proof token", stdout)
	}
	p, err := enroll.DecodeProof(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	ch, _ := enroll.DecodeChallenge(string(raw))
	req, _, _ := ch.Request()
	if !enroll.Verify(w.audience, req, p.Proof) || string(p.Transaction) != string(req.Transaction) {
		t.Fatal("the proof does not verify for the request the token yields")
	}
	shown := w.terminal.String()
	for _, want := range []string{
		"https://bitshelf.dev/api asks you to add a key to an account:\n",
		"  account:      julia (bitspark)\n",
		"  key:          " + keytext.EncodeKey(w.key) + "\n",
		"  restrictions:\n    read:projects\n",
		"signing with the store key personal\n",
		`add this key to the account "julia (bitspark)"? [y/N] `,
		"proof produced.",
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("the terminal did not show %q:\n%s", want, shown)
		}
	}
}

func TestEnrollRefusals(t *testing.T) {
	enrollOnly := keystore.Policy{Contexts: []string{enroll.Domain}}
	for _, tc := range []struct {
		name     string
		policy   keystore.Policy
		answer   string
		edit     func(c *enroll.Challenge, i *enroll.Intent)
		args     func(w *enrollWorld, path string) []string
		want     string // in the error, or on the terminal for a "no"
		shownYet bool   // whether the statement may have been shown
	}{
		{name: "another audience", policy: enrollOnly, answer: "y\n",
			edit: func(c *enroll.Challenge, _ *enroll.Intent) { c.Audience = "https://bitshelf.dev/other" },
			want: `the token is for "https://bitshelf.dev/other", not the audience you selected, "https://bitshelf.dev/api"`},
		{name: "another key", policy: enrollOnly, answer: "y\n",
			edit: func(c *enroll.Challenge, _ *enroll.Intent) { c.NewKey = crypto.PublicKeyFromSeed(make([]byte, 32)) },
			want: "not this key"},
		{name: "the deadline is now", policy: enrollOnly, answer: "y\n",
			edit: func(c *enroll.Challenge, _ *enroll.Intent) { c.Deadline = enrollNow },
			want: "has passed"},
		{name: "a purpose this archon does not render", policy: enrollOnly, answer: "y\n",
			edit: func(_ *enroll.Challenge, i *enroll.Intent) { i.Purpose = "rotate" },
			want: `the intent's purpose is "rotate"`},
		{name: "a policy without archon-enroll/1", policy: keystore.Policy{Contexts: []string{"thesmos/fact/v2"}}, answer: "y\n",
			want: "archon key policy personal --allow thesmos/fact/v2 --allow archon-enroll/1"},
		{name: "the person says no", policy: enrollOnly, answer: "n\n", want: "refused. nothing was signed.", shownYet: true},
		{name: "no answer at all", policy: enrollOnly, answer: "", want: "refused. nothing was signed.", shownYet: true},
		{name: "the token and the password on one stdin", policy: enrollOnly, answer: "y\n",
			args: func(w *enrollWorld, _ string) []string {
				return []string{"--audience", w.audience, "--password-fd", "0"}
			},
			want: "--password-fd 0"},
		{name: "no audience", policy: enrollOnly, answer: "y\n",
			args: func(_ *enrollWorld, path string) []string {
				return []string{"--challenge-file", path, "--key", "personal"}
			},
			want: "no audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newEnrollWorld(t, tc.policy, tc.answer)
			path := w.token(t, tc.edit)
			args := []string{"--challenge-file", path, "--audience", w.audience, "--key", "personal"}
			if tc.args != nil {
				args = tc.args(w, path)
			}
			stdout, _, err := captureBoth(t, func() error { return runEnroll(args) })
			if stdout != "" {
				t.Fatalf("stdout %q: a refusal prints nothing there", stdout)
			}
			got := w.terminal.String()
			if err != nil {
				got = err.Error()
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want it to contain %q", got, tc.want)
			}
			if !tc.shownYet && strings.Contains(w.terminal.String(), "asks you to add a key") {
				t.Fatal("the statement was shown before a refusal that needed nothing from the person")
			}
		})
	}
}

func TestEnrollRefusesWithNoTerminal(t *testing.T) {
	w := newEnrollWorld(t, keystore.Policy{Contexts: []string{enroll.Domain}}, "y\n")
	path := w.token(t, nil)
	enrollTerminal = func() (*os.File, *os.File, error) { return nil, nil, os.ErrNotExist }
	stdout, _, err := captureBoth(t, func() error {
		return runEnroll([]string{"--challenge-file", path, "--audience", w.audience, "--key", "personal"})
	})
	if err == nil || !strings.Contains(err.Error(), "no terminal to ask on") || stdout != "" {
		t.Fatalf("err %v, stdout %q: want a refusal naming the terminal", err, stdout)
	}
}
