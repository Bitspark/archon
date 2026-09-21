// The door checks of docs/login.md §3.1, tested on the function rather than through the
// route.
//
// Through begin these are invisible: the scheme's own Binding refuses the same strings, so a
// malformed scope entry answers 400 either way and a route-level test cannot tell which check
// fired. That is not a guess -- the call was removed from begin and `go test ./...` stayed
// green, which is how this file came to exist.
//
// They still belong at the door. The scheme refuses when a proof is MADE, which is AFTER the
// person has read the statement, so an entry that could repaint the terminal would already
// have been shown. Checking here means it never exists to be shown.
package login

import "testing"

func TestAScopeEntryThatCouldLieOnScreenIsRefusedAtTheDoor(t *testing.T) {
	for _, c := range []struct {
		name  string
		entry string
	}{
		{"an empty entry", ""},
		{"ESC [ 2 J, which clears the screen", "read:\x1b[2Jx"},
		{"NUL", "read:\x00"},
		{"DEL", "read:\x7f"},
		{"CRLF", "read:\r\nX-Evil: 1"},
		// A Go string can hold bytes that are not UTF-8 at all. Rust needs no such case --
		// its String cannot hold one -- which is exactly why go and ts must check.
		{"invalid UTF-8", "read:" + string([]byte{0xff, 0xfe})},
	} {
		if err := checkScopeEntry(c.entry); err == nil {
			t.Errorf("%s: accepted, and the CLI would print it verbatim", c.name)
		}
	}
	// Ordinary text passes, astral characters included: refusing every emoji would be a
	// different bug wearing the same clothes.
	for _, entry := range []string{"read:projects", "read:\U0001F680"} {
		if err := checkScopeEntry(entry); err != nil {
			t.Errorf("%q: refused (%v)", entry, err)
		}
	}
}
