//go:build !windows

package main

import "os"

// openTerminal opens the CONTROLLING TERMINAL for one prompt: /dev/tty, which is the
// session's terminal whatever fd 0 is. One descriptor reads and writes; the caller closes it.
func openTerminal() (in, out *os.File, err error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}
