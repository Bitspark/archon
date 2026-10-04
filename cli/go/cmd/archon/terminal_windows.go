//go:build windows

package main

import "os"

// openTerminal opens the CONTROLLING TERMINAL for one prompt: the console's input and output
// devices, which are the person's console whatever the standard handles are. CONIN$ is
// opened read-write because changing its mode (no echo) needs write access to it.
func openTerminal() (in, out *os.File, err error) {
	in, err = os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	out, err = os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		in.Close()
		return nil, nil, err
	}
	return in, out, nil
}
