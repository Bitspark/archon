package keystore

// Where the key store lives and what a key may be called — docs/keystore.md §1 and §5.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const NameMaxBytes = 64

// reservedDeviceNames are refused bare AND with any extension: Windows treats CON.key as
// the device CON, so `archon key add CON.key` would name a file nobody can open.
var reservedDeviceNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true,
	"com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true,
	"lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// ValidateName restricts rather than escapes: a name is a path segment on three
// operating systems, and quoting it correctly on all of them is a harder problem than
// refusing the characters that make it interesting.
func ValidateName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("a key name may not be empty")
	case len(name) > NameMaxBytes:
		return fmt.Errorf("a key name may be at most %d bytes (got %d)", NameMaxBytes, len(name))
	case strings.HasPrefix(name, "."):
		return fmt.Errorf("a key name may not begin with %q: it would hide the key", ".")
	case strings.HasSuffix(name, "."):
		// Windows strips a trailing dot, so `alice.` and `alice` would be one file on one
		// OS and two on another.
		return fmt.Errorf("a key name may not end with %q", ".")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if !ok {
			if c < 0x20 || c == 0x7f {
				return fmt.Errorf("a key name may not contain control characters")
			}
			return fmt.Errorf("a key name may not contain %q; allowed: letters, digits, %q, %q, %q",
				string(rune(c)), ".", "_", "-")
		}
	}
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if reservedDeviceNames[strings.ToLower(stem)] {
		return fmt.Errorf("%q is a reserved device name on Windows, with or without an extension", name)
	}
	return nil
}

// Dir is $ARCHON_HOME/keys, ARCHON_HOME defaulting to ~/.archon.
func Dir() (string, error) {
	home := os.Getenv("ARCHON_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not resolve the home directory (set ARCHON_HOME): %w", err)
		}
		home = filepath.Join(h, ".archon")
	}
	return filepath.Join(home, "keys"), nil
}

func Path(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// WriteFile writes atomically: a temp file in the SAME directory, then a rename, so a
// crash mid-write can never leave a half key where a whole one was.
func WriteFile(path string, blob []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("could not create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("could not create a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Windows will not rename onto an existing file; the callers refuse an existing name
	// first, so a leftover here is a genuine race and the error is the right answer.
	return os.Rename(tmpName, path)
}

// ListNames returns the store's key names, sorted, skipping the temp files an
// interrupted write may have left behind. A missing store directory is an empty store,
// not an error: nothing has been added yet.
func ListNames() ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
