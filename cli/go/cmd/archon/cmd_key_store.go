package main

// `archon key add|list|rm|default|export` — the password-protected seed store of
// ADR 0007 §A. The format lives in internal/keystore; this file is the command: flags,
// prompts, paths, and the lines we print about what we did.
//
// Every operation that destroys, reveals or creates key material says so IN SCOPE
// (docs/keystore.md §6): archon speaks for its own store and never for anyone else's, so
// an empty result means "nothing visible here", never "nothing exists". The wording is
// pinned in cli/smoke.mjs.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/hexbytes"
	"github.com/Bitspark/archon/core/go/keycodec"
	"github.com/Bitspark/archon/core/go/keytext"
)

const keyStoreUsage = "usage: archon key <add <name> [--seed <hex>|--seed-file <file>|--pkcs8 <file>]|" +
	"list [--json]|rm <name> [--force]|default [<name>]|export <name> --reveal --out <file>>\n  " +
	"the password-protected seed store; keys live in $ARCHON_HOME/keys (default ~/.archon). " +
	"Password: interactive prompt, or ARCHON_KEY_PASSWORD / --password-fd <n>, never argv."

// runKeyAdd stores a seed under a name, generating one when no source is given.
func runKeyAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", keyStoreUsage)
	}
	name := args[0]
	if err := keystore.ValidateName(name); err != nil {
		return err
	}
	var seedHex, seedFile, pkcs8File string
	rest, pwFD, err := takePasswordFD(args[1:])
	if err != nil {
		return err
	}
	for i := 0; i < len(rest); i += 2 {
		if i+1 >= len(rest) {
			return fmt.Errorf("flag %q needs a value\n%s", rest[i], keyStoreUsage)
		}
		switch rest[i] {
		case "--seed":
			seedHex = rest[i+1]
		case "--seed-file":
			seedFile = rest[i+1]
		case "--pkcs8":
			pkcs8File = rest[i+1]
		default:
			return fmt.Errorf("unknown flag %q\n%s", rest[i], keyStoreUsage)
		}
	}
	sources := 0
	for _, s := range []string{seedHex, seedFile, pkcs8File} {
		if s != "" {
			sources++
		}
	}
	if sources > 1 {
		return fmt.Errorf("--seed, --seed-file and --pkcs8 are mutually exclusive\n%s", keyStoreUsage)
	}

	path, err := keystore.Path(name)
	if err != nil {
		return err
	}
	// Refused BEFORE a password is asked for: a key is never silently replaced, and there
	// is no reason to make someone type a password to find that out.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("a key named %q already exists; remove it first (archon key rm %s)", name, name)
	}

	var seed []byte
	var from string
	switch {
	case seedHex != "":
		if seed, err = seedFromHexish(seedHex); err != nil {
			return fmt.Errorf("--seed: %w", err)
		}
		from = "--seed"
	case seedFile != "":
		raw, e := os.ReadFile(seedFile)
		if e != nil {
			return fmt.Errorf("could not read %q: %w", seedFile, e)
		}
		if seed, err = seedFromHexish(strings.TrimSpace(string(raw))); err != nil {
			return fmt.Errorf("%s: %w", seedFile, err)
		}
		from = seedFile
	case pkcs8File != "":
		raw, e := os.ReadFile(pkcs8File)
		if e != nil {
			return fmt.Errorf("could not read %q: %w", pkcs8File, e)
		}
		if seed, err = keycodec.PKCS8PEMToSeed(raw); err != nil {
			return fmt.Errorf("%s: %w", pkcs8File, err)
		}
		from = pkcs8File
	default:
		seed = make([]byte, crypto.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return fmt.Errorf("could not read OS randomness: %w", err)
		}
	}
	defer keystore.Zeroise(seed)

	password, err := readPassword(pwFD, true)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(password)

	principal, err := sealAndWrite(path, seed, password)
	if err != nil {
		return err
	}
	if from == "" {
		fmt.Printf("generated and stored %s (%s).\n", name, principal)
	} else {
		fmt.Printf("stored %s (%s) from %s; the source file is untouched.\n", name, principal, from)
	}
	return nil
}

// runKeyList prints what each header CLAIMS. The claim is only proven at unlock, which is
// why this never opens a key and never asks for a password.
func runKeyList(args []string) error {
	asJSON := false
	for _, a := range args {
		if a != "--json" {
			return fmt.Errorf("unknown flag %q\n%s", a, keyStoreUsage)
		}
		asJSON = true
	}
	names, err := keystore.ListNames()
	if err != nil {
		return err
	}
	type row struct {
		Name      string `json:"name"`
		Principal string `json:"principal"`
	}
	rows := make([]row, 0, len(names))
	for _, n := range names {
		path, err := keystore.Path(n)
		if err != nil {
			continue // a file the store cannot name is not a key; `rm --force` deals with it
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h, err := keystore.ParseHeader(raw)
		if err != nil {
			continue // the magic is what keeps a stray file out of this list
		}
		rows = append(rows, row{Name: n, Principal: keytext.EncodeKey(h.PublicKey)})
	}
	if asJSON {
		out, err := json.Marshal(rows)
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	for _, r := range rows {
		fmt.Printf("%s\t%s\n", r.Name, r.Principal)
	}
	return nil
}

// runKeyRm removes a key and says exactly what it removed, from where, and what it does
// NOT speak for. An unparsable file is refused unless --force: deleting an unrecognised
// file inside the store silently is what this rule exists to prevent.
func runKeyRm(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", keyStoreUsage)
	}
	name, force := args[0], false
	for _, a := range args[1:] {
		if a != "--force" {
			return fmt.Errorf("unknown flag %q\n%s", a, keyStoreUsage)
		}
		force = true
	}
	path, err := keystore.Path(name)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no key named %q in archon's store", name)
	}
	h, parseErr := keystore.ParseHeader(raw)
	if parseErr != nil && !force {
		return fmt.Errorf("not an archon key file: %s: %v", path, parseErr)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("could not remove %s: %w", path, err)
	}
	if parseErr != nil {
		fmt.Printf("removed %s (unreadable header: %v) from archon's store at %s; "+
			"any copy of this key outside it is untouched.\n", name, parseErr, path)
		return nil
	}
	fmt.Printf("removed %s (%s) from archon's store at %s; "+
		"any copy of this key outside it is untouched.\n", name, keytext.EncodeKey(h.PublicKey), path)
	return nil
}

// runKeyDefault sets or shows the default key. Selection is by NAME, never by principal
// text (ADR 0007 §A). The pointer lives beside keys/, not in it, so it can never collide
// with a key name.
func runKeyDefault(args []string) error {
	pointer, err := defaultPointerPath()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		name, err := readDefaultKeyName()
		if err != nil {
			return err
		}
		if name == "" {
			return fmt.Errorf("no default key is set")
		}
		fmt.Println(name)
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("%s", keyStoreUsage)
	}
	name := args[0]
	if err := requireNamedKey(name); err != nil {
		return err
	}
	if err := os.WriteFile(pointer, []byte(name+"\n"), 0o600); err != nil {
		return fmt.Errorf("could not write %s: %w", pointer, err)
	}
	fmt.Printf("default key is now %s.\n", name)
	return nil
}

// requireNamedKey is the store's own "is there a key called that": a validated name, then a
// stat — opening nothing, asking for no password. Shared by `key default <name>` and by
// `login`'s pre-network check, so both refuse a missing key with one wording.
func requireNamedKey(name string) error {
	path, err := keystore.Path(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no key named %q in archon's store", name)
	}
	return nil
}

// defaultPointerPath is $ARCHON_HOME/default: BESIDE keys/, never inside it, so the pointer
// can never collide with a key name.
func defaultPointerPath() (string, error) {
	dir, err := keystore.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(dir), "default"), nil
}

// readDefaultKeyName is the ONE reader of the default pointer, shared by `key default` and
// by `login`'s fallback so the two can never disagree about what "the default" is. Absent,
// unreadable, or present-but-empty all read as "" with no error — there is no default —
// and the caller says what that means for it.
func readDefaultKeyName() (string, error) {
	pointer, err := defaultPointerPath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(pointer)
	if err != nil {
		return "", nil
	}
	return strings.TrimSpace(string(raw)), nil
}

// runKeyExport writes the seed out. It refuses without --reveal, and refuses to write to
// stdout unless `--out -` is given explicitly: a seed should never land in a pipe by
// accident.
func runKeyExport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", keyStoreUsage)
	}
	name := args[0]
	rest, pwFD, err := takePasswordFD(args[1:])
	if err != nil {
		return err
	}
	reveal, out := false, ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--reveal":
			reveal = true
		case "--out":
			if i+1 >= len(rest) {
				return fmt.Errorf("flag %q needs a value\n%s", "--out", keyStoreUsage)
			}
			out = rest[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag %q\n%s", rest[i], keyStoreUsage)
		}
	}
	if !reveal {
		return fmt.Errorf("refusing to export a seed without --reveal")
	}
	if out == "" {
		return fmt.Errorf("refusing to write a seed to stdout: pass --out <file>, or --out - to mean it")
	}
	seed, err := unlockNamedKey(name, pwFD)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(seed)
	pem, err := keycodec.SeedToPKCS8PEM(seed)
	if err != nil {
		return err
	}
	if out == "-" {
		fmt.Print(string(pem))
		fmt.Fprintf(os.Stderr, "wrote the seed of %s to stdout; the store's copy remains.\n", name)
		return nil
	}
	if err := os.WriteFile(out, pem, 0o600); err != nil {
		return fmt.Errorf("could not write %q: %w", out, err)
	}
	fmt.Printf("wrote the seed of %s to %s; the store's copy remains.\n", name, out)
	return nil
}

// unlockNamedKey opens the key called name: the path, the file, the password — sourced the
// store's one way (--password-fd, then ARCHON_KEY_PASSWORD, then a prompt) — and the seal.
// It is the ONE unlock path, shared by `key export` and `login --key`, so no two commands
// can ask for a password differently. The caller owns the seed and must Zeroise it.
func unlockNamedKey(name string, pwFD int) ([]byte, error) {
	path, err := keystore.Path(name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no key named %q in archon's store", name)
	}
	password, err := readPassword(pwFD, false)
	if err != nil {
		return nil, err
	}
	defer keystore.Zeroise(password)
	return keystore.Open(raw, password)
}

// seedFromHexish accepts the two shapes ADR 0007 §A names: a 32-byte seed as 64 hex, and
// the first consumer's ed25519.PrivateKey shape as 128 hex (seed ‖ public key). The public half is
// CHECKED against the seed rather than trusted — a mismatch means the file is not what its
// owner thinks it is, and storing it would carry the confusion forward.
func seedFromHexish(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	switch len(s) {
	case 64:
		return hexbytes.SeedFromHex(s)
	case 128:
		seed, err := hexbytes.SeedFromHex(s[:64])
		if err != nil {
			return nil, err
		}
		claimed, err := hexbytes.PubkeyFromHex(s[64:])
		if err != nil {
			return nil, err
		}
		derived := crypto.PublicKeyFromSeed(seed)
		if string(claimed) != string(derived) {
			return nil, fmt.Errorf("the public half does not match the seed: this is not a consistent private key")
		}
		return seed, nil
	default:
		return nil, fmt.Errorf("expected 64 hex characters (a seed) or 128 (seed ‖ public key), got %d", len(s))
	}
}

// takePasswordFD scans for `--password-fd <n>` and removes it. The password never travels
// in argv, so this carries a descriptor number rather than the secret.
func takePasswordFD(args []string) (rest []string, fd int, err error) {
	fd = -1
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--password-fd" {
			if i+1 >= len(args) {
				return nil, -1, fmt.Errorf("flag %q needs a value", "--password-fd")
			}
			n, e := strconv.Atoi(args[i+1])
			if e != nil || n < 0 {
				return nil, -1, fmt.Errorf("--password-fd: %q is not a file descriptor", args[i+1])
			}
			fd = n
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest, fd, nil
}

// readPassword sources the password: --password-fd, then ARCHON_KEY_PASSWORD, then an
// interactive prompt. Never argv. `confirm` asks twice when a key is being created, where
// a typo would otherwise be discovered only at the next unlock.
func readPassword(fd int, confirm bool) ([]byte, error) {
	if fd >= 0 {
		f := os.NewFile(uintptr(fd), fmt.Sprintf("fd/%d", fd))
		if f == nil {
			return nil, fmt.Errorf("--password-fd: %d is not open", fd)
		}
		if err := refuseLoosePasswordFile(f); err != nil {
			return nil, err
		}
		buf := make([]byte, 4096)
		n, err := f.Read(buf)
		if err != nil && n == 0 {
			return nil, fmt.Errorf("--password-fd: could not read: %w", err)
		}
		return trimNewline(buf[:n]), nil
	}
	if env, ok := os.LookupEnv("ARCHON_KEY_PASSWORD"); ok {
		return []byte(env), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("no password: stdin is not a terminal — set ARCHON_KEY_PASSWORD or pass --password-fd <n>")
	}
	fmt.Fprint(os.Stderr, "password: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read the password: %w", err)
	}
	if confirm {
		fmt.Fprint(os.Stderr, "password (again): ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("could not read the password: %w", err)
		}
		if string(first) != string(second) {
			return nil, fmt.Errorf("the two passwords differ")
		}
		keystore.Zeroise(second)
	}
	return first, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// sealAndWrite is the one place a key is written, shared by `key add` and
// `keygen --store` so the two can never drift apart. The salt and nonce are drawn here,
// in the command: the format takes them as arguments and never sources randomness, which
// is what makes it pinnable by vectors/keystore.json.
func sealAndWrite(path string, seed, password []byte) (string, error) {
	salt := make([]byte, keystore.SaltSize)
	nonce := make([]byte, keystore.NonceSize)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("could not read OS randomness: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("could not read OS randomness: %w", err)
	}
	blob, err := keystore.Seal(seed, password, salt, nonce, keystore.DefaultParams())
	if err != nil {
		return "", err
	}
	if err := keystore.WriteFile(path, blob); err != nil {
		return "", err
	}
	return keytext.EncodeKey(crypto.PublicKeyFromSeed(seed)), nil
}

// takeStoreFlag scans for `--store <name>` and removes it, the same shape as takeInFlag.
func takeStoreFlag(args []string) (rest []string, name string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--store" {
			if i+1 >= len(args) || args[i+1] == "" {
				return nil, "", fmt.Errorf("flag %q needs a value", "--store")
			}
			name = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	return rest, name, nil
}

// storeGenerated is `keygen --store <name>`: the same seal path as `key add`, reached from
// the command that already owns the CSPRNG.
func storeGenerated(name string, seed []byte, pwFD int) error {
	if err := keystore.ValidateName(name); err != nil {
		return err
	}
	path, err := keystore.Path(name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("a key named %q already exists; remove it first (archon key rm %s)", name, name)
	}
	password, err := readPassword(pwFD, true)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(password)
	principal, err := sealAndWrite(path, seed, password)
	if err != nil {
		return err
	}
	fmt.Printf("generated and stored %s (%s).\n", name, principal)
	return nil
}

// refuseLoosePasswordFile refuses a password file that anyone but its owner can read
// (ADR 0007 §A). Only a REGULAR file is checked: a pipe, a terminal or a process
// substitution has no meaningful mode, and `--password-fd 0` fed by a heredoc is a pipe,
// so checking those would refuse the ordinary non-interactive case for nothing.
//
// Windows has no mode bits and reports a synthetic 0666, so there is nothing to check and
// nothing is claimed — the same honesty the store keeps about 0600 elsewhere.
func refuseLoosePasswordFile(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		// Undecidable, so this refuses nothing rather than guessing. The read below will
		// produce the real error if the descriptor is unusable.
		return nil
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("--password-fd: the password file is readable by others (mode %04o); chmod 600 it", perm)
	}
	return nil
}
