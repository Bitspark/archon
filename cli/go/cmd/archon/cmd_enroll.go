package main

// `archon enroll` (docs/enroll.md §4, ADR 0013): make the enrollment proof for a key in the
// store, but only after showing the person which account the key joins, decoded from the very
// intent bytes whose digest the proof binds. The challenge arrives as a token the person
// carries from the signed-in page; the proof leaves as a token they carry back. The command
// contacts no server, so its success means a proof was produced, never that the key is
// enrolled.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Bitspark/archon/cli/go/internal/keystore"
	"github.com/Bitspark/archon/core/go/crypto"
	"github.com/Bitspark/archon/core/go/keytext"
	"github.com/Bitspark/archon/sdk/go/enroll"
)

const enrollUsage = "usage: archon enroll [--challenge-file <file>] [--audience <base>] [--key <name>] [--password-fd <n>]\n" +
	"  makes the enrollment proof for a key in the store, after showing which account it joins\n" +
	"  (docs/enroll.md). The challenge token is read from --challenge-file, or one line of stdin;\n" +
	"  the audience is --audience or ARCHON_AUDIENCE; the key is --key or the default key. The\n" +
	"  question is asked on the terminal, always, and the proof token is printed on stdout."

// enrollPurpose is the one purpose version 1 renders (docs/enroll.md §2).
const enrollPurpose = "add-key"

// maxChallengeInput bounds what is read before decoding: a token and its surrounding whitespace.
const maxChallengeInput = 1 << 20

// enrollTerminal is where the statement is shown and the question asked. A variable so a test
// can stand in for the controlling terminal.
var enrollTerminal = openTerminal

func runEnroll(args []string) error {
	if wantsHelp(args) {
		fmt.Println(enrollUsage)
		return nil
	}
	rest, pwFD, err := takePasswordFD(args)
	if err != nil {
		return err
	}
	var challengeFile, audienceFlag, keyName string
	for i := 0; i < len(rest); i++ {
		flag := rest[i]
		if i+1 >= len(rest) || rest[i+1] == "" {
			return fmt.Errorf("flag %q needs a value\n%s", flag, enrollUsage)
		}
		value := rest[i+1]
		i++
		switch flag {
		case "--challenge-file":
			challengeFile = value
		case "--audience":
			audienceFlag = value
		case "--key":
			keyName = value
		default:
			return fmt.Errorf("unknown flag %q\n%s", flag, enrollUsage)
		}
	}
	if challengeFile == "" && pwFD == 0 {
		return errors.New("enroll: --password-fd 0 and a challenge token on stdin would read the same stream; pass the token with --challenge-file")
	}

	// 1. The entry: one read, whose header the seal authenticates at unlock (ADR 0012 §4).
	if keyName == "" {
		if keyName, err = readDefaultKeyName(); err != nil {
			return err
		}
		if keyName == "" {
			return errors.New("enroll: no default key is set; pass --key <name>, or choose one with: archon key default <name>")
		}
	}
	file, h, err := usableKey(keyName)
	if err != nil {
		return err
	}
	if h.Policy == nil || !h.Policy.Permits(enroll.Domain) { // fails closed on its own
		return errors.New(policyRefusal(keyName, h.Policy))
	}

	// 2. The audience the person selected, and a terminal to ask on.
	audience, err := selectedAudience("enroll", "the audience is your configuration, never a token's word (docs/enroll.md §4)", audienceFlag)
	if err != nil {
		return err
	}
	termIn, termOut, err := enrollTerminal()
	if err != nil {
		return errors.New("enroll: there is no terminal to ask on; archon enroll asks every time, and a password from ARCHON_KEY_PASSWORD or --password-fd does not answer it")
	}
	defer func() {
		if termOut != termIn {
			termOut.Close()
		}
		termIn.Close()
	}()

	// 3. The token, read and decoded once. From here on only these values are used.
	text, fromTerminal, err := readChallenge(challengeFile)
	if err != nil {
		return err
	}
	ch, err := enroll.DecodeChallenge(text)
	if err != nil {
		if fromTerminal {
			return fmt.Errorf("%w (a terminal cuts a long pasted line; save the token to a file and pass --challenge-file)", err)
		}
		return err
	}

	// 4.–7. Everything decidable before the person is asked.
	if err := checkChallenge(ch, audience, h.PublicKey, clockNow()); err != nil {
		return err
	}
	req, intent, err := ch.Request()
	if err != nil {
		return err
	}
	if intent.Purpose != enrollPurpose {
		return fmt.Errorf("enroll: the intent's purpose is %s; this archon renders only %q, so it signs nothing else",
			jsonString(intent.Purpose), enrollPurpose)
	}

	// 8. Show, and ask on the terminal.
	fmt.Fprint(termOut, renderEnrollStatement(audience, intent, h.PublicKey, ch.Deadline, "the store key "+keyName))
	fmt.Fprint(termOut, enrollPrompt(intent))
	if !answeredYes(termIn) {
		fmt.Fprintln(termOut, "refused. nothing was signed.")
		return nil
	}

	// 9. Only now is the key unlocked: the same snapshot, its header now authenticated.
	password, err := readPassword(pwFD, false, "")
	if err != nil {
		return err
	}
	seed, err := keystore.Open(file, password)
	keystore.Zeroise(password)
	if err != nil {
		return err
	}
	defer keystore.Zeroise(seed)
	if !h.Policy.Permits(enroll.Domain) {
		return errors.New(policyRefusal(keyName, h.Policy))
	}
	if !bytes.Equal(crypto.PublicKeyFromSeed(seed), h.PublicKey) || !bytes.Equal(h.PublicKey, ch.NewKey) {
		return fmt.Errorf("enroll: key %s did not open to the key that was shown; nothing was signed", keyName)
	}

	// 10. The proof, over what was shown, checked before it is printed.
	proof, err := enroll.Prove(seed, audience, req)
	if err != nil {
		return err
	}
	if !enroll.Verify(audience, req, proof) {
		return errors.New("enroll: the proof did not verify; nothing was printed")
	}
	token, err := enroll.EncodeProof(&enroll.Proof{Transaction: req.Transaction, NewKey: req.NewKey, Proof: proof})
	if err != nil {
		return err
	}

	// 11. The proof token on stdout, alone; the person is told what it is not.
	fmt.Println(token)
	fmt.Fprintln(termOut, "proof produced. paste it into the service's page: the key is enrolled only when the page completes.")
	return nil
}

// checkChallenge is steps 4 to 6 of docs/enroll.md §4: the token's audience is the selected one,
// its key is the entry's, and its deadline is still ahead. The token's audience is display-safe
// already (the codec refuses otherwise), and is JSON-quoted to show where it ends.
func checkChallenge(ch *enroll.Challenge, audience string, key []byte, now time.Time) error {
	if ch.Audience != audience {
		return fmt.Errorf("enroll: the token is for %s, not the audience you selected, %s; nothing was shown or signed",
			jsonString(ch.Audience), jsonString(audience))
	}
	if !bytes.Equal(ch.NewKey, key) {
		return fmt.Errorf("enroll: the token enrolls %s, not this key, %s; nothing was shown or signed",
			keytext.EncodeKey(ch.NewKey), keytext.EncodeKey(key))
	}
	if now.Unix() >= ch.Deadline.Unix() {
		return fmt.Errorf("enroll: the request's deadline, about %s, has passed; begin again on the service's page",
			ch.Deadline.UTC().Format("2006-01-02T15:04:05Z"))
	}
	return nil
}

// renderEnrollStatement is the statement of docs/enroll.md §4, byte-identical in every lane
// (cli/testdata/enroll-statement.json). Every text in it is display-safe: the intent's fields
// by the codec, the audience by its canonical form, the key source by the store's name rules.
func renderEnrollStatement(audience string, intent *enroll.Intent, key []byte, deadline time.Time, keySource string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s asks you to add a key to an account:\n", audience)
	fmt.Fprintf(&b, "  account:      %s\n", intent.AccountName)
	fmt.Fprintf(&b, "  account id:   %s\n", intent.AccountID)
	fmt.Fprintf(&b, "  key:          %s\n", keytext.EncodeKey(key))
	if len(intent.Restrictions) == 0 {
		b.WriteString("  restrictions: none\n")
	} else {
		b.WriteString("  restrictions:\n")
		for _, r := range intent.Restrictions {
			fmt.Fprintf(&b, "    %s\n", r)
		}
	}
	b.WriteString("the service may give this key the account's authority.\n")
	fmt.Fprintf(&b, "the request's deadline is about %s, the service's word; it is not the key's expiry.\n",
		deadline.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "signing with %s\n", keySource)
	return b.String()
}

// enrollPrompt is the question, naming the account the person is agreeing to. Plain quotes, not
// a language's quoting: the name is display-safe already, and the three lanes must agree.
func enrollPrompt(intent *enroll.Intent) string {
	return "add this key to the account \"" + intent.AccountName + "\"? [y/N] "
}

// answeredYes reads one line from the terminal: y or yes, and nothing else, is consent.
func answeredYes(in io.Reader) bool {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// readChallenge reads the token: the whole file, or one line of stdin. It reports whether stdin
// was a terminal, whose line limit can cut a pasted token.
func readChallenge(path string) (text string, fromTerminal bool, err error) {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return "", false, fmt.Errorf("enroll: could not read %q: %w", path, err)
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, maxChallengeInput+1))
		if err != nil {
			return "", false, fmt.Errorf("enroll: could not read %q: %w", path, err)
		}
		if len(raw) > maxChallengeInput {
			return "", false, fmt.Errorf("enroll: %q is over %d bytes; a challenge token is at most %d", path, maxChallengeInput, enroll.MaxTokenSize)
		}
		return string(raw), false, nil
	}
	fromTerminal = term.IsTerminal(int(os.Stdin.Fd()))
	line, err := bufio.NewReaderSize(io.LimitReader(os.Stdin, maxChallengeInput), 64*1024).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fromTerminal, fmt.Errorf("enroll: could not read the token from stdin: %w", err)
	}
	return line, fromTerminal, nil
}

// bareContext is a context every shell receives as itself, unquoted: sh, cmd.exe and
// PowerShell alike. A leading '@' or '-' is left out, since PowerShell and flag parsers read
// those as something else (docs/enroll.md §4 step 1).
var bareContext = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:+=-]*$`)

// policyRefusal says why the entry may not enroll and how to change that. `key policy` replaces
// a list rather than adding to it, so the command it prints names every context the entry keeps,
// then archon-enroll/1; it prints the command only when every context needs no quoting in any
// shell, and otherwise lists the contexts JSON-quoted.
func policyRefusal(name string, p *keystore.Policy) string {
	head := fmt.Sprintf("enroll: key %s may not sign in %s: its policy is %s", name, enroll.Domain, p)
	if p == nil {
		return head
	}
	if len(p.Contexts) >= keystore.MaxContexts {
		return fmt.Sprintf("%s.\n  it already lists %d contexts, the most a policy holds: drop one with archon key policy, "+
			"or keep a separate key for enrollment", head, keystore.MaxContexts)
	}
	quoted := make([]string, 0, len(p.Contexts))
	bare := true
	for _, c := range p.Contexts {
		bare = bare && bareContext.MatchString(c)
		quoted = append(quoted, jsonString(c))
	}
	if !bare {
		return fmt.Sprintf("%s.\n  key policy replaces the list: run archon key policy %s with --allow for each of %s, and for %s",
			head, name, strings.Join(quoted, ", "), enroll.Domain)
	}
	command := "archon key policy " + name
	for _, c := range p.Contexts {
		command += " --allow " + c
	}
	command += " --allow " + enroll.Domain
	return fmt.Sprintf("%s.\n  to let it enroll, keeping what it has (key policy replaces the list):\n    %s", head, command)
}
