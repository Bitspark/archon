package enroll

// The service's half of `archon enroll`'s formats (docs/enroll.md §2–§3, §6; ADR 0013): build
// an intent in format 1 with a fresh blind, and write the challenge token a person carries to
// the command. Verification and completion never read the intent; only these helpers and the
// command do.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	sdk "github.com/Bitspark/archon/sdk/go/enroll"
)

// blindSize is the blind Intent draws: the format's floor, 128 bits.
const blindSize = sdk.MinBlindSize

// Intent builds an intent in format 1 (docs/enroll.md §2) with a fresh blind from the
// Enroller's entropy. accountID is the service's identifier for the account; accountName is the
// account's unique name, such as its sign-in handle, never a display name its holder chooses
// freely. Build both from the account the validated session or credential authorizes, never
// from a label the browser sent.
//
// Pass the bytes to Prepare as Begin.Intent with Begin.Purpose set to the same purpose, and
// persist them beside the record: ChallengeToken needs them again.
func (e *Enroller) Intent(accountID, accountName, purpose string, restrictions []string) ([]byte, error) {
	blind := make([]byte, blindSize)
	if err := e.entropy(blind); err != nil {
		return nil, fmt.Errorf("enroll: entropy: %w", err)
	}
	return sdk.EncodeIntent(&sdk.Intent{
		Blind: blind, AccountID: accountID, AccountName: accountName, Purpose: purpose, Restrictions: restrictions,
	})
}

// ChallengeToken writes the challenge token for r (docs/enroll.md §3): the configured audience,
// the record's transaction, nonce and new key, intent, and the record's expiry rounded down to
// the second. intent is the bytes passed to Prepare for r.
//
// It refuses intent bytes whose SHA-256 is not r's intent digest, an intent not in format 1,
// and an intent whose purpose is not r's: `archon enroll` binds the intent's purpose and the
// digest of the bytes it shows, so a proof over any of those would never verify.
func (e *Enroller) ChallengeToken(r Record, intent []byte) (string, error) {
	digest := sha256.Sum256(intent)
	if !bytes.Equal(digest[:], r.IntentDigest) {
		return "", errors.New("enroll: these intent bytes are not the record's: their SHA-256 differs from its intent digest")
	}
	i, err := sdk.DecodeIntent(intent)
	if err != nil {
		return "", err
	}
	if i.Purpose != r.Purpose {
		return "", fmt.Errorf("enroll: the intent's purpose %q is not the record's %q; pass Prepare the intent's purpose", i.Purpose, r.Purpose)
	}
	return sdk.EncodeChallenge(&sdk.Challenge{
		Audience: e.audience, Transaction: r.Transaction, Nonce: r.Nonce, NewKey: r.NewKey,
		Intent: intent, Deadline: r.Expires.Truncate(time.Second),
	})
}
