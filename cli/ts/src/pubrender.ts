// Public-key rendering in the shared CLI formats — used by `key pub` and `keygen
// --pub-out`, so every entry point that emits a public key agrees byte-for-byte across
// the three lanes (pinned by cli/smoke.mjs):
//   - spki: the keycodec SPKI PEM, VERBATIM (it carries its own single trailing newline)
//   - text: the canonical key text `ed25519:<hex>` + "\n"
//   - hex:  the raw 32-byte pubkey as lowercase hex + "\n"
import { encodeKey, pubkeyToSpkiPem, toHex } from "@bitspark/archon";

export type PubFormat = "spki" | "text" | "hex";

/** Parse a `--format` value; the message is byte-identical across the three lanes. */
export function parsePubFormat(s: string): PubFormat {
  switch (s) {
    case "spki":
    case "text":
    case "hex":
      return s;
    default:
      throw new Error(`unknown --format ${JSON.stringify(s)} (want spki|text|hex)`);
  }
}

/** Render a 32-byte public key; the returned string is the EXACT bytes to write. */
export function renderPub(pub: Uint8Array, fmt: PubFormat): string {
  switch (fmt) {
    case "spki":
      return pubkeyToSpkiPem(pub);
    case "text":
      return `${encodeKey(pub)}\n`;
    case "hex":
      return `${toHex(pub)}\n`;
  }
}
