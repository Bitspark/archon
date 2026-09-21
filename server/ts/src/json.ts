// Hex, strict body parsing and the door checks. Small on purpose: the wire format is §4's
// and is spelled where the routes are, not abstracted behind builders that would hide it.

/** Caps every request body. See the note on `MAX_BODY_BYTES` in the Rust lane: the authority
 *  payload is the only field with no natural size, and a law needing more than this should say
 *  so rather than have the handler guess high. */
export const MAX_BODY_BYTES = 64 * 1024;

/** The floor on an offer's code (§4.1): at least 16 bytes of the PROVER's entropy, spelled as
 *  lowercase hex — so 32 characters. The code is the address of an open offer and is
 *  confidential until the offer is taken; a short one is guessable. */
export const MIN_CODE_HEX = 32;

/**
 * Throws on a code that is not what §4.1 says a code is: lowercase hex of even length, at
 * least MIN_CODE_HEX characters. The offer route answers 400 to a refusal; begin's `offer`
 * member and the read route answer 404, because a registered code is always well-formed and
 * so a malformed one is unknown by construction — a stranger learns nothing from the
 * difference (the same rule as an unknown versus an expired id).
 */
export function checkCode(code: string): void {
  if (code.length < MIN_CODE_HEX || code.length % 2 !== 0) {
    throw new Error(`a code is lowercase hex of even length, at least ${MIN_CODE_HEX} characters`);
  }
  if (!/^[0-9a-f]*$/.test(code)) throw new Error("a code is lowercase hex");
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Throws on anything that is not an even-length run of hex digits. Total by refusal, never
 *  by silently dropping a bad pair. */
export function fromHex(text: string): Uint8Array {
  if (text.length % 2 !== 0) throw new Error(`hex has odd length (${text.length})`);
  if (!/^[0-9a-fA-F]*$/.test(text)) throw new Error("hex carries a non-hex character");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Parses a request body strictly: capped, an object, and with UNKNOWN FIELDS REFUSED.
 *
 * The refusal is deliberate and is the same rule the other two lanes apply. A caller sending
 * a field this package does not know is speaking a different version of the protocol, and
 * half-reading their message is how two peers come to disagree about what was agreed.
 * Refusing says so at the door — and in particular refuses an `audience` field, which is
 * exactly the value review Finding 1 forbids trusting.
 */
export function parseBody(raw: ArrayBuffer, allowed: readonly string[]): ParsedBody {
  if (raw.byteLength > MAX_BODY_BYTES) {
    throw new Error(`body is ${raw.byteLength} bytes, over the ${MAX_BODY_BYTES} cap`);
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  const value: unknown = JSON.parse(text);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("body is not a JSON object");
  }
  const body = value as Record<string, unknown>;
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) throw new Error(`body carries the unknown field ${JSON.stringify(key)}`);
  }
  // Scanned once, HERE, so every route refuses a repeated member — not only the one that
  // happens to want a span. go refuses duplicates in its shared decoder and serde refuses
  // them for a struct; a lane that refused them on `answer` alone would be the same
  // three-lanes-three-answers defect in miniature.
  const members = scanTopLevel(text);
  return { text, body, members };
}

/** A parsed body, the exact text it was parsed from, and each top-level member's source span. */
export interface ParsedBody {
  text: string;
  body: Record<string, unknown>;
  /** Member name to the exact source text of its value. */
  members: Map<string, string>;
}

/**
 * An unpaired surrogate — a string JavaScript will hold happily and UTF-8 cannot represent.
 *
 * Go and TypeScript both need this check; Rust does not, because a `String` cannot hold one.
 * That asymmetry is why it is spelled out here rather than assumed: the scheme refuses these
 * at `loginBinding`, but that happens when a proof is MADE, which is after the person has
 * already read the statement.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Refuses what the CLI could not display faithfully: an empty entry, a control character
 * (§3.1), or text that is not valid UTF-8.
 *
 * Checked HERE as well as in the scheme, and that is not redundancy for its own sake:
 * checking at the door means a request that could lie on screen never exists to be shown.
 */
export function checkScopeEntry(entry: string): void {
  if (entry.length === 0) throw new Error("a scope entry is empty");
  if (LONE_SURROGATE.test(entry)) throw new Error("a scope entry is not valid UTF-8");
  for (const ch of entry) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      throw new Error(`a scope entry carries a control character (U+${code.toString(16).padStart(4, "0")})`);
    }
  }
}

/**
 * Formats a Unix timestamp as RFC 3339 UTC, which is what §4's `expires` field carries.
 *
 * The milliseconds are dropped so all three lanes emit the SAME spelling: Go and Rust format
 * whole seconds, and a `.000Z` here would be a difference visible to any client that compared
 * two services.
 */
export function rfc3339(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Strips `mount` from the front of a request path, or returns undefined if the path is not
 * under it.
 *
 * EXPORTED SO IT CAN BE TESTED DIRECTLY, and that is not an accident of style. Through the
 * handler this rule is nearly invisible: a path that should have been refused here goes on to
 * miss the id lookup and produce the same 404 anyway, so a test driving it through `handle`
 * passes whether the rule is present or not. The Rust lane has the same rule in its adapter
 * and tests it the same way, on the function itself.
 *
 * The remainder must be empty or begin with `/`, so a handler mounted at `/api/login` does not
 * also claim `/api/loginX` — a path that belongs to whatever else the service routes.
 *
 * Nothing is percent-decoded: ids are hex and never need it, and decoding is how a `%2f` turns
 * into a path separator that routing has already finished looking at.
 */
export function stripMount(pathname: string, mount: string): string | undefined {
  const prefix = mount.replace(/\/+$/, "");
  if (prefix.length === 0) return pathname;
  if (!pathname.startsWith(prefix)) return undefined;
  const rest = pathname.slice(prefix.length);
  if (rest.length > 0 && !rest.startsWith("/")) return undefined;
  return rest;
}

/**
 * The exact source text of the top-level `authority` member of `text`, or undefined if the
 * body has no such member.
 *
 * THE AUTHORITY IS OPAQUE BYTES (ADR 0007 §B), and `JSON.parse` followed by `JSON.stringify`
 * is NOT a round trip. `9007199254740993` comes back `9007199254740992` — it does not fit a
 * double. `1.10` comes back `1.1`. A `\\u00e9` escape comes back as the character. Key order is
 * whatever the parser kept. A law that signs its payload, or carries a 64-bit id, would then
 * be handed something the CLI never sent, and the browser something the law never saw — and
 * the three server lanes would each produce a different payload from one answer.
 *
 * `JSON.parse`'s reviver cannot do this: its `context.source` is populated for primitives
 * only, so an object- or array-valued authority would have no source to read. Hence the
 * scanner. It runs on text that has ALREADY parsed, so it is measuring, not validating.
 *
 * A repeated top-level key is refused rather than resolved. `JSON.parse` keeps the last one,
 * so a body with two `authority` members would have two candidate spans and no reason to
 * prefer either; refusing is the only answer that cannot be argued with. (The Rust lane
 * refuses duplicates already, via serde; Go accepts them and keeps the last.)
 */
export function authoritySpan(text: string): string | undefined {
  return scanTopLevel(text).get("authority");
}

/**
 * Every top-level member of `text`, name to the exact source text of its value.
 *
 * A repeated name is REFUSED rather than resolved. `JSON.parse` keeps the last one, so a body
 * with two `authority` members would have two candidate spans and no reason to prefer either;
 * refusing is the only answer that cannot be argued with. That reasoning is about `authority`,
 * but the refusal is applied to every member, because "which of the two did you mean" has no
 * good answer for any of them.
 */
export function scanTopLevel(text: string): Map<string, string> {
  const members = new Map<string, string>();
  const cur = new Cursor(text);
  cur.ws();
  cur.expect("{");
  cur.ws();
  if (cur.peek() === "}") {
    cur.take();
  } else {
    for (;;) {
      cur.ws();
      const key = cur.str();
      if (members.has(key)) throw new Error(`the body repeats the top-level key ${JSON.stringify(key)}`);
      cur.ws();
      cur.expect(":");
      cur.ws();
      const start = cur.i;
      cur.skip();
      members.set(key, text.slice(start, cur.i));
      cur.ws();
      const next = cur.take();
      if (next === ",") continue;
      if (next === "}") break;
      throw new Error("expected , or } after a member");
    }
  }
  cur.ws();
  if (cur.peek() !== undefined) throw new Error("trailing content after the body");
  return members;
}

/** Just enough JSON to walk a top-level object and measure one member's value. */
class Cursor {
  i = 0;

  constructor(private readonly text: string) {}

  ws(): void {
    while (this.i < this.text.length && " \t\n\r".includes(this.text[this.i] as string)) this.i += 1;
  }

  peek(): string | undefined {
    return this.text[this.i];
  }

  take(): string {
    const c = this.text[this.i];
    if (c === undefined) throw new Error("unexpected end of body");
    this.i += 1;
    return c;
  }

  expect(c: string): void {
    if (this.take() !== c) throw new Error(`expected ${c}`);
  }

  /** Consumes a string literal and returns its value. Used for member names only — the
   *  authority is never decoded. */
  str(): string {
    const start = this.i;
    this.expect('"');
    for (;;) {
      const c = this.take();
      if (c === '"') return JSON.parse(this.text.slice(start, this.i)) as string;
      // Skip whatever the backslash escapes. For \\uXXXX the four hex digits that follow are
      // ordinary characters — none of them can be a quote or a backslash — so no special case.
      if (c === "\\") this.i += 1;
    }
  }

  /** Advances past one value of any type WITHOUT interpreting it. */
  skip(): void {
    this.ws();
    const c = this.peek();
    if (c === '"') {
      this.str();
      return;
    }
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]";
      this.take();
      this.ws();
      if (this.peek() === close) {
        this.take();
        return;
      }
      for (;;) {
        this.ws();
        if (close === "}") {
          this.str();
          this.ws();
          this.expect(":");
        }
        this.skip();
        this.ws();
        const next = this.take();
        if (next === ",") continue;
        if (next === close) return;
        throw new Error(`expected , or ${close}`);
      }
    }
    // A number, true, false or null: up to the next structural character.
    const start = this.i;
    while (this.i < this.text.length && !",}] \t\n\r".includes(this.text[this.i] as string)) {
      this.i += 1;
    }
    if (this.i === start) throw new Error("expected a value");
  }
}
