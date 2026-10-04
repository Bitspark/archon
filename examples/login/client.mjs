// The key-less client: what a web page does to be let in. It makes its own key — the browser
// key, held only in memory — and never sees the person's. It begins a login, hands the person
// a URL to run `archon login` on, and collects the answer by proving it holds the browser key.
//
// Everything here is plain fetch plus two sdk calls, so it runs unchanged in a browser.

import { decodeKey, encodeKey, getPublicKey } from "@bitspark/archon";
import { proveCollect, verifyLogin } from "@bitspark/archon-sdk";

// docs/login.md §4: the collect proof travels in this header.
const COLLECT_HEADER = "archon-collect";

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (text) => Uint8Array.from(text.match(/../g) ?? [], (h) => Number.parseInt(h, 16));
const sleep = (seconds) => new Promise((resolve) => setTimeout(resolve, seconds * 1000));

/**
 * Begins a login at `audience` for `scope` and `validFor` seconds. Returns the URL the person
 * runs `archon login` on, and two ways to collect: `poll` asks once, `collect` waits.
 */
export async function beginLogin(audience, { scope, validFor }) {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const browser = getPublicKey(seed);

  const begun = await fetch(`${audience}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ browser: encodeKey(browser), scope, valid_for: validFor }),
  });
  if (begun.status !== 201) throw new Error(`begin: ${begun.status} ${await begun.text()}`);
  const { id, nonce, interval, expires_in: expiresIn } = await begun.json();

  // What the person's key signs, and what the collect proof and the check below are made over.
  const request = { id: unhex(id), nonce: unhex(nonce), browser, scope, validFor };

  /** One collect. 200 hands over the answer exactly once; 202 means not answered yet. */
  async function poll() {
    const res = await fetch(`${audience}/login/${id}/answer`, {
      headers: { [COLLECT_HEADER]: hex(proveCollect(seed, audience, request)) },
    });
    const body = await res.json();
    if (res.status !== 200) return { status: res.status, error: body.error };
    // The service verified the person's proof before storing it. A client that wants the
    // person's own word, not the service's, checks it again: the proof binds the principal
    // to this audience, this browser key, this scope and this validity.
    const verified = verifyLogin(decodeKey(body.principal), audience, request, unhex(body.possession));
    return { status: 200, principal: body.principal, verified, authority: body.authority };
  }

  /** Polls at the service's interval until answered, refused or expired. */
  async function collect() {
    const deadline = Date.now() + expiresIn * 1000;
    for (;;) {
      const got = await poll();
      if (got.status !== 202 && got.status !== 429) return got;
      if (Date.now() >= deadline) return got;
      await sleep(interval);
    }
  }

  return { url: `${audience}/login/${id}`, browser: encodeKey(browser), poll, collect };
}
