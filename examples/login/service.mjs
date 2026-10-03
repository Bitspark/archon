// The service: archon's login handler mounted on node:http, with the one decision archon
// leaves to you — whether to let this person in — supplied as `admit`.
//
//   node service.mjs <ed25519:key text> <team>...    serve on 127.0.0.1:8787 until stopped,
//                                                     with that one person in those teams

import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { encodeKey } from "@bitspark/archon";
import { Handler } from "@bitspark/archon-server";

/**
 * Starts the service. `members` is the toy law: which principal (as key text) belongs to which
 * teams. In a real service this is your account store, or a grant layer such as thesmos —
 * archon never sees it, and only `admit` below reads it.
 */
export async function startService({ members, host = "127.0.0.1", port = 0, log = () => {} }) {
  let handler;
  let origin;
  const server = createServer((incoming, outgoing) => {
    bridge(handler, origin, incoming, outgoing).catch((e) => {
      outgoing.writeHead(500);
      outgoing.end(String(e));
    });
  });
  await new Promise((resolve) => server.listen(port, host, resolve));
  origin = `http://${host}:${server.address().port}`;

  // The audience is the service's own configuration and is never read from a request. It is
  // what every proof is bound to: a proof made for one audience verifies at no other.
  const audience = `${origin}/api`;
  handler = new Handler({ audience, mount: "/api/login", admit: admitBy(members, log), intervalSeconds: 1 });

  return { audience, close: () => new Promise((resolve) => server.close(resolve)) };
}

/**
 * The `AdmitAuthority` hook. The handler calls it only after the person's possession proof
 * has verified, with three things it interprets none of: the browser key, the principal, and
 * the authority payload. Returning admits; THROWING refuses the login with
 * `403 invalid_grant`, and nothing is stored for the client to collect.
 *
 * The authority payload is the exact bytes of the JSON value the person's command sent.
 * `archon login --authority-file <file>` sends the file's bytes as a lowercase-hex JSON
 * string, so what arrives here is `"<hex>"`, quotes included — decoded by `authorityText`.
 */
function admitBy(members, log) {
  return (browser, principal, authority) => {
    const who = encodeKey(principal);
    const team = authorityText(authority);
    if (!(members.get(who) ?? []).includes(team)) {
      log(`service: refused ${who} for team ${JSON.stringify(team)} (browser ${encodeKey(browser)})`);
      throw new Error("not a member");
    }
    log(`service: admitted ${who} for team ${JSON.stringify(team)} (browser ${encodeKey(browser)})`);
  };
}

/** The authority as the text of the file the person named: JSON string → hex → UTF-8. */
export function authorityText(bytes) {
  const value = JSON.parse(new TextDecoder().decode(bytes));
  if (typeof value !== "string" || !/^(?:[0-9a-f]{2})*$/.test(value)) {
    throw new Error("the authority is not the hex string archon login sends");
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(value, "hex"));
}

/** node:http → the Web platform's Request, which is all the handler takes, and back. */
async function bridge(handler, origin, incoming, outgoing) {
  const chunks = [];
  for await (const chunk of incoming) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue;
    for (const one of Array.isArray(value) ? value : [value]) headers.append(name, one);
  }
  const init = { method: incoming.method ?? "GET", headers };
  if (body.byteLength > 0) init.body = body;
  const response = await handler.handle(new Request(new URL(incoming.url ?? "/", origin), init));
  const out = {};
  response.headers.forEach((v, n) => { out[n] = v; });
  outgoing.writeHead(response.status, out);
  outgoing.end(Buffer.from(await response.arrayBuffer()));
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [principal, ...teams] = process.argv.slice(2);
  if (principal === undefined || teams.length === 0) {
    console.error("usage: node service.mjs <ed25519:key text> <team>...");
    process.exit(2);
  }
  const { audience } = await startService({ members: new Map([[principal, teams]]), port: 8787, log: console.log });
  console.log(`serving ${audience} — Ctrl-C to stop`);
}
