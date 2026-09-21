// A complete mount of the login handler on node:http, with no dependencies beyond this
// package. It is here to be the shortest true answer to "how do I run this", and to be
// COMPILED BY CI so it cannot quietly rot into an example that no longer builds.
//
//   npm run build && node dist/examples/serve.js https://dawn.example/api 127.0.0.1:8080
//
// Deno, Bun and Workers need none of this — they serve a fetch handler directly, which is why
// `Handler.handle` is fetch-style in the first place. Node is the runtime that still needs a
// bridge, so the bridge is what this example is.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { Handler } from "../src/index.js";

/** Where the four routes live under. Everything before this is the service's own business. */
const MOUNT = "/api/login";

// THE AUDIENCE IS THE SERVICE'S PUBLIC IDENTITY, NOT ITS BIND ADDRESS. A service behind a
// proxy listens on 127.0.0.1 and is still `https://dawn.example/api` to every CLI that signs
// for it — the audience must be the URL people actually type, because that is what the CLI
// derives and binds.
const audience = process.argv[2] ?? "https://dawn.example/api";
const bind = process.argv[3] ?? "127.0.0.1:8080";

// No admit: this example's law is "the proof suffices", which is the right default for a
// service that only needs to know a key holder was here and approved a scope.
const handler = ((): Handler => {
  try {
    return new Handler({ audience, mount: MOUNT });
  } catch (error) {
    // A misconfigured audience is a startup error naming the fix, not a service that runs and
    // refuses every proof for reasons nobody can see.
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
})();

/** node:http request → the Web platform's `Request`, which is what the handler takes. */
async function toFetchRequest(incoming: IncomingMessage, origin: string): Promise<Request> {
  const chunks: Buffer[] = [];
  for await (const chunk of incoming) chunks.push(chunk as Buffer);
  const body = Buffer.concat(chunks);

  // Header names are lowercased by node already; `append` keeps repeats rather than losing
  // them, which is what `Headers` is for.
  const headers = new Headers();
  for (const [name, value] of Object.entries(incoming.headers)) {
    if (value === undefined) continue;
    for (const one of Array.isArray(value) ? value : [value]) headers.append(name, one);
  }

  const init: RequestInit = { method: incoming.method ?? "GET", headers };
  // A GET with a body is not constructible, and none of the four routes sends one.
  if (body.byteLength > 0) init.body = body;
  return new Request(new URL(incoming.url ?? "/", origin), init);
}

/** …and back again. */
async function writeFetchResponse(response: Response, outgoing: ServerResponse): Promise<void> {
  const body = Buffer.from(await response.arrayBuffer());
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    headers[name] = value;
  });
  outgoing.writeHead(response.status, headers);
  outgoing.end(body);
}

const [host = "127.0.0.1", port = "8080"] = bind.split(":");

createServer((incoming, outgoing) => {
  void (async () => {
    try {
      const request = await toFetchRequest(incoming, `http://${host}:${port}`);
      await writeFetchResponse(await handler.handle(request), outgoing);
    } catch (error) {
      console.error("connection:", error);
      outgoing.writeHead(400, { "content-type": "application/json" });
      // The same body shape §4 uses, so a client parses one thing whether the refusal came
      // from the handler or from the bridge in front of it.
      outgoing.end(JSON.stringify({ error: "invalid_request" }));
    }
  })();
}).listen(Number(port), host, () => {
  console.error(`archon login: ${audience} mounted at ${MOUNT} on http://${host}:${port}`);
});
