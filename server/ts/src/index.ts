// archon-server — the service side of the archon login protocol (docs/login.md §4).
//
// A service adopts proof-of-possession sign-in by constructing a `Handler` and calling it from
// whatever already serves its requests. The handler is fetch-style —
// `(Request) => Promise<Response>` — so it mounts in Node, Deno, Bun, a Worker, or any
// framework that speaks the Web platform's own types, and this package depends on none of
// them. It opens no socket, starts no timer, persists nothing, and interprets no authority:
// that is ADR 0007 §B, and it is what makes the tier adoptable by a service that has already
// chosen its stack.
export * from "./login.js";
export { fromHex, MAX_BODY_BYTES, rfc3339, scanTopLevel, stripMount, toHex } from "./json.js";
