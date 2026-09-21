// deriveAudience — the invocation URL → { audience, id bytes }, docs/login.md §2.1.
//
// Part of the scheme, not of any CLI: three URL parsers normalise three ways (a WHATWG URL
// drops a default port and userinfo, net/url decodes the path, a hand-rolled split keeps
// userinfo as the host) and the audience is the first field of the binding, so one URL must
// yield one audience in every lane. This function accepts exactly the grammar of §2.1 and
// REFUSES everything else rather than normalising it — deliberately not the WHATWG `URL`
// class, which is a normaliser.
//
//   invocation = scheme "://" host [ ":" port ] *( "/" segment ) "/login/" id

/**
 * The audience the login proof binds and the request id's bytes, from the URL the person was
 * told to run. Scheme is http/https/ws/wss (case-insensitive; ws → http, wss → https); the
 * host is an ASCII reg-name or a bracketed IPv6 literal, lowercased; a port is 1..=65535
 * without a leading zero and is omitted from the audience when it is the folded scheme's
 * default (80, 443); segments are kept as written (case preserved, percent-escapes never
 * decoded); the id is lowercase hex of even length and is returned decoded. Throws on any
 * non-ASCII, whitespace or control character, userinfo, query, fragment, empty segment,
 * `.`/`..` segment, malformed escape, or a penultimate segment other than `login`.
 */
export function deriveAudience(url: string): { audience: string; id: Uint8Array } {
  for (let i = 0; i < url.length; i++) {
    const c = url.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f) {
      throw new Error(`login: URL character ${i} is U+${c.toString(16).toUpperCase().padStart(4, "0")} — only printable ASCII is accepted`);
    }
  }
  const sep = url.indexOf("://");
  if (sep < 0) throw new Error("login: URL has no scheme");
  const [scheme, defaultPort] = foldScheme(url.slice(0, sep));
  const rest = url.slice(sep + 3);
  const slash = rest.indexOf("/");
  if (slash < 0) throw new Error("login: URL has no path — expected <audience>/login/<id>");
  const [host, port] = parseAuthority(rest.slice(0, slash));
  const path = rest.slice(slash);
  if (path.includes("?") || path.includes("#")) {
    throw new Error("login: URL carries a query or fragment — expected <audience>/login/<id>");
  }
  const segments = path.slice(1).split("/");
  segments.forEach((seg, i) => checkSegment(seg, i));
  if (segments.length < 2) throw new Error("login: URL is not <audience>/login/<id>");
  const penultimate = segments[segments.length - 2]!;
  if (penultimate !== "login") {
    throw new Error(`login: expected <audience>/login/<id>, got ${JSON.stringify(penultimate)} as the penultimate segment`);
  }
  const id = decodeId(segments[segments.length - 1]!);
  let audience = `${scheme}://${host}`;
  if (port !== "" && port !== defaultPort) audience += `:${port}`;
  for (const seg of segments.slice(0, -2)) audience += `/${seg}`;
  return { audience, id };
}

function foldScheme(s: string): [string, string] {
  switch (s.toLowerCase()) {
    case "http":
    case "ws":
      return ["http", "80"];
    case "https":
    case "wss":
      return ["https", "443"];
    default:
      throw new Error(`login: unsupported URL scheme ${JSON.stringify(s)} — want http(s) or ws(s)`);
  }
}

function parseAuthority(auth: string): [string, string] {
  if (auth.includes("@")) throw new Error("login: URL carries userinfo — refused");
  if (auth === "") throw new Error("login: URL has no host");
  if (auth.startsWith("[")) {
    const end = auth.indexOf("]");
    if (end < 0) throw new Error("login: unterminated IPv6 literal");
    const lit = auth.slice(1, end).toLowerCase();
    if (lit.length < 2 || !lit.includes(":") || !/^[0-9a-f:.]+$/.test(lit)) {
      throw new Error("login: malformed IPv6 literal");
    }
    const tail = auth.slice(end + 1);
    if (tail === "") return [`[${lit}]`, ""];
    if (!tail.startsWith(":")) throw new Error("login: bytes after the IPv6 literal — refused");
    return [`[${lit}]`, checkPort(tail.slice(1))];
  }
  const colon = auth.indexOf(":");
  const name = colon < 0 ? auth : auth.slice(0, colon);
  const port = colon < 0 ? "" : checkPort(auth.slice(colon + 1));
  const host = name.toLowerCase();
  for (const label of host.split(".")) {
    if (label === "") throw new Error("login: host has an empty label — refused");
    if (!/^[a-z0-9-]+$/.test(label)) {
      throw new Error("login: host has a character outside [a-z0-9-.] — refused (IDNs must be given as punycode)");
    }
  }
  return [host, port];
}

function checkPort(p: string): string {
  if (!/^[0-9]+$/.test(p) || (p.length > 1 && p.startsWith("0"))) throw new Error(`login: port ${JSON.stringify(p)} — refused`);
  const n = Number(p);
  if (n < 1 || n > 65535) throw new Error(`login: port ${JSON.stringify(p)} is out of range`);
  return p;
}

const SEGMENT_CHAR = /^[A-Za-z0-9\-._~!$&'()*+,;=:@]$/;

function checkSegment(seg: string, i: number): void {
  if (seg === "") throw new Error(`login: path segment ${i}: empty segment (a trailing slash or \`//\`) — refused`);
  if (seg === "." || seg === "..") throw new Error(`login: path segment ${i}: dot segment — refused`);
  for (let j = 0; j < seg.length; j++) {
    const c = seg[j]!;
    if (c === "%") {
      if (j + 2 >= seg.length || !/^[0-9A-Fa-f]{2}$/.test(seg.slice(j + 1, j + 3))) {
        throw new Error(`login: path segment ${i}: malformed percent-escape — refused`);
      }
      j += 2;
    } else if (!SEGMENT_CHAR.test(c)) {
      throw new Error(`login: path segment ${i}: ${JSON.stringify(c)} is not allowed in a path segment — refused`);
    }
  }
}

function decodeId(s: string): Uint8Array {
  if (s.length < 2 || s.length % 2 !== 0 || !/^[0-9a-f]+$/.test(s)) {
    throw new Error(`login: id ${JSON.stringify(s)} is not lowercase hex of even length`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
