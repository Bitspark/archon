package login

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DeriveAudience turns the URL a person is told to run — `<audience>/login/<id>` — into the
// audience the login proof binds and the request id's bytes (docs/login.md §2.1).
//
// It is part of the scheme, not of any CLI, because three URL parsers normalise three ways
// and the audience is the first field of the binding: a WHATWG URL drops a default port,
// net/url keeps it and decodes the path, a hand-rolled parser keeps userinfo. One URL must
// yield one audience in every lane, so this function accepts exactly the grammar in §2.1
// and REFUSES everything else rather than normalising it:
//
//	invocation = scheme "://" host [ ":" port ] *( "/" segment ) "/login/" id
//
// scheme is http/https/ws/wss (case-insensitive; ws → http, wss → https); host is an ASCII
// reg-name or a bracketed IPv6 literal, lowercased; a port is 1..=65535 without a leading
// zero and is omitted from the audience when it is the folded scheme's default (80, 443);
// segments are kept as written (case preserved, percent-escapes never decoded); the id is
// lowercase hex of even length and is returned decoded. Any non-ASCII, whitespace or
// control byte, userinfo, query, fragment, empty segment, `.`/`..` segment, malformed
// escape, or a penultimate segment other than `login` is an error.
func DeriveAudience(rawURL string) (audience string, id []byte, err error) {
	for i := 0; i < len(rawURL); i++ {
		if c := rawURL[i]; c <= 0x20 || c >= 0x7f {
			return "", nil, fmt.Errorf("login: URL byte %d is 0x%02x — only printable ASCII is accepted", i, c)
		}
	}
	sep := strings.Index(rawURL, "://")
	if sep < 0 {
		return "", nil, errors.New("login: URL has no scheme")
	}
	scheme, defaultPort, err := foldScheme(rawURL[:sep])
	if err != nil {
		return "", nil, err
	}
	rest := rawURL[sep+3:]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return "", nil, errors.New("login: URL has no path — expected <audience>/login/<id>")
	}
	host, port, err := parseAuthority(rest[:slash])
	if err != nil {
		return "", nil, err
	}
	path := rest[slash:]
	if strings.ContainsAny(path, "?#") {
		return "", nil, errors.New("login: URL carries a query or fragment — expected <audience>/login/<id>")
	}
	segments := strings.Split(path[1:], "/")
	for i, seg := range segments {
		if err := checkSegment(seg); err != nil {
			return "", nil, fmt.Errorf("login: path segment %d: %w", i, err)
		}
	}
	if len(segments) < 2 {
		return "", nil, errors.New("login: URL is not <audience>/login/<id>")
	}
	if segments[len(segments)-2] != "login" {
		return "", nil, fmt.Errorf("login: expected <audience>/login/<id>, got %q as the penultimate segment", segments[len(segments)-2])
	}
	id, err = decodeID(segments[len(segments)-1])
	if err != nil {
		return "", nil, err
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if port != "" && port != defaultPort {
		b.WriteByte(':')
		b.WriteString(port)
	}
	for _, seg := range segments[:len(segments)-2] {
		b.WriteByte('/')
		b.WriteString(seg)
	}
	return b.String(), id, nil
}

// foldScheme lowercases and folds the scheme; returns it with the default port it implies.
func foldScheme(s string) (scheme, defaultPort string, err error) {
	switch strings.ToLower(s) {
	case "http", "ws":
		return "http", "80", nil
	case "https", "wss":
		return "https", "443", nil
	}
	return "", "", fmt.Errorf("login: unsupported URL scheme %q — want http(s) or ws(s)", s)
}

// parseAuthority lowercases the host and validates the port; userinfo is refused.
func parseAuthority(auth string) (host, port string, err error) {
	if strings.IndexByte(auth, '@') >= 0 {
		return "", "", errors.New("login: URL carries userinfo — refused")
	}
	if auth == "" {
		return "", "", errors.New("login: URL has no host")
	}
	if auth[0] == '[' {
		end := strings.IndexByte(auth, ']')
		if end < 0 {
			return "", "", errors.New("login: unterminated IPv6 literal")
		}
		host = strings.ToLower(auth[:end+1])
		lit := host[1:end]
		if len(lit) < 2 || !strings.Contains(lit, ":") {
			return "", "", errors.New("login: malformed IPv6 literal")
		}
		for i := 0; i < len(lit); i++ {
			if c := lit[i]; !(isHexLower(c) || c == ':' || c == '.') {
				return "", "", fmt.Errorf("login: IPv6 literal has byte 0x%02x — refused", c)
			}
		}
		tail := auth[end+1:]
		if tail == "" {
			return host, "", nil
		}
		if tail[0] != ':' {
			return "", "", errors.New("login: bytes after the IPv6 literal — refused")
		}
		port, err = checkPort(tail[1:])
		return host, port, err
	}
	name := auth
	if colon := strings.IndexByte(auth, ':'); colon >= 0 {
		name = auth[:colon]
		if port, err = checkPort(auth[colon+1:]); err != nil {
			return "", "", err
		}
	}
	host = strings.ToLower(name)
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return "", "", errors.New("login: host has an empty label — refused")
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", "", fmt.Errorf("login: host has byte 0x%02x — refused (IDNs must be given as punycode)", c)
			}
		}
	}
	return host, port, nil
}

// checkPort accepts 1..=65535 written without a leading zero.
func checkPort(p string) (string, error) {
	if p == "" || (len(p) > 1 && p[0] == '0') {
		return "", fmt.Errorf("login: port %q — refused", p)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return "", fmt.Errorf("login: port %q is not a number", p)
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("login: port %q is out of range", p)
	}
	return p, nil
}

// checkSegment is RFC 3986 pchar with escapes kept as written; `.` and `..` are refused.
func checkSegment(seg string) error {
	if seg == "" {
		return errors.New("empty segment (a trailing slash or `//`) — refused")
	}
	if seg == "." || seg == ".." {
		return errors.New("dot segment — refused")
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
		case strings.IndexByte("-._~!$&'()*+,;=:@", c) >= 0:
		case c == '%':
			if i+2 >= len(seg) || !isHex(seg[i+1]) || !isHex(seg[i+2]) {
				return errors.New("malformed percent-escape — refused")
			}
			i += 2
		default:
			return fmt.Errorf("byte 0x%02x is not allowed in a path segment — refused", c)
		}
	}
	return nil
}

// decodeID accepts lowercase hex of even length ≥ 2 and returns the bytes.
func decodeID(s string) ([]byte, error) {
	if len(s) < 2 || len(s)%2 != 0 {
		return nil, fmt.Errorf("login: id %q is not lowercase hex of even length", s)
	}
	for i := 0; i < len(s); i++ {
		if !isHexLower(s[i]) {
			return nil, fmt.Errorf("login: id %q is not lowercase hex of even length", s)
		}
	}
	return hex.DecodeString(s)
}

func isHexLower(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') }
func isHex(c byte) bool      { return isHexLower(c) || (c >= 'A' && c <= 'F') }
