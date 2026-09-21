package login

import (
	"encoding/hex"
	"testing"
)

func TestDeriveAudienceAccepts(t *testing.T) {
	const id = "8f3c1d2e4b5a69780f1e2d3c4b5a6978"
	cases := []struct{ url, audience string }{
		{"https://dawn.example/api/login/" + id, "https://dawn.example/api"},
		{"https://dawn.example:443/api/login/" + id, "https://dawn.example/api"},
		{"http://localhost:80/login/" + id, "http://localhost"},
		{"http://localhost:8080/login/" + id, "http://localhost:8080"},
		{"HTTPS://Dawn.Example/API/login/" + id, "https://dawn.example/API"},
		{"wss://dawn.example/api/login/" + id, "https://dawn.example/api"},
		{"ws://dawn.example:80/login/" + id, "http://dawn.example"},
		{"wss://dawn.example:80/login/" + id, "https://dawn.example:80"},
		{"https://dawn.example/a/b%2Fc/v1/login/" + id, "https://dawn.example/a/b%2Fc/v1"},
		{"https://[::1]:8443/api/login/" + id, "https://[::1]:8443/api"},
		{"https://[2001:DB8::1]:443/login/" + id, "https://[2001:db8::1]"},
		{"https://10.0.0.7/login/" + id, "https://10.0.0.7"},
		{"https://dawn.example/login/" + id, "https://dawn.example"},
		{"https://dawn.example/a:b@c/login/" + id, "https://dawn.example/a:b@c"},
	}
	for _, tc := range cases {
		aud, got, err := DeriveAudience(tc.url)
		if err != nil {
			t.Errorf("%s: %v", tc.url, err)
			continue
		}
		if aud != tc.audience {
			t.Errorf("%s: audience %q, want %q", tc.url, aud, tc.audience)
		}
		if hex.EncodeToString(got) != id {
			t.Errorf("%s: id %x", tc.url, got)
		}
	}
}

func TestDeriveAudienceRefuses(t *testing.T) {
	const id = "8f3c1d2e4b5a69780f1e2d3c4b5a6978"
	cases := []string{
		"dawn.example/api/login/" + id,                // no scheme
		"ftp://dawn.example/login/" + id,              // unsupported scheme
		"https://dawn.example",                        // no path
		"https://dawn.example/login",                  // no id
		"https://dawn.example/api/" + id,              // penultimate not login
		"https://dawn.example/api/login/" + id + "/",  // trailing slash
		"https://dawn.example//login/" + id,           // empty segment
		"https://dawn.example/./login/" + id,          // dot segment
		"https://dawn.example/../login/" + id,         // dotdot segment
		"https://user@dawn.example/login/" + id,       // userinfo
		"https://dawn.example/login/" + id + "?x=1",   // query
		"https://dawn.example/login/" + id + "#f",     // fragment
		"https://dawn.example/api/login/8F3C",         // uppercase hex
		"https://dawn.example/api/login/8f3",          // odd length
		"https://dawn.example/api/login/zz",           // not hex
		"https://dawn.example/api/login/",             // empty id
		"https://dawn.example:0/login/" + id,          // port 0
		"https://dawn.example:65536/login/" + id,      // port too big
		"https://dawn.example:0443/login/" + id,       // leading zero
		"https://dawn.example:4a3/login/" + id,        // non-digit port
		"https://dawn.example:/login/" + id,           // empty port
		"https://dawn.example./login/" + id,           // trailing dot in host
		"https://.dawn.example/login/" + id,           // leading dot in host
		"https://dawn_example/login/" + id,            // underscore in host
		"https://dawn.exämple/login/" + id,            // non-ASCII host
		"https://[::1/login/" + id,                    // unterminated IPv6
		"https://[::1]x/login/" + id,                  // junk after IPv6
		"https://[fe80::1%25eth0]/login/" + id,        // zone id
		"https://dawn.example/a b/login/" + id,        // space
		"https://dawn.example/a%2/login/" + id,        // malformed escape
		"https://dawn.example/a%zz/login/" + id,       // malformed escape
		"https://dawn.example/\x01/login/" + id,       // control byte
		"https://dawn.example/api/login/" + id + "\n", // trailing newline
		"",
		"https://",
		"https:///login/" + id, // empty host
	}
	for _, u := range cases {
		if aud, got, err := DeriveAudience(u); err == nil {
			t.Errorf("%q: not refused (audience %q id %x)", u, aud, got)
		}
	}
}
