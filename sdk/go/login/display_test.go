package login

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestDisplayUnsafeIsTheFixture sweeps every code point against vectors/display-unsafe.json, so
// this lane's table is that list exactly — and so are the other two lanes', which sweep the
// same file.
func TestDisplayUnsafeIsTheFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "vectors", "display-unsafe.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Ranges [][2]string }
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	want := map[rune]bool{}
	for _, r := range fixture.Ranges {
		lo, err1 := strconv.ParseUint(r[0], 16, 32)
		hi, err2 := strconv.ParseUint(r[1], 16, 32)
		if err1 != nil || err2 != nil || lo > hi {
			t.Fatalf("bad range %v", r)
		}
		for cp := lo; cp <= hi; cp++ {
			want[rune(cp)] = true
		}
	}
	if len(want) < 4000 {
		t.Fatalf("the fixture lists only %d code points: not the file this test expects", len(want))
	}
	for cp := rune(0); cp <= 0x10FFFF; cp++ {
		if cp >= 0xD800 && cp <= 0xDFFF {
			continue
		}
		if got := DisplayUnsafe(cp); got != want[cp] {
			t.Fatalf("DisplayUnsafe(U+%04X) = %v, the fixture says %v", cp, got, want[cp])
		}
	}
}
