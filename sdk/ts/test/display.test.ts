// Sweeps every code point against vectors/display-unsafe.json, so this lane's table is that list
// exactly — and so are the other two lanes', which sweep the same file. By code point, so the
// astral tag block (U+E0000–U+E0FFF) is covered.

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { displayUnsafe } from "../src/index.js";

test("displayUnsafe is vectors/display-unsafe.json, code point for code point", () => {
  const fixture = JSON.parse(
    readFileSync(fileURLToPath(new URL("../../../../vectors/display-unsafe.json", import.meta.url)), "utf8"),
  ) as { ranges: Array<[string, string]> };
  const want = new Set<number>();
  for (const [a, b] of fixture.ranges) {
    const lo = parseInt(a, 16);
    const hi = parseInt(b, 16);
    assert.ok(lo <= hi, `bad range ${a}..${b}`);
    for (let cp = lo; cp <= hi; cp++) want.add(cp);
  }
  assert.ok(want.size >= 4000, `the fixture lists only ${want.size} code points`);
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    if (displayUnsafe(cp) !== want.has(cp)) {
      assert.fail(`displayUnsafe(U+${cp.toString(16).toUpperCase().padStart(4, "0")}) disagrees with the fixture`);
    }
  }
});

test("an astral display-unsafe code point is seen through a string", () => {
  // U+E0041 TAG LATIN CAPITAL LETTER A: two UTF-16 units, one code point.
  const s = "read:projects\u{E0041}";
  assert.ok([...s].some((ch) => displayUnsafe(ch.codePointAt(0)!)));
});
