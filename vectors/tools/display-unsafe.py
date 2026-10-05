#!/usr/bin/env python3
"""Derive vectors/display-unsafe.json: the code points archon will not show as themselves.

A code point is DISPLAY-UNSAFE when a terminal may render it as nothing, or let it rearrange or
hide the text around it, so that what a person reads differs from the bytes that are signed:

    Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point

control characters (C0, DEL, C1), format characters (the bidirectional controls, zero-width
characters, invisible operators, interlinear annotations, tags), the line and paragraph
separators, and every code point Unicode itself says should render invisibly (soft hyphen,
combining grapheme joiner, Hangul fillers, variation selectors, …).

The list is FROZEN as explicit ranges, so no lane depends on its platform's Unicode tables, and
each sdk lane's unit test sweeps every code point against this file. General categories come
from this Python's unicodedata; Default_Ignorable_Code_Point is not in unicodedata, so it is
written out below from Unicode's DerivedCoreProperties.txt. Extending the list is a change to
this file, reviewed like any other.

Run from the repo root, with a Python whose Unicode data is 15.1.0:
`python vectors/tools/display-unsafe.py > vectors/display-unsafe.json`.
"""

import json
import sys
import unicodedata

# The general categories come from the running Python's tables, so the Unicode version is
# pinned: another version may move a code point between categories, and moving to it is a
# reviewed change to this line, not a side effect of upgrading Python.
UNICODE = "15.1.0"
if unicodedata.unidata_version != UNICODE:
    sys.exit(f"display-unsafe.py: this Python's Unicode data is {unicodedata.unidata_version}, "
             f"the list is pinned to {UNICODE}; run it with a Python that has {UNICODE}")

# DerivedCoreProperties.txt, Default_Ignorable_Code_Point (unchanged from Unicode 14.0 to 16.0).
DEFAULT_IGNORABLE = [
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
]

unsafe = set()
for lo, hi in DEFAULT_IGNORABLE:
    unsafe.update(range(lo, hi + 1))
for cp in range(0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue  # never in valid UTF-8, so never in a string archon holds
    if unicodedata.category(chr(cp)) in ("Cc", "Cf", "Zl", "Zp"):
        unsafe.add(cp)

ranges = []
for cp in sorted(unsafe):
    if ranges and cp == ranges[-1][1] + 1:
        ranges[-1][1] = cp
    else:
        ranges.append([cp, cp])

doc = {
    "_why": "The code points archon refuses to show as themselves (docs/login.md §5): Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point. login refuses a scope entry carrying one before it is shown or signed; the servers refuse one at the door; the CLIs' display and machine output escape one as \\uXXXX. Frozen here as explicit ranges so every lane agrees without a Unicode table; each sdk lane's unit test sweeps all of 0..=0x10FFFF (surrogates excepted) against this file, by code point.",
    "definition": "Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point",
    "unicode": UNICODE,
    "generator": "vectors/tools/display-unsafe.py",
    "ranges": [[f"{lo:04X}", f"{hi:04X}"] for lo, hi in ranges],
}
# UTF-8 and LF whatever the platform: Windows' console encoding and newline translation would
# otherwise change the bytes.
sys.stdout.reconfigure(encoding="utf-8", newline="\n")
print(json.dumps(doc, indent=2, ensure_ascii=False))
