// What may be shown: the code points archon will not show as themselves (docs/login.md §5).

/** vectors/display-unsafe.json's list, sorted and disjoint, as [first, last] code points. */
const DISPLAY_UNSAFE_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x001f], [0x007f, 0x009f], [0x00ad, 0x00ad], [0x034f, 0x034f],
  [0x0600, 0x0605], [0x061c, 0x061c], [0x06dd, 0x06dd], [0x070f, 0x070f],
  [0x0890, 0x0891], [0x08e2, 0x08e2], [0x115f, 0x1160], [0x17b4, 0x17b5],
  [0x180b, 0x180f], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f],
  [0x3164, 0x3164], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xffa0, 0xffa0],
  [0xfff0, 0xfffb], [0x110bd, 0x110bd], [0x110cd, 0x110cd], [0x13430, 0x1343f],
  [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0000, 0xe0fff],
];

/**
 * Whether `codePoint` is one archon will not show as itself: a terminal may render it as
 * nothing, or let it rearrange or hide the text around it, so that what a person reads differs
 * from the bytes they sign. The set is `Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point`:
 * control characters (C0, DEL, C1), format characters (bidirectional controls, zero-width
 * characters, invisible operators, interlinear annotations, tags), the line and paragraph
 * separators, and every code point Unicode says should render invisibly (soft hyphen, combining
 * grapheme joiner, Hangul fillers, variation selectors, …).
 *
 * It takes a CODE POINT, not a UTF-16 unit: iterate a string with `for (const ch of s)` and pass
 * `ch.codePointAt(0)`, or the astral tag block is never seen. The list is frozen as explicit
 * ranges, identical in the three lanes and pinned by vectors/display-unsafe.json. It is stricter
 * than the binding's own grammar, which refuses only C0 and DEL: the wire is unchanged, and this
 * is the rule for what may be SHOWN. A look-alike character (a Cyrillic "а" for a Latin "a") is
 * not in it; no list of code points can catch those.
 */
export function displayUnsafe(codePoint: number): boolean {
  let lo = 0;
  let hi = DISPLAY_UNSAFE_RANGES.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (DISPLAY_UNSAFE_RANGES[mid]![1] < codePoint) lo = mid + 1;
    else hi = mid;
  }
  return lo < DISPLAY_UNSAFE_RANGES.length && DISPLAY_UNSAFE_RANGES[lo]![0] <= codePoint;
}
