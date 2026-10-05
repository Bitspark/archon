//! What may be shown: the code points archon will not show as themselves (`docs/login.md` §5).

/// Whether `c` is a code point archon will not show as itself: a terminal may render it as
/// nothing, or let it rearrange or hide the text around it, so that what a person reads differs
/// from the bytes they sign. The set is
///
/// ```text
/// Cc ∪ Cf ∪ Zl ∪ Zp ∪ Default_Ignorable_Code_Point
/// ```
///
/// — control characters (C0, DEL, C1), format characters (bidirectional controls, zero-width
/// characters, invisible operators, interlinear annotations, tags), the line and paragraph
/// separators, and every code point Unicode says should render invisibly (soft hyphen, combining
/// grapheme joiner, Hangul fillers, variation selectors, …).
///
/// It is frozen as explicit ranges, identical in the three lanes and pinned by
/// `vectors/display-unsafe.json`, so no lane depends on its platform's Unicode tables. It is
/// stricter than the binding's own grammar, which refuses only C0 and DEL: the wire is unchanged,
/// and this is the rule for what may be SHOWN. A look-alike character (a Cyrillic "а" for a Latin
/// "a") is not in it; no list of code points can catch those.
pub fn display_unsafe(c: char) -> bool {
    let cp = c as u32;
    let i = DISPLAY_UNSAFE_RANGES.partition_point(|&(_, hi)| hi < cp);
    i < DISPLAY_UNSAFE_RANGES.len() && DISPLAY_UNSAFE_RANGES[i].0 <= cp
}

/// `vectors/display-unsafe.json`'s list, sorted and disjoint.
const DISPLAY_UNSAFE_RANGES: [(u32, u32); 27] = [
    (0x0000, 0x001F),
    (0x007F, 0x009F),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];
