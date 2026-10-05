//! Sweeps every code point against `vectors/display-unsafe.json`, so this lane's table is that
//! list exactly — and so are the other two lanes', which sweep the same file.

use archon_sdk::login::display_unsafe;

#[test]
fn display_unsafe_is_the_fixture() {
    let raw = std::fs::read_to_string("../../vectors/display-unsafe.json").expect("fixture");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("json");
    let mut want = std::collections::HashSet::new();
    for r in v["ranges"].as_array().expect("ranges") {
        let lo = u32::from_str_radix(r[0].as_str().unwrap(), 16).unwrap();
        let hi = u32::from_str_radix(r[1].as_str().unwrap(), 16).unwrap();
        assert!(lo <= hi, "bad range {r}");
        want.extend(lo..=hi);
    }
    assert!(
        want.len() >= 4000,
        "the fixture lists only {} code points",
        want.len()
    );
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue; // the surrogates: never in a string
        };
        assert_eq!(
            display_unsafe(c),
            want.contains(&cp),
            "display_unsafe(U+{cp:04X}) disagrees with the fixture"
        );
    }
}
