//! An OUTSIDE consumer of archon from crates.io — see ../Cargo.toml. The registry names are
//! `bitspark-archon-*`; what a consumer writes is `archon_core::` and `archon_sdk::`.
use archon_core::{crypto, keytext};
use archon_sdk::possession;

fn main() {
    let seed = [0x11u8; 32];
    let pk = crypto::public_key_from_seed(&seed);
    println!("key: {}", keytext::encode_key(&pk));

    let sig = crypto::sign_in_domain(&seed, "archon/test/v1", b"hello").expect("sign");
    let in_domain = crypto::verify_in_domain(&pk, "archon/test/v1", b"hello", &sig);
    let other_domain = crypto::verify_in_domain(&pk, "archon/test/v2", b"hello", &sig);
    let as_raw = crypto::verify(&pk, b"hello", &sig);
    println!("genuine: in v1={in_domain} in v2={other_domain} raw={as_raw}");

    // ADR 0008, asserted on inputs EVERY library accepted before it — the identity as R, and
    // a mixed-order key with a challenge divisible by 8 (oracle cases profile-identity-R and
    // profile-mixed-order-A-k-divisible) — so that only archon's own check can be what
    // refuses them. An input the library already refuses on its own would pass whether or
    // not the published crate enforces anything.
    let identity_r = refused(
        &pk,
        "68656c6c6f",
        "010000000000000000000000000000000000000000000000000000000000000004201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07",
    );
    let mixed_key = unhex("05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4");
    let mixed_a = refused(
        &mixed_key,
        "6d697865642d6f72646572233133",
        "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b120e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b",
    );
    println!("profile: identity R refused={identity_r}, mixed-order key refused={mixed_a}");

    let nonce = [0x42u8; 32];
    let proof = possession::prove(&seed, "example/pop/v1", &nonce, b"binding").expect("prove");
    let pop = possession::verify(&pk, "example/pop/v1", &nonce, b"binding", &proof);
    println!("possession: {pop}");

    if !(in_domain && !other_domain && !as_raw && identity_r && mixed_a && pop) {
        eprintln!("FAIL: the published crates do not behave as the release claims");
        std::process::exit(1);
    }
    println!("OK: bitspark-archon-core + bitspark-archon-sdk from crates.io");
}

/// Whether the published floor refuses (pubkey, message, sig) — a case an unprofiled
/// verifier accepts.
fn refused(pubkey: &[u8], message_hex: &str, sig_hex: &str) -> bool {
    !crypto::verify(pubkey, &unhex(message_hex), &unhex(sig_hex))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}
