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

    // ADR 0008: the identity key's universal signature (R = B, S = 1) is refused.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut universal = [0x66u8; 64];
    universal[0] = 0x58;
    universal[32] = 1;
    for b in &mut universal[33..] {
        *b = 0;
    }
    let u_raw = crypto::verify(&identity, b"hello", &universal);
    let u_domain = crypto::verify_in_domain(&identity, "archon/test/v1", b"hello", &universal);
    println!("identity key: raw={u_raw} in v1={u_domain}");

    let nonce = [0x42u8; 32];
    let proof = possession::prove(&seed, "example/pop/v1", &nonce, b"binding").expect("prove");
    let pop = possession::verify(&pk, "example/pop/v1", &nonce, b"binding", &proof);
    println!("possession: {pop}");

    if !(in_domain && !other_domain && !as_raw && !u_raw && !u_domain && pop) {
        eprintln!("FAIL: the published crates do not behave as the release claims");
        std::process::exit(1);
    }
    println!("OK: bitspark-archon-core + bitspark-archon-sdk from crates.io");
}
