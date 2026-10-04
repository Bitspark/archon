//! The signer contract — SIGNING CAPABILITY, NOT SEEDS (ADR 0009 §2–4).
//!
//! Every helper in this crate can take a seed, which is right for a key held in software and
//! wrong for one that is not: a stored key behind `archon sign --key`, or any backend a caller
//! wires in. So each signing helper also comes in three parts — a PURE `prepare` (the exact
//! request it needs signed), the signer's own work, and a PURE `complete` (the checked
//! signature, then packaging) — with a `…_with` convenience that runs the signer between them.
//! The seed functions are unchanged.
//!
//! A [`SigningRequest`] is three things, and the scheme is a discriminated value, never a
//! scheme name plus an optional domain: the public key the caller expects, raw Ed25519 or
//! Ed25519ph with the domain as the RFC 8032 context, and the ORIGINAL message bytes — never a
//! digest; a backend that wants a prehash computes it inside its own adapter.
//!
//! Three rules, all enforced here rather than trusted to a signer:
//!
//! - A request is validated BEFORE the signer is invoked: a domain the floor refuses never
//!   reaches it (a wrong-length key cannot be written down: it is a `[u8; 32]`).
//! - A signer REPORTS what it can do ([`Capabilities`]), and a request outside that is refused
//!   before it is invoked. A signer that cannot carry a context declares raw only; it must
//!   never sign a ph request with an empty context instead, and if it does anyway, the check
//!   below catches it.
//! - Every returned signature is VERIFIED against the requested key, scheme, domain and bytes
//!   — never against values the signer echoes back. That catches a wrong key, a dropped
//!   context, raw substituted for ph, and a wrong prehash adaptation. It does not prove that a
//!   signer signs deterministically (ADR 0008 §1.7 requires it); that is a property of the
//!   backend, tested against the `domain_sign` vectors.
//!
//! Cancellation is Rust's own: dropping the future returned by [`sign_with`] abandons the call,
//! and a signature the signer produced after that is never seen, let alone packaged.
//!
//! Domain separation is not authorization: whoever may ask for signatures in a domain gets
//! any signature in that domain. Consent belongs to the caller that knows what the bytes mean.

use std::future::Future;

use archon_core::crypto::{
    public_key_from_seed, sign, sign_in_domain, verify, verify_in_domain, PUBLIC_KEY_SIZE,
    SEED_SIZE, SIGNATURE_SIZE,
};

/// Raw Ed25519 over the message, or Ed25519ph with the domain as the RFC 8032 context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Pure Ed25519. Carries no domain.
    Raw,
    /// Ed25519ph with `domain` as the context.
    PhContext {
        /// The domain, as ADR 0008 §2 bounds it.
        domain: String,
    },
}

/// A scheme's name, for [`Capabilities`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `ed25519-raw`.
    Raw,
    /// `ed25519ph-context`.
    PhContext,
}

impl Scheme {
    /// The scheme's name.
    pub fn kind(&self) -> Kind {
        match self {
            Scheme::Raw => Kind::Raw,
            Scheme::PhContext { .. } => Kind::PhContext,
        }
    }
}

/// What a signer is asked to sign. `message` is always the original bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningRequest {
    /// The public key the caller expects the signature to verify under.
    pub expected_public_key: [u8; PUBLIC_KEY_SIZE],
    /// How to sign.
    pub scheme: Scheme,
    /// The original message bytes.
    pub message: Vec<u8>,
}

/// What a signer can do. `domains: None` means any domain the floor accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    /// The schemes it can produce.
    pub schemes: Vec<Kind>,
    /// When present, the only domains it will sign in.
    pub domains: Option<Vec<String>>,
}

/// A source of signatures. `sign` may prompt, call a subprocess or wait on a device.
pub trait Signer {
    /// The key it signs with.
    fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE];
    /// What it can do.
    fn capabilities(&self) -> Capabilities;
    /// Signs `request`. Called only after the request is validated and within the
    /// capabilities; what it returns is checked before anyone uses it.
    fn sign(
        &self,
        request: &SigningRequest,
    ) -> impl Future<Output = Result<[u8; SIGNATURE_SIZE], String>>;
}

/// Errors unless `request` is in range: for ph, a domain the floor accepts. The domain is
/// checked by the floor's own rule (it signs nothing with a throwaway key), so no copy of
/// ADR 0008 §2 lives here to drift.
pub fn validate(request: &SigningRequest) -> Result<(), String> {
    match &request.scheme {
        Scheme::Raw => Ok(()),
        Scheme::PhContext { domain } => sign_in_domain(&[0u8; SEED_SIZE], domain, &[]).map(|_| ()),
    }
}

/// The signature, if it verifies for exactly what was REQUESTED: its key, scheme, domain and
/// original bytes.
pub fn check_signature(
    request: &SigningRequest,
    signature: &[u8],
) -> Result<[u8; SIGNATURE_SIZE], String> {
    validate(request)?;
    let ok = match &request.scheme {
        Scheme::Raw => verify(&request.expected_public_key, &request.message, signature),
        Scheme::PhContext { domain } => verify_in_domain(
            &request.expected_public_key,
            domain,
            &request.message,
            signature,
        ),
    };
    let checked: Option<[u8; SIGNATURE_SIZE]> = signature.try_into().ok();
    match checked {
        Some(sig) if ok => Ok(sig),
        _ => Err(
            "signer: the signature does not verify for the requested key, scheme and message"
                .to_string(),
        ),
    }
}

/// Errors unless `signer` claims to be able to sign `request`: its key is the expected one,
/// and the scheme and domain are among its capabilities. Called before it is invoked.
pub fn check_capability<S: Signer>(signer: &S, request: &SigningRequest) -> Result<(), String> {
    if signer.public_key() != request.expected_public_key {
        return Err("signer: this signer's key is not the expected key".to_string());
    }
    let caps = signer.capabilities();
    if !caps.schemes.contains(&request.scheme.kind()) {
        return Err(format!(
            "signer: this signer cannot produce {}",
            match request.scheme.kind() {
                Kind::Raw => "ed25519-raw",
                Kind::PhContext => "ed25519ph-context",
            }
        ));
    }
    if let (Scheme::PhContext { domain }, Some(domains)) = (&request.scheme, &caps.domains) {
        if !domains.contains(domain) {
            return Err(format!(
                "signer: this signer does not sign in domain {domain:?}"
            ));
        }
    }
    Ok(())
}

/// Validates, checks the signer's capabilities, invokes it, and returns the signature only if
/// it verifies for what was requested.
pub async fn sign_with<S: Signer>(
    signer: &S,
    request: &SigningRequest,
) -> Result<[u8; SIGNATURE_SIZE], String> {
    validate(request)?;
    check_capability(signer, request)?;
    let signature = signer.sign(request).await?;
    check_signature(request, &signature)
}

/// The software signer: a seed held in this process, both schemes, any domain the floor
/// accepts, deterministic by the floor's construction. The seed is copied.
#[derive(Clone)]
pub struct SeedSigner {
    seed: [u8; SEED_SIZE],
}

impl SeedSigner {
    /// A signer for the key behind `seed`.
    pub fn new(seed: &[u8; SEED_SIZE]) -> Self {
        SeedSigner { seed: *seed }
    }
}

impl std::fmt::Debug for SeedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the seed.
        f.debug_struct("SeedSigner")
            .field("public_key", &public_key_from_seed(&self.seed))
            .finish()
    }
}

impl Signer for SeedSigner {
    fn public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        public_key_from_seed(&self.seed)
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            schemes: vec![Kind::Raw, Kind::PhContext],
            domains: None,
        }
    }

    fn sign(
        &self,
        request: &SigningRequest,
    ) -> impl Future<Output = Result<[u8; SIGNATURE_SIZE], String>> {
        let result = match &request.scheme {
            Scheme::Raw => Ok(sign(&self.seed, &request.message)),
            Scheme::PhContext { domain } => sign_in_domain(&self.seed, domain, &request.message),
        };
        std::future::ready(result)
    }
}
