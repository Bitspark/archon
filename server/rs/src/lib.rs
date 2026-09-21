//! The service side of the archon login protocol (`docs/login.md` §4 and §4.1): the four
//! routes a browser and a CLI need to rendezvous, and the two by which the CLI may start
//! instead (an offer, read and taken by the page), so a service adopts proof-of-possession
//! sign-in by mounting a handler rather than by building a session system.
//!
//! # Three things this crate deliberately is not (ADR 0007 §B)
//!
//! - **Not a server.** It opens no socket and spawns no task. [`Handler::handle`] is a plain
//!   function from a [`Request`] to a [`Response`]; the service's own server owns the
//!   listener. That is why there is no framework here — no axum, no tower, no hyper. An
//!   adapter for whichever the service uses is a dozen lines and belongs beside this crate,
//!   not inside it.
//! - **Not a law.** The authority payload is opaque bytes, interpreted only inside the
//!   [`AdmitAuthority`] the service supplies. archon ships no implementation of one.
//! - **Not a store.** One in-memory record per pending login, dropped at expiry or on
//!   collection; nothing persisted, nothing surviving the process.
//!
//! # The audience is configured, never read from the wire
//!
//! Every binding is recomputed from the string the service configured. That is the WebAuthn
//! rule and review Finding 1: a relying party's identity comes from its own configuration,
//! not from a value an attacker can put in a message. No code path here reads an audience
//! from a request, which is why there is no way to get it wrong — and [`Handler::new`]
//! refuses an audience that is not a fixed point of the §2.1 grammar, so a misspelling is a
//! startup error rather than every proof failing silently.
//!
//! The scheme itself — the binding layout, the domain, the proofs — is `archon-sdk`'s and is
//! consumed, never reimplemented: a binding written twice is a binding that drifts.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;

use archon_core::keytext;
use archon_sdk::login;

pub mod http;
mod json;
mod routes;

pub use routes::{Request, Response};

/// The RFC 8628 / RFC 6749 codes §4 adopts verbatim. Their bearer-token result is not ours,
/// but their vocabulary is, so a client that already speaks device flow behaves well.
pub(crate) const ERR_INVALID_REQUEST: &str = "invalid_request";
pub(crate) const ERR_INVALID_GRANT: &str = "invalid_grant";
pub(crate) const ERR_EXPIRED_TOKEN: &str = "expired_token";
pub(crate) const ERR_PENDING: &str = "authorization_pending";
pub(crate) const ERR_SLOW_DOWN: &str = "slow_down";

/// The header carrying the browser's collect proof. Exported because a browser client has to
/// spell it, and one spelling in one place is how the two halves stay agreed.
pub const COLLECT_HEADER: &str = "archon-collect";

/// Five minutes, from §4.
pub const DEFAULT_TTL_SECS: u64 = 300;
/// Five seconds, from §4.
pub const DEFAULT_INTERVAL_SECS: u64 = 5;

/// The floor on both the generated id and the generated nonce. §3.1 requires it of the nonce
/// and recommends it for the id; this crate applies it to both, since an id a stranger can
/// guess is the address of a pending login.
pub(crate) const MIN_ENTROPY: usize = 16;

/// The floor on an offer's code (§4.1): at least 16 bytes of the PROVER's entropy, spelled as
/// lowercase hex — so 32 characters. The code is the address of an open offer and is
/// confidential until the offer is taken; a short one is guessable.
pub(crate) const MIN_CODE_HEX: usize = 2 * MIN_ENTROPY;

/// Caps every request body. Each message here is a key, a hex proof and a short scope list;
/// the authority payload is the only field with no natural size, and a law needing more than
/// this should say so rather than have the handler guess high.
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;

/// Interprets the authority payload — the ONLY place one is interpreted, and archon ships no
/// implementation. Returning `Err` refuses the answer with `403 invalid_grant` and stores
/// nothing. `None` means the proof alone suffices, which is right for a service whose law
/// needs nothing beyond "this key holder was here and approved this scope".
///
/// It runs OUTSIDE the store's lock: it is the service's code and may block on a database or
/// a network, and a law that held the lock would decide the throughput of every login in the
/// process.
pub type AdmitAuthority =
    Box<dyn Fn(&[u8], &[u8], &[u8]) -> Result<(), String> + Send + Sync + 'static>;

/// Seconds since the Unix epoch. A constructor argument rather than a call to the system
/// clock, which is the sdk's rule and the reason the suite never sleeps: a test steps it by
/// hand, and production passes something that reads the clock.
pub type Clock = Box<dyn Fn() -> u64 + Send + Sync + 'static>;

/// Fills a buffer with random bytes. A constructor argument for the same reason as [`Clock`]:
/// a test predicts it, production draws from the OS.
pub type Entropy = Box<dyn Fn(&mut [u8]) -> Result<(), String> + Send + Sync + 'static>;

/// One pending login. Written once at begin; only `answered` and `last_poll` ever change, and
/// NEITHER ENTERS A BINDING — which is what makes it safe to verify a proof against a copy
/// taken outside the lock.
pub(crate) struct Record {
    pub id: Vec<u8>,
    pub nonce: Vec<u8>,
    pub browser: Vec<u8>,
    pub scope: Vec<String>,
    pub valid_for: u32,
    pub expires: u64,
    pub answered: Option<Answer>,
    pub last_poll: Option<u64>,
}

/// What the CLI posted and the browser collects, held verbatim between the two.
#[derive(Clone)]
pub(crate) struct Answer {
    pub principal: String,
    pub possession: String,
    /// Opaque. Stored as the raw JSON the CLI sent, so what the law admitted is what the
    /// browser receives, byte for byte.
    pub authority: Option<String>,
}

impl Record {
    pub(crate) fn as_request(&self) -> login::Request {
        login::Request {
            id: self.id.clone(),
            nonce: self.nonce.clone(),
            browser: self.browser.clone(),
            scope: self.scope.clone(),
            valid_for: self.valid_for,
        }
    }
}

/// One registered offer (`docs/login.md` §4.1): what a prover is willing to delegate, to a key
/// it does not know yet. It carries no key and no proof — what it carries is the code's
/// confidentiality until it is taken. Written once at registration; only `request` changes,
/// once, when the first matching request takes it.
#[derive(Clone)]
pub(crate) struct Offer {
    /// Lowercase hex — the map key and the URL segment; ≥ 16 bytes of the prover's entropy.
    pub code: String,
    pub scope: Vec<String>,
    pub valid_for: u32,
    pub expires: u64,
    /// The hex id of the request that took this offer, or `None` while it is open. An offer
    /// dies with its request (§4.1 "State"): once that record is gone — collected or
    /// expired — the offer is gone too, which the store enforces on read like every expiry.
    pub request: Option<String>,
}

/// The verdict on a request naming an offer, beyond "gone" being one answer for unknown,
/// expired and orphaned alike: `Gone` is `404 expired_token`, `Taken` is `409 invalid_request`
/// (one offer, one request — §4.1 rule 5), `Mismatch` is `400 invalid_request` (the request
/// differs from the offer, in any way).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OfferRefusal {
    Gone,
    Taken,
    Mismatch,
}

/// Both maps under ONE lock. "Begin on the offer" must check the offer, store the request and
/// take the offer in a single critical section, and two locks would make that an ordering
/// discipline instead of a fact.
#[derive(Default)]
pub(crate) struct Store {
    pub requests: HashMap<String, Record>,
    pub offers: HashMap<String, Offer>,
}

/// §4.1's "differs in any way", stated once: the same number of entries, each equal to its
/// counterpart IN ORDER, and the same validity. A set comparison would let a page reorder
/// what the person typed; a length comparison would let it swap an entry.
fn matches_offer(o: &Offer, scope: &[String], valid_for: u32) -> bool {
    valid_for == o.valid_for && scope == o.scope.as_slice()
}

impl Store {
    /// The one definition of a live offer: unexpired, and — if a request has taken it — that
    /// request still present and unexpired. "Dies with its request" is enforced here, on
    /// every read, rather than by anything that runs when a request is collected: an offer
    /// that consults the record it points at can never disagree with it.
    pub(crate) fn offer_live(&self, o: &Offer, now: u64) -> bool {
        if now >= o.expires {
            return false;
        }
        match &o.request {
            None => true,
            Some(id) => self.requests.get(id).is_some_and(|r| now < r.expires),
        }
    }

    /// A COPY of the live offer under `code`, dropping a dead one. A copy rather than a
    /// reference, because `request` is written by `take_offer` while a poll may be rendering
    /// it — the one field of an offer that changes after registration is the one the poll
    /// reads — and the guard must not be held while a response is built.
    pub(crate) fn live_offer(&mut self, code: &str, now: u64) -> Option<Offer> {
        let live = self
            .offers
            .get(code)
            .is_some_and(|o| self.offer_live(o, now));
        if !live {
            self.offers.remove(code);
            return None;
        }
        self.offers.get(code).cloned()
    }

    /// Whether a request with this scope and validity may take the offer. `begin` asks BEFORE
    /// decoding the browser key or drawing entropy, so a page that alters what it was offered
    /// is refused before anything is stored and before any key is involved (§4.1) — and asks
    /// again, inside `take_offer`, when it stores.
    pub(crate) fn check_offer(
        &mut self,
        code: &str,
        now: u64,
        scope: &[String],
        valid_for: u32,
    ) -> Result<(), OfferRefusal> {
        match self.live_offer(code, now) {
            None => Err(OfferRefusal::Gone),
            Some(o) if o.request.is_some() => Err(OfferRefusal::Taken),
            Some(o) if !matches_offer(&o, scope, valid_for) => Err(OfferRefusal::Mismatch),
            Some(_) => Ok(()),
        }
    }

    /// Stores the request AND marks the offer taken in one critical section, repeating every
    /// check first: the offer may have expired, been taken by another request, or — its
    /// request gone — died while this request was being built outside the lock. Two pages
    /// beginning on one code is ordinary (a person with two tabs), and exactly one must win.
    pub(crate) fn take_offer(
        &mut self,
        code: &str,
        now: u64,
        record: Record,
    ) -> Result<(), OfferRefusal> {
        self.check_offer(code, now, &record.scope, record.valid_for)?;
        let id = json::to_hex(&record.id);
        self.requests.insert(id.clone(), record);
        if let Some(o) = self.offers.get_mut(code) {
            o.request = Some(id);
        }
        Ok(())
    }
}

/// The handler. Build one with [`Handler::new`] and call [`Handler::handle`] from whatever
/// server the service runs.
pub struct Handler {
    pub(crate) audience: String,
    pub(crate) admit: Option<AdmitAuthority>,
    pub(crate) page: Option<String>,
    pub(crate) ttl: u64,
    pub(crate) interval: u64,
    pub(crate) clock: Clock,
    pub(crate) entropy: Entropy,
    pub(crate) store: Mutex<Store>,
}

/// What a service supplies. Only the audience is required; [`Config::new`] fills the rest.
pub struct Config {
    pub audience: String,
    pub admit: Option<AdmitAuthority>,
    /// The address a person opens to finish a login the CLI started (§4.1 — the offers
    /// form). Optional. When set, an offer's response carries `<page>#<code>`: the code
    /// travels in the FRAGMENT, which a browser never sends to any server, so it reaches the
    /// page's script and no log. A page that already carries a fragment is refused by
    /// [`Handler::new`]. The CLI prints the address and never opens it (§4.1 rule 1).
    pub page: Option<String>,
    /// How long a pending login lives — and how long an open offer lives.
    pub ttl_secs: u64,
    pub interval_secs: u64,
    pub clock: Option<Clock>,
    pub entropy: Option<Entropy>,
}

impl Config {
    /// A config with the defaults of §4: a five-minute TTL, a five-second interval, no law
    /// (the proof alone suffices), no page, the system clock and the OS random source.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            admit: None,
            page: None,
            ttl_secs: DEFAULT_TTL_SECS,
            interval_secs: DEFAULT_INTERVAL_SECS,
            clock: None,
            entropy: None,
        }
    }

    pub fn admit(mut self, admit: AdmitAuthority) -> Self {
        self.admit = Some(admit);
        self
    }

    pub fn page(mut self, page: impl Into<String>) -> Self {
        self.page = Some(page.into());
        self
    }

    pub fn clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn entropy(mut self, entropy: Entropy) -> Self {
        self.entropy = Some(entropy);
        self
    }
}

impl Handler {
    /// Builds a handler, or explains why the configuration cannot work.
    ///
    /// THE AUDIENCE MUST BE A FIXED POINT OF THE §2.1 GRAMMAR, and that is checked with the
    /// grammar itself rather than with a list of rules restated here. `https://Dawn.example/api`,
    /// `…:443` and `wss://…` each DERIVE to something else, so a handler configured with one
    /// would bind the spelling in the config file while the CLI bound the derived one, and
    /// every proof would fail with nothing on either side saying why. Feeding the audience
    /// back through `derive_audience` asks the only question that matters: is this the string
    /// the CLI will produce?
    ///
    /// The `/login/00` is the shortest invocation URL the grammar admits — a minimum-length
    /// id — and exists only to make the audience parseable as one.
    pub fn new(cfg: Config) -> Result<Self, String> {
        if cfg.audience.is_empty() {
            return Err("login: an audience is required — the handler binds to it and never reads one from the wire".to_string());
        }
        let (derived, _) =
            login::derive_audience(&format!("{}/login/00", cfg.audience)).map_err(|e| {
                format!(
                    "login: audience {:?} is not valid: {e} (docs/login.md §2.1)",
                    cfg.audience
                )
            })?;
        if derived != cfg.audience {
            return Err(format!(
                "login: audience {:?} is not canonical — the CLI will derive {:?} and bind THAT, \
                 so every proof would fail. Configure {:?} (docs/login.md §2.1)",
                cfg.audience, derived, derived
            ));
        }
        // The code goes in the page's fragment (§4.1), so a page that already has one is a
        // configuration mistake — refused here, where the operator can read it, rather than
        // producing an address with two fragments that no browser parses the way anyone meant.
        if let Some(page) = &cfg.page {
            if page.contains('#') {
                return Err(format!(
                    "login: page {page:?} carries a fragment — the offer's code goes there (docs/login.md §4.1)"
                ));
            }
        }
        Ok(Self {
            audience: cfg.audience,
            admit: cfg.admit,
            page: cfg.page,
            ttl: if cfg.ttl_secs == 0 {
                DEFAULT_TTL_SECS
            } else {
                cfg.ttl_secs
            },
            interval: if cfg.interval_secs == 0 {
                DEFAULT_INTERVAL_SECS
            } else {
                cfg.interval_secs
            },
            clock: cfg.clock.unwrap_or_else(|| {
                Box::new(|| {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                })
            }),
            entropy: cfg.entropy.unwrap_or_else(|| {
                Box::new(|b: &mut [u8]| getrandom::fill(b).map_err(|e| e.to_string()))
            }),
            store: Mutex::new(Store::default()),
        })
    }

    /// Drops expired records and dead offers and reports how many went.
    ///
    /// Optional: both also expire on read, so a handler that is never swept is correct, just
    /// less tidy. A long-lived service can call this from its own maintenance loop — this
    /// crate spawns nothing of its own.
    pub fn sweep(&self) -> usize {
        let now = (self.clock)();
        let mut store = self.store.lock().expect("store lock");
        let before = store.requests.len() + store.offers.len();
        store.requests.retain(|_, r| now < r.expires);
        // Offers after requests, so an offer whose request just went is seen as orphaned.
        let dead: Vec<String> = store
            .offers
            .iter()
            .filter(|(_, o)| !store.offer_live(o, now))
            .map(|(code, _)| code.clone())
            .collect();
        for code in dead {
            store.offers.remove(&code);
        }
        before - (store.requests.len() + store.offers.len())
    }

    pub(crate) fn key(id: &[u8]) -> String {
        json::to_hex(id)
    }

    pub(crate) fn encode_browser(&self, browser: &[u8]) -> String {
        keytext::encode_key(browser)
    }
}

/// Redacted rather than derived: the fields are closures the service supplied, and the only
/// thing worth printing about a handler is what it binds to and how many logins are pending.
///
/// It exists because a service whose own struct derives `Debug` cannot hold a type that does
/// not implement it — and this crate's whole shape is "held inside someone else's
/// application".
impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handler")
            .field("audience", &self.audience)
            .field("law", &if self.admit.is_some() { "set" } else { "none" })
            .field("ttl_secs", &self.ttl)
            .field("interval_secs", &self.interval)
            .field(
                "pending",
                &self.store.lock().map(|s| s.requests.len()).unwrap_or(0),
            )
            .field(
                "offers",
                &self.store.lock().map(|s| s.offers.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("audience", &self.audience)
            .field("law", &if self.admit.is_some() { "set" } else { "none" })
            .field("ttl_secs", &self.ttl_secs)
            .field("interval_secs", &self.interval_secs)
            .finish()
    }
}

/// Formats a Unix timestamp as RFC 3339 UTC, which is what §4's `expires` field carries.
/// Written out rather than pulled from a date crate: this is the only date this crate
/// renders, and the civil-from-days algorithm is exact and total for every timestamp a
/// clock can hand back.
pub(crate) fn rfc3339(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
