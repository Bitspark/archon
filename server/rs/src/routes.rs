//! The four routes of `docs/login.md` §4 and the two of §4.1, as a plain function from a
//! request to a response.
//!
//! There is no framework here by design (ADR 0007 §B: it opens no socket). [`Request`] and
//! [`Response`] are the smallest shapes the routes need, so an adapter for axum, hyper, or a
//! bare `std::net` loop is a dozen lines beside this crate rather than a dependency inside it.

use archon_core::keytext;
use archon_sdk::login;
use serde::Deserialize;

use crate::json::{
    check_code, check_scope_entry, error_body, from_hex, malformed, parse_body, to_hex,
};
use crate::{
    Answer, Handler, Offer, OfferRefusal, Record, COLLECT_HEADER, ERR_EXPIRED_TOKEN,
    ERR_INVALID_GRANT, ERR_INVALID_REQUEST, ERR_PENDING, ERR_SLOW_DOWN, MIN_ENTROPY,
};

/// What the service hands in. `path` is RELATIVE to wherever the handler is mounted, so the
/// same code serves any prefix.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    /// Header lookups are case-insensitive per HTTP; the adapter lowercases names.
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What the service writes back.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Response {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
            ],
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            body: Vec::new(),
            headers: Vec::new(),
        }
    }

    fn error(status: u16, code: &str) -> Self {
        Self::json(status, error_body(code))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BeginBody {
    browser: String,
    #[serde(default)]
    scope: Vec<String>,
    valid_for: u32,
    /// The offer this request is made on (§4.1): `None` for the page-started form (the member
    /// absent), `Some(None)` for a member that is present but `null`, `Some(Some(code))` for a
    /// string. The double option is what lets null be told apart from absent — a present
    /// member must be a code string, and `null` is a malformed body (400), not "no offer";
    /// `Option<String>` alone read null as absent and began a login on a body ts refused
    /// (caa's review of #40). A member of any other type fails to deserialise: 400 as well.
    #[serde(default, deserialize_with = "present")]
    offer: Option<Option<String>>,
}

/// Wraps a deserialised value in `Some`, so that with `#[serde(default)]` an ABSENT member is
/// `None` and a PRESENT one — `null` included — is `Some(...)`.
fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// What the prover posts to register an offer (§4.1).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferBody {
    code: String,
    #[serde(default)]
    scope: Vec<String>,
    valid_for: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerBody {
    principal: String,
    possession: String,
    /// OPAQUE BYTES, and `RawValue` is what makes that true rather than aspirational.
    ///
    /// This was `serde_json::Value`, and a `Value` is not the CLI's bytes: its object is a
    /// sorted map, so `{"z":1,"a":2}` came back `{"a":2,"z":1}`; its numbers normalise, so
    /// `1.10` came back `1.1`; its strings are decoded, so `\u00e9` came back as the
    /// character. A law that signs its payload, or carries a 64-bit id, was handed something
    /// the CLI never sent (caa, on #28).
    #[serde(default)]
    authority: Option<Box<serde_json::value::RawValue>>,
}

impl Handler {
    /// Routes a request. The four shapes of §4 and the two of §4.1, relative to the mount:
    ///
    /// ```text
    /// POST   ""               begin       the browser opens a request ("offer" names an offer)
    /// POST   "/offers"        offer       the CLI registers what it will delegate, under its code
    /// GET    "/offers/<code>" read offer  the page reads it once; the CLI polls it until taken
    /// GET    "/<id>"          read        the CLI reads what it is being asked to sign
    /// POST   "/<id>/answer"   answer      the CLI delivers the proof
    /// GET    "/<id>/answer"   collect     the browser takes the answer, once
    /// ```
    ///
    /// The `offers` segment is matched before the id routes. There is no ambiguity to
    /// resolve — an id is hex and `offers` is not — but the order says which family owns it.
    pub fn handle(&self, req: &Request) -> Response {
        let rest = req.path.trim_matches('/');
        if rest.is_empty() {
            return if req.method == "POST" {
                self.begin(req)
            } else {
                Response::error(405, ERR_INVALID_REQUEST)
            };
        }
        let parts: Vec<&str> = rest.split('/').collect();
        match parts.as_slice() {
            ["offers"] if req.method == "POST" => self.offer(req),
            ["offers"] => Response::error(405, ERR_INVALID_REQUEST),
            ["offers", code] if req.method == "GET" => self.read_offer(code),
            ["offers", _] => Response::error(405, ERR_INVALID_REQUEST),
            [id] if req.method == "GET" => self.read(id),
            [_] => Response::error(405, ERR_INVALID_REQUEST),
            [id, "answer"] if req.method == "POST" => self.answer(req, id),
            [id, "answer"] if req.method == "GET" => self.collect(req, id),
            [_, "answer"] => Response::error(405, ERR_INVALID_REQUEST),
            _ => Response::error(404, ERR_EXPIRED_TOKEN),
        }
    }

    /// Creates a pending record: the server's id and nonce, the browser's key, the scope and
    /// validity it asked for. The nonce is the SERVER's, never the browser's — a nonce a
    /// caller chooses is a nonce a caller can replay (§3.1).
    ///
    /// On an offer, the request must be what the prover offered — scope entry for entry, in
    /// order, and validity equal — and the offer must be open. That is checked FIRST, before
    /// the browser key is decoded and before any entropy is drawn (§4.1: refused before
    /// anything is stored, before any key is involved), and again under the lock when the
    /// request is stored and the offer taken in one critical section (`Store::take_offer`).
    fn begin(&self, req: &Request) -> Response {
        let body: BeginBody = match parse_body(&req.body) {
            Ok(b) => b,
            Err(_) => return Response::json(400, malformed()),
        };
        // A member that is present must be a code STRING: `null` is a malformed body, refused
        // rather than read as "no offer" (the page-started form leaves the member out).
        if matches!(body.offer, Some(None)) {
            return Response::json(400, malformed());
        }
        if let Some(Some(code)) = &body.offer {
            // A malformed code is an UNKNOWN one (§4.1): a registered code is always
            // well-formed, so this names nothing, and the answer is the poll route's 404, not
            // a 400 that would tell a prober which guesses were at least the right shape.
            if check_code(code).is_err() {
                return Response::error(404, ERR_EXPIRED_TOKEN);
            }
            let verdict = self.store.lock().expect("store lock").check_offer(
                code,
                (self.clock)(),
                &body.scope,
                body.valid_for,
            );
            if let Err(refusal) = verdict {
                return Self::offer_refusal(refusal);
            }
        }
        let browser = match keytext::decode_key(&body.browser) {
            Ok(b) => b,
            Err(_) => return Response::json(400, malformed()),
        };
        if body.valid_for == 0 {
            return Response::json(400, malformed());
        }
        // Checked at the door: the CLI prints these verbatim to a terminal, so an entry
        // carrying a control character could repaint the statement the person approves.
        for entry in &body.scope {
            if check_scope_entry(entry).is_err() {
                return Response::json(400, malformed());
            }
        }

        let mut id = vec![0u8; MIN_ENTROPY];
        let mut nonce = vec![0u8; MIN_ENTROPY];
        if (self.entropy)(&mut id).is_err() || (self.entropy)(&mut nonce).is_err() {
            return Response::json(500, malformed());
        }

        let now = (self.clock)();
        let record = Record {
            id: id.clone(),
            nonce: nonce.clone(),
            browser: browser.clone(),
            scope: body.scope.clone(),
            valid_for: body.valid_for,
            expires: now + self.ttl,
            answered: None,
            last_poll: None,
        };
        // A request that cannot produce a binding must not be handed out: the CLI would
        // fetch it, show it, and fail at signing time with nothing to explain.
        if login::binding(login::ROLE_LOGIN, &self.audience, &record.as_request()).is_err() {
            return Response::json(400, malformed());
        }

        let id_hex = Self::key(&id);
        let scope_json = serde_json::to_string(&body.scope).unwrap_or_else(|_| "[]".to_string());
        {
            let mut store = self.store.lock().expect("store lock");
            match &body.offer {
                // Store the request and take the offer together, re-checking under the lock:
                // the offer may have been taken, or died, while this request was built.
                Some(Some(code)) => {
                    if let Err(refusal) = store.take_offer(code, (self.clock)(), record) {
                        return Self::offer_refusal(refusal);
                    }
                }
                // Absent (a present null was refused above, before anything was built).
                _ => {
                    store.requests.insert(id_hex.clone(), record);
                }
            }
        }

        // The same body whether or not an offer was named: the offer is not echoed, so a
        // browser client needs one shape for begin (pinned as begin_on_offer in the fixture).
        Response::json(
            201,
            format!(
                "{{\"id\":\"{}\",\"nonce\":\"{}\",\"browser\":\"{}\",\"scope\":{},\
                 \"valid_for\":{},\"expires_in\":{},\"interval\":{},\"verification_uri\":\"{}\"}}",
                id_hex,
                to_hex(&nonce),
                body.browser,
                scope_json,
                body.valid_for,
                self.ttl,
                self.interval,
                format_args!("{}/login/{}", self.audience, id_hex),
            )
            .into_bytes(),
        )
    }

    /// §4.1's refusals for a request naming an offer, stated once because `begin` asks twice —
    /// before building the request and again when storing it.
    fn offer_refusal(refusal: OfferRefusal) -> Response {
        match refusal {
            OfferRefusal::Gone => Response::error(404, ERR_EXPIRED_TOKEN),
            OfferRefusal::Taken => Response::error(409, ERR_INVALID_REQUEST),
            OfferRefusal::Mismatch => Response::error(400, ERR_INVALID_REQUEST),
        }
    }

    /// Registers what a prover is willing to delegate, under a code the PROVER minted. The
    /// server draws no entropy here: the code is the prover's own, which is what lets the
    /// prover know it before anyone else does and print it on its own terminal (§4.1).
    ///
    /// Everything that would make the offer impossible to begin on is refused now, at the
    /// door, rather than at the page's begin — where the refusal would reach the page and not
    /// the person who typed the offer: a malformed code, a validity of zero, a scope entry the
    /// CLI could not display, and a scope that cannot bind at all.
    fn offer(&self, req: &Request) -> Response {
        let body: OfferBody = match parse_body(&req.body) {
            Ok(b) => b,
            Err(_) => return Response::json(400, malformed()),
        };
        if check_code(&body.code).is_err() || body.valid_for == 0 {
            return Response::json(400, malformed());
        }
        for entry in &body.scope {
            if check_scope_entry(entry).is_err() {
                return Response::json(400, malformed());
            }
        }
        // THE SCOPE MUST BIND. A binding needs a key and an id the offer does not have yet, so
        // the probe uses placeholders of the right size: what is being asked is only whether
        // THESE scope entries and THIS validity fit the binding's fields (§3.2), which no key
        // changes. An offer that passes here can always be begun on; one that failed would
        // have sat open until it expired, every begin on it refused for a reason the page
        // cannot see.
        let probe = login::Request {
            id: vec![0u8; MIN_ENTROPY],
            nonce: vec![0u8; MIN_ENTROPY],
            browser: vec![0u8; 32],
            scope: body.scope.clone(),
            valid_for: body.valid_for,
        };
        if login::binding(login::ROLE_LOGIN, &self.audience, &probe).is_err() {
            return Response::json(400, malformed());
        }

        let now = (self.clock)();
        let offer = Offer {
            code: body.code.clone(),
            scope: body.scope.clone(),
            valid_for: body.valid_for,
            expires: now + self.ttl,
            request: None,
        };
        {
            let mut store = self.store.lock().expect("store lock");
            // One code, one offer: a LIVE offer under this code already is a conflict. The
            // prover minted the code from 16 bytes of its own entropy, so this is a broken
            // prover or a replay, never a collision worth retrying silently. A dead offer
            // under the code is simply replaced — the code is free again.
            if store
                .offers
                .get(&body.code)
                .is_some_and(|live| store.offer_live(live, now))
            {
                return Response::error(409, ERR_INVALID_REQUEST);
            }
            store.offers.insert(body.code.clone(), offer);
        }

        let scope_json = serde_json::to_string(&body.scope).unwrap_or_else(|_| "[]".to_string());
        // The code rides in the fragment, which a browser keeps to itself: the page's script
        // reads it, no server and no log ever sees it (§4.1 "The code").
        let page = match &self.page {
            Some(page) => format!(
                ",\"page\":{}",
                serde_json::to_string(&format!("{page}#{}", body.code)).unwrap_or_default()
            ),
            None => String::new(),
        };
        Response::json(
            201,
            format!(
                "{{\"code\":\"{}\",\"scope\":{},\"valid_for\":{},\"expires_in\":{},\"interval\":{}{}}}",
                body.code, scope_json, body.valid_for, self.ttl, self.interval, page
            )
            .into_bytes(),
        )
    }

    /// Read once by the page — to learn what it is being offered — and polled by the prover
    /// until `request` names the request that took the offer (§4.1).
    ///
    /// There is deliberately NO pacing on this route (ADR 0007 §C.7, amendment #39). Two
    /// parties poll it, and one reference time would let the prover's period lock the page
    /// out on every retry; and there is nothing here to protect — no proof to verify, no
    /// answer to hand over. A stranger who holds the code already has everything this route
    /// returns. The prover paces itself by the `interval` the offer response advertised.
    ///
    /// A malformed code is `404`, the same as an unknown one: a registered code is always
    /// well-formed, so a malformed one is unknown by construction.
    fn read_offer(&self, code: &str) -> Response {
        if check_code(code).is_err() {
            return Response::error(404, ERR_EXPIRED_TOKEN);
        }
        let now = (self.clock)();
        let offer = self.store.lock().expect("store lock").live_offer(code, now);
        let Some(offer) = offer else {
            return Response::error(404, ERR_EXPIRED_TOKEN);
        };
        let scope_json = serde_json::to_string(&offer.scope).unwrap_or_else(|_| "[]".to_string());
        // null until taken, then the id — the shape a poller switches on.
        let request = match &offer.request {
            Some(id) => format!("\"{id}\""),
            None => "null".to_string(),
        };
        Response::json(
            200,
            format!(
                "{{\"code\":\"{}\",\"scope\":{},\"valid_for\":{},\"request\":{},\"expires\":\"{}\"}}",
                offer.code,
                scope_json,
                offer.valid_for,
                request,
                crate::rfc3339(offer.expires),
            )
            .into_bytes(),
        )
    }

    /// What the CLI fetches. It answers with the request and NOT with the audience: there is
    /// no audience field in this response by design, because a CLI that would read one is a
    /// CLI that can be told to sign for someone else (Finding 1).
    fn read(&self, id_hex: &str) -> Response {
        let now = (self.clock)();
        let mut store = self.store.lock().expect("store lock");
        let Some(record) = store.requests.get(id_hex) else {
            return Response::error(404, ERR_EXPIRED_TOKEN);
        };
        if now >= record.expires {
            store.requests.remove(id_hex);
            return Response::error(404, ERR_EXPIRED_TOKEN);
        }
        let scope_json = serde_json::to_string(&record.scope).unwrap_or_else(|_| "[]".to_string());
        Response::json(
            200,
            format!(
                "{{\"id\":\"{}\",\"nonce\":\"{}\",\"browser\":\"{}\",\"scope\":{},\
                 \"valid_for\":{},\"expires\":\"{}\"}}",
                id_hex,
                to_hex(&record.nonce),
                self.encode_browser(&record.browser),
                scope_json,
                record.valid_for,
                crate::rfc3339(record.expires),
            )
            .into_bytes(),
        )
    }

    /// Verifies BEFORE storing, which is the whole point of the route (§4).
    ///
    /// SNAPSHOT, VERIFY OUTSIDE THE LOCK, RE-LOCK TO STORE. `AdmitAuthority` is the SERVICE's
    /// code and may block on a database or a network; running it under the store's mutex
    /// would let one law decide the throughput of every login in the process. Verification is
    /// moved out for the same reason. Both are safe outside the lock because every field a
    /// binding is computed from is written once at begin and never mutated.
    ///
    /// What CAN change while unlocked is whether the request is still unanswered, so that
    /// check is REPEATED on re-lock: two CLIs answering one login is ordinary — a person with
    /// two terminals — and the second must get 409, not overwrite the first.
    fn answer(&self, req: &Request, id_hex: &str) -> Response {
        let body: AnswerBody = match parse_body(&req.body) {
            Ok(b) => b,
            Err(_) => return Response::json(400, malformed()),
        };
        let principal = match keytext::decode_key(&body.principal) {
            Ok(p) => p,
            Err(_) => return Response::json(400, malformed()),
        };
        let possession = match from_hex(&body.possession) {
            Ok(p) => p,
            Err(_) => return Response::json(400, malformed()),
        };

        let now = (self.clock)();
        let (request, browser, already) = {
            let mut store = self.store.lock().expect("store lock");
            let Some(record) = store.requests.get(id_hex) else {
                return Response::error(404, ERR_EXPIRED_TOKEN);
            };
            if now >= record.expires {
                store.requests.remove(id_hex);
                return Response::error(404, ERR_EXPIRED_TOKEN);
            }
            (
                record.as_request(),
                record.browser.clone(),
                record.answered.is_some(),
            )
        };
        if already {
            return Response::error(409, ERR_INVALID_REQUEST);
        }

        if !login::verify(&principal, &self.audience, &request, &possession) {
            return Response::error(403, ERR_INVALID_GRANT);
        }
        // `get()` is the source text as the CLI wrote it. Nothing here re-encodes it: it
        // reaches the law and the browser as the same bytes, or the tier is not opaque.
        let authority_raw = body.authority.as_ref().map(|raw| raw.get().to_string());
        if let Some(admit) = &self.admit {
            let payload = authority_raw.as_deref().unwrap_or("").as_bytes();
            if admit(&browser, &principal, payload).is_err() {
                return Response::error(403, ERR_INVALID_GRANT);
            }
        }

        let mut store = self.store.lock().expect("store lock");
        let Some(record) = store.requests.get_mut(id_hex) else {
            return Response::error(404, ERR_EXPIRED_TOKEN);
        };
        if (self.clock)() >= record.expires {
            store.requests.remove(id_hex);
            return Response::error(404, ERR_EXPIRED_TOKEN);
        }
        if record.answered.is_some() {
            // Another answer won while this one was being verified. Storing here would
            // discard a proof the browser may already have collected.
            return Response::error(409, ERR_INVALID_REQUEST);
        }
        record.answered = Some(Answer {
            principal: body.principal.clone(),
            possession: body.possession.clone(),
            authority: authority_raw,
        });
        Response::empty(204)
    }

    /// Hands the answer to the browser ONCE and drops the record.
    ///
    /// THE ORDER IS THE FIX caa FOUND: the interval is checked WITHOUT writing the timer, the
    /// proof is verified, and only then does the timer advance — inside the same critical
    /// section that takes the answer. Advancing it before verification let a stranger polling
    /// junk hold the real browser at 429 indefinitely, turning slow_down into a denial of
    /// service handed to anyone who saw the id.
    ///
    /// A stranger is therefore not rate-limited here at all. That is correct: they get 403
    /// every time, and §B says to add no rate limiting beyond slow_down, which exists for the
    /// legitimate client rather than as a guard.
    fn collect(&self, req: &Request, id_hex: &str) -> Response {
        let proof = match req.header(COLLECT_HEADER).map(from_hex) {
            Some(Ok(p)) if !p.is_empty() => p,
            _ => return Response::error(403, ERR_INVALID_GRANT),
        };

        let now = (self.clock)();
        let request = {
            let mut store = self.store.lock().expect("store lock");
            let Some(record) = store.requests.get(id_hex) else {
                return Response::error(404, ERR_EXPIRED_TOKEN);
            };
            if now >= record.expires {
                store.requests.remove(id_hex);
                return Response::error(404, ERR_EXPIRED_TOKEN);
            }
            if let Some(last) = record.last_poll {
                if now.saturating_sub(last) < self.interval {
                    return Response::error(429, ERR_SLOW_DOWN);
                }
            }
            record.as_request()
        };

        if !login::verify_collect(&self.audience, &request, &proof) {
            return Response::error(403, ERR_INVALID_GRANT);
        }

        // ONE critical section: advance the timer, and take-and-drop if an answer is waiting.
        // Taking the payload and removing separately would leave a window in which a second
        // proven collector reads the same answer, and §4 says the record is handed over ONCE.
        let mut store = self.store.lock().expect("store lock");
        let Some(record) = store.requests.get_mut(id_hex) else {
            return Response::error(404, ERR_EXPIRED_TOKEN);
        };
        if (self.clock)() >= record.expires {
            store.requests.remove(id_hex);
            return Response::error(404, ERR_EXPIRED_TOKEN);
        }
        record.last_poll = Some(now);
        let Some(answer) = record.answered.clone() else {
            return Response::error(202, ERR_PENDING);
        };
        store.requests.remove(id_hex);
        drop(store);

        let authority = match &answer.authority {
            Some(raw) => format!(",\"authority\":{raw}"),
            None => String::new(),
        };
        Response::json(
            200,
            format!(
                "{{\"principal\":\"{}\",\"possession\":\"{}\"{}}}",
                answer.principal, answer.possession, authority
            )
            .into_bytes(),
        )
    }
}
