// archon-sdk — one layer above the identity floor.
//
// @bitspark/archon answers "is this really them?" over bytes. This package answers the
// two questions every protocol asks next, without knowing the protocol:
//
// - possession — can they sign, right now, for this channel? Challenge/response; the
//   binding is what makes it a proof, so an empty one is refused.
// - envelope — these bytes, signed by this key, in this domain. JWS, never JWT.
//
// The rule that keeps this layer honest: entropy, time and channel binding are
// ARGUMENTS. This package never sources them. That is what lets every byte it emits be a
// deterministic function of its inputs and be pinned by vectors/sdk.json across three
// languages — the same way the floor is pinned. Connection setup is not here and never
// will be: that is the transport's (ADR 0004).
export * from "./possession.js";
export * from "./envelope.js";
export * from "./login.js";
export * from "./login-audience.js";
