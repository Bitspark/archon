// archon core — the identity floor in C++.
//
// Ed25519 key bytes, one canonical text spelling, the SPKI/PKCS-8 codecs, and
// domain-separated signing. Two questions and no others: are these bytes that key, and is
// this signature that key's. Authority and custody belong to their own layers.
//
// Like the other cores this binds an existing Ed25519 and writes none of its own curve
// arithmetic. The binding is OpenSSL, which reaches Ed25519ph with a context through
// signature-operation parameters ("instance" and "context-string") on an ordinary Ed25519
// key. OpenSSL 3.2 or later is required: earlier releases have no such parameter, and the
// construction cannot be expressed without it.
//
// ⚠ A NOTE ON WHAT THIS CORE'S CONFORMANCE PROVES. archon's domain vectors were themselves
// derived with OpenSSL 3.2.4 (`pkeyutl -rawin -pkeyopt instance:Ed25519ph -pkeyopt
// context-string:<domain>`). So this core agreeing with the oracle on the domain families is
// partly OpenSSL agreeing with itself, and is weaker evidence than the Go, Rust, TypeScript,
// Python and Java cores, each of which binds an implementation the vectors did not come from.
// The non-domain families — the codecs, the key text, the hex spellings — are archon's own
// encodings and are tested as strongly here as anywhere.

#ifndef ARCHON_CORE_HPP
#define ARCHON_CORE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace archon {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::size_t kPublicKeySize = 32;
inline constexpr std::size_t kSignatureSize = 64;
inline constexpr std::size_t kSeedSize = 32;

/// The longest domain (RFC 8032 context) a signature can be made in, in bytes.
inline constexpr std::size_t kMaxDomainSize = 255;

// --- crypto ---------------------------------------------------------------------------
//
// Signing returns std::nullopt rather than throwing on a refusal — an empty or over-long
// domain, a wrong-sized seed. Verification is total: every shape failure is `false`, so a
// caller cannot mistake malformed for valid.

/// The 32-byte public key for `seed`, or nullopt when the seed is not 32 bytes.
/// Whether the OpenSSL and libsodium this process LOADED meet archon's floors (OpenSSL >= 3.2,
/// libsodium >= 1.0.21). When they do not, every function below refuses: signing nothing and
/// accepting nothing is the only safe behaviour for a core that cannot enforce its profile.
bool libraries_meet_floors();

std::optional<Bytes> public_key_from_seed(const Bytes& seed);

/// A raw Ed25519 signature over `message`.
std::optional<Bytes> sign(const Bytes& seed, const Bytes& message);

/// True when `signature` is `pubkey`'s over `message`.
bool verify(const Bytes& pubkey, const Bytes& message, const Bytes& signature);

/// Signs `message` in `domain` — Ed25519ph with the domain as the RFC 8032 context.
/// Never silently signs raw: an empty domain, or one over 255 bytes, is nullopt.
std::optional<Bytes> sign_in_domain(const Bytes& seed, std::string_view domain,
                                    const Bytes& message);

/// True when `signature` is `pubkey`'s over `message` IN `domain`.
bool verify_in_domain(const Bytes& pubkey, std::string_view domain, const Bytes& message,
                      const Bytes& signature);

// --- hexbytes -------------------------------------------------------------------------
//
// Not a hex helper — every language has one — but the FIXED SIZE. The length is checked on
// the TEXT before any byte is decoded. Either case in, lowercase out.

std::string to_hex(const Bytes& data);
std::optional<Bytes> seed_from_hex(std::string_view text);
std::optional<Bytes> pubkey_from_hex(std::string_view text);
std::optional<Bytes> signature_from_hex(std::string_view text);

// --- keytext --------------------------------------------------------------------------

/// `ed25519:` followed by the key as lowercase hex.
std::string encode_key(const Bytes& pubkey);

/// The 32 key bytes, or nullopt — missing prefix, odd length, non-hex, wrong size.
std::optional<Bytes> decode_key(std::string_view text);

// --- keycodec -------------------------------------------------------------------------
//
// A byte codec, not an ASN.1 parser: for an Ed25519 key the DER is fixed-length and
// fixed-shape, so this is a template match. A general parser would accept encodings the
// other cores would not, and agreement is the claim.

std::optional<std::string> pubkey_to_spki_pem(const Bytes& pubkey);
std::optional<std::string> seed_to_pkcs8_pem(const Bytes& seed);
std::optional<Bytes> spki_pem_to_pubkey(std::string_view pem);
std::optional<Bytes> pkcs8_pem_to_seed(std::string_view pem);

}  // namespace archon

#endif  // ARCHON_CORE_HPP
