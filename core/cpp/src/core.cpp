#include "archon/core.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

namespace archon {
namespace {

// ADR 0008's point predicate, in one call.
//
// OpenSSL cannot express it. EVP_PKEY_public_check validates NOTHING for Ed25519 -- measured,
// it accepts all eight profile classes -- and OpenSSL exposes no scalar multiplication for
// the curve, so [L]P = O cannot be computed through its public API. That is why this core
// binds a second library: OpenSSL signs (it is the only one here with Ed25519ph plus a
// context string), libsodium decides what is acceptable.
//
// crypto_core_ed25519_is_valid_point checks, in one call, that the encoding is canonical,
// the point is on the curve, it is not of small order, and it lies in the prime-order
// subgroup. That is the whole of the profile for a point.
//
// It REQUIRES libsodium >= 1.0.21. In 1.0.20 and earlier this same function accepted some
// points in mixed-order subgroups. Measured against the oracle's four mixed-order public keys:
// 1.0.20 refuses the 8L and 4L ones and ACCEPTS profile-mixed-order-A-torsion-2-k-divisible,
// a point of order 2L. A core built against 1.0.20 compiles, links, signs correctly, passes 104
// of 105 cases, and silently ships the one defect the profile exists to forbid. The outside
// consumers' shared pair would NOT notice -- it uses the 8L point -- so the floor is asserted
// by CMake at configure time, by the #errors below, and against the loaded library at runtime.
#if OPENSSL_VERSION_NUMBER < 0x30200000L
#error "archon needs OpenSSL >= 3.2: Ed25519ph with a context string is unreachable below it"
#endif
#if SODIUM_LIBRARY_VERSION_MAJOR < 26 || \
    (SODIUM_LIBRARY_VERSION_MAJOR == 26 && SODIUM_LIBRARY_VERSION_MINOR < 3)
#error "archon needs libsodium >= 1.0.21 (library 26.3): older versions accept mixed-order points"
#endif

// The floors again, against what was actually LOADED. CMakeLists.txt and the #errors above
// see the headers this file was compiled against; a shared library is resolved when the process
// starts. libsodium 1.0.20 and 1.0.22 share the soname libsodium.so.26, so a core built against
// 1.0.22 will run against a 1.0.20 that a package manager left on the library path -- and would
// then accept mixed-order keys while every build-time check stayed green. Demonstrated rather
// than supposed; see docs/languages.md. A process below the floors signs nothing and accepts
// nothing. Measured from the release tarballs: 1.0.20 is library 26.2, 1.0.21 is 26.3.
bool loaded_libraries_ok() {
  static const bool ok = [] {
    if (sodium_init() < 0) return false;
    const int major = sodium_library_version_major();
    const int minor = sodium_library_version_minor();
    if (!(major > 26 || (major == 26 && minor >= 3))) return false;
    return OpenSSL_version_num() >= 0x30200000L;
  }();
  return ok;
}

bool point_acceptable(const unsigned char* point) {
  return crypto_core_ed25519_is_valid_point(point) == 1;
}

// RAII for the OpenSSL handles. Every exit path here is an early return on refusal, and a
// leaked EVP_PKEY on each one is how a long-lived verifier grows without anyone noticing.
struct PkeyDeleter {
  void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct MdCtxDeleter {
  void operator()(EVP_MD_CTX* c) const noexcept { EVP_MD_CTX_free(c); }
};
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using MdCtx = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

constexpr std::array<std::uint8_t, 12> kSpkiPrefix = {
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00};
constexpr std::array<std::uint8_t, 16> kPkcs8Prefix = {
    0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};

constexpr const char* kPemPublic = "PUBLIC KEY";
constexpr const char* kPemPrivate = "PRIVATE KEY";

/// The domain as context bytes, bounds-checked. The bound is on BYTES, not characters — the
/// other cores measure it the same way.
bool domain_ok(std::string_view domain) {
  return !domain.empty() && domain.size() <= kMaxDomainSize;
}

Pkey private_key(const Bytes& seed) {
  if (seed.size() != kSeedSize) return nullptr;
  return Pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size())};
}

Pkey public_key(const Bytes& pubkey) {
  if (pubkey.size() != kPublicKeySize) return nullptr;
  return Pkey{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size())};
}

/// Ed25519ph with a context, expressed the way OpenSSL 3.2+ reaches it: signature-operation
/// parameters on an ordinary Ed25519 key. There is no separate "Ed25519ph key" and no
/// dedicated OID — asking for one is the usual wrong turn here.
std::array<OSSL_PARAM, 3> ph_params(std::string_view domain, char* instance_buf) {
  std::strcpy(instance_buf, "Ed25519ph");
  return {
      OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, instance_buf, 0),
      OSSL_PARAM_construct_octet_string(
          OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
          const_cast<char*>(domain.data()), domain.size()),
      OSSL_PARAM_construct_end(),
  };
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::optional<Bytes> fixed_from_hex(std::string_view text, std::size_t n) {
  if (text.size() != n * 2) return std::nullopt;
  Bytes out(n);
  for (std::size_t i = 0; i < n; ++i) {
    int hi = hex_digit(text[2 * i]);
    int lo = hex_digit(text[2 * i + 1]);
    if (hi < 0 || lo < 0) return std::nullopt;
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return out;
}

std::string base64_encode(const std::uint8_t* data, std::size_t len) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  for (std::size_t i = 0; i < len; i += 3) {
    std::uint32_t chunk = static_cast<std::uint32_t>(data[i]) << 16;
    if (i + 1 < len) chunk |= static_cast<std::uint32_t>(data[i + 1]) << 8;
    if (i + 2 < len) chunk |= static_cast<std::uint32_t>(data[i + 2]);
    out.push_back(kAlphabet[(chunk >> 18) & 0x3F]);
    out.push_back(kAlphabet[(chunk >> 12) & 0x3F]);
    out.push_back(i + 1 < len ? kAlphabet[(chunk >> 6) & 0x3F] : '=');
    out.push_back(i + 2 < len ? kAlphabet[chunk & 0x3F] : '=');
  }
  return out;
}

/// Strict base64: any character outside the alphabet is a refusal, not something to skip.
/// A lenient decoder would accept PEM bodies the other cores reject.
std::optional<Bytes> base64_decode(std::string_view text) {
  auto value = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
  };
  if (text.size() % 4 != 0 || text.empty()) return std::nullopt;
  std::size_t padding = 0;
  while (padding < 2 && text.size() > padding && text[text.size() - 1 - padding] == '=') ++padding;
  Bytes out;
  out.reserve(text.size() / 4 * 3);
  for (std::size_t i = 0; i < text.size(); i += 4) {
    std::uint32_t chunk = 0;
    for (std::size_t j = 0; j < 4; ++j) {
      char c = text[i + j];
      if (c == '=') {
        if (i + 4 < text.size()) return std::nullopt;  // padding only at the very end
        chunk <<= 6;
        continue;
      }
      int v = value(c);
      if (v < 0) return std::nullopt;
      chunk = (chunk << 6) | static_cast<std::uint32_t>(v);
    }
    out.push_back(static_cast<std::uint8_t>((chunk >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((chunk >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(chunk & 0xFF));
  }
  out.resize(out.size() - padding);
  return out;
}

std::optional<std::string> pem_encode(const Bytes& key, const std::uint8_t* prefix,
                                      std::size_t prefix_len, const char* pem_type) {
  if (key.size() != kPublicKeySize) return std::nullopt;
  Bytes der(prefix, prefix + prefix_len);
  der.insert(der.end(), key.begin(), key.end());
  std::string body = base64_encode(der.data(), der.size());
  return std::string("-----BEGIN ") + pem_type + "-----\n" + body + "\n-----END " + pem_type +
         "-----\n";
}

std::optional<Bytes> pem_decode(std::string_view pem, const std::uint8_t* prefix,
                                std::size_t prefix_len, const char* pem_type) {
  std::string text(pem);
  // CRLF is accepted; the other cores accept it too.
  std::string normalised;
  normalised.reserve(text.size());
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n') continue;
    normalised.push_back(text[i]);
  }
  while (!normalised.empty() && normalised.back() == '\n') normalised.pop_back();

  std::string begin = std::string("-----BEGIN ") + pem_type + "-----";
  std::string end = std::string("-----END ") + pem_type + "-----";

  std::vector<std::string> lines;
  std::size_t start = 0;
  for (std::size_t i = 0; i <= normalised.size(); ++i) {
    if (i == normalised.size() || normalised[i] == '\n') {
      lines.push_back(normalised.substr(start, i - start));
      start = i + 1;
    }
  }
  if (lines.size() < 3 || lines.front() != begin || lines.back() != end) return std::nullopt;

  std::string body;
  for (std::size_t i = 1; i + 1 < lines.size(); ++i) body += lines[i];
  auto der = base64_decode(body);
  if (!der) return std::nullopt;
  if (der->size() != prefix_len + kPublicKeySize) return std::nullopt;
  if (!std::equal(prefix, prefix + prefix_len, der->begin())) return std::nullopt;
  return Bytes(der->begin() + static_cast<std::ptrdiff_t>(prefix_len), der->end());
}

}  // namespace

// --- crypto ---------------------------------------------------------------------------

bool libraries_meet_floors() { return loaded_libraries_ok(); }

std::optional<Bytes> public_key_from_seed(const Bytes& seed) {
  if (!loaded_libraries_ok()) return std::nullopt;
  Pkey key = private_key(seed);
  if (!key) return std::nullopt;
  Bytes out(kPublicKeySize);
  std::size_t len = out.size();
  if (EVP_PKEY_get_raw_public_key(key.get(), out.data(), &len) != 1 || len != kPublicKeySize) {
    return std::nullopt;
  }
  return out;
}

std::optional<Bytes> sign(const Bytes& seed, const Bytes& message) {
  if (!loaded_libraries_ok()) return std::nullopt;
  Pkey key = private_key(seed);
  if (!key) return std::nullopt;
  MdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) return std::nullopt;
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    return std::nullopt;
  }
  Bytes sig(kSignatureSize);
  std::size_t len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1) {
    return std::nullopt;
  }
  sig.resize(len);
  return sig;
}

bool verify(const Bytes& pubkey, const Bytes& message, const Bytes& signature) {
  if (!loaded_libraries_ok()) return false;
  if (pubkey.size() != kPublicKeySize || signature.size() != kSignatureSize) return false;
  // The profile decides BEFORE the equation does, so the accepted set is archon's rather
  // than the binding library's. R is sig[0..32]: a verifier that checks only the public key
  // accepts an identity or small-order R, which no honest signer produces.
  if (!point_acceptable(pubkey.data()) || !point_acceptable(signature.data())) return false;
  Pkey key = public_key(pubkey);
  if (!key) return false;
  MdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) return false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) return false;
  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(),
                          message.size()) == 1;
}

std::optional<Bytes> sign_in_domain(const Bytes& seed, std::string_view domain,
                                    const Bytes& message) {
  if (!loaded_libraries_ok()) return std::nullopt;
  if (!domain_ok(domain)) return std::nullopt;
  Pkey key = private_key(seed);
  if (!key) return std::nullopt;
  MdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) return std::nullopt;

  char instance[16];
  auto params = ph_params(domain, instance);
  if (EVP_DigestSignInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr, key.get(),
                            params.data()) != 1) {
    return std::nullopt;
  }
  Bytes sig(kSignatureSize);
  std::size_t len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1) {
    return std::nullopt;
  }
  sig.resize(len);
  return sig;
}

bool verify_in_domain(const Bytes& pubkey, std::string_view domain, const Bytes& message,
                      const Bytes& signature) {
  if (!loaded_libraries_ok()) return false;
  if (pubkey.size() != kPublicKeySize || signature.size() != kSignatureSize) return false;
  // The profile decides BEFORE the equation does, so the accepted set is archon's rather
  // than the binding library's. R is sig[0..32]: a verifier that checks only the public key
  // accepts an identity or small-order R, which no honest signer produces.
  if (!point_acceptable(pubkey.data()) || !point_acceptable(signature.data())) return false;
  if (!domain_ok(domain)) return false;
  Pkey key = public_key(pubkey);
  if (!key) return false;
  MdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) return false;

  char instance[16];
  auto params = ph_params(domain, instance);
  if (EVP_DigestVerifyInit_ex(ctx.get(), nullptr, nullptr, nullptr, nullptr, key.get(),
                              params.data()) != 1) {
    return false;
  }
  return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(),
                          message.size()) == 1;
}

// --- hexbytes -------------------------------------------------------------------------

std::string to_hex(const Bytes& data) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (std::uint8_t b : data) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0x0F]);
  }
  return out;
}

std::optional<Bytes> seed_from_hex(std::string_view text) {
  return fixed_from_hex(text, kSeedSize);
}
std::optional<Bytes> pubkey_from_hex(std::string_view text) {
  return fixed_from_hex(text, kPublicKeySize);
}
std::optional<Bytes> signature_from_hex(std::string_view text) {
  return fixed_from_hex(text, kSignatureSize);
}

// --- keytext --------------------------------------------------------------------------

std::string encode_key(const Bytes& pubkey) { return "ed25519:" + to_hex(pubkey); }

std::optional<Bytes> decode_key(std::string_view text) {
  constexpr std::string_view kPrefix = "ed25519:";
  if (text.size() < kPrefix.size() || text.substr(0, kPrefix.size()) != kPrefix) {
    return std::nullopt;
  }
  std::string_view body = text.substr(kPrefix.size());
  if (body.size() % 2 != 0) return std::nullopt;
  return fixed_from_hex(body, kPublicKeySize);
}

// --- keycodec -------------------------------------------------------------------------

std::optional<std::string> pubkey_to_spki_pem(const Bytes& pubkey) {
  return pem_encode(pubkey, kSpkiPrefix.data(), kSpkiPrefix.size(), kPemPublic);
}
std::optional<std::string> seed_to_pkcs8_pem(const Bytes& seed) {
  return pem_encode(seed, kPkcs8Prefix.data(), kPkcs8Prefix.size(), kPemPrivate);
}
std::optional<Bytes> spki_pem_to_pubkey(std::string_view pem) {
  return pem_decode(pem, kSpkiPrefix.data(), kSpkiPrefix.size(), kPemPublic);
}
std::optional<Bytes> pkcs8_pem_to_seed(std::string_view pem) {
  return pem_decode(pem, kPkcs8Prefix.data(), kPkcs8Prefix.size(), kPemPrivate);
}

}  // namespace archon
