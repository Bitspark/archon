// What an outside consumer of the archon C++ package must be able to do.
//
// This builds against the INSTALLED package, not the source tree. Passing the oracle proves
// the code; it says nothing about whether the package is right — a missing include
// directory, or a config that forgets to re-find libsodium, fails here and nowhere else.
//
// Two claims, the same two every archon consumer asserts in every language:
//
//   1. Domain separation holds — a signature verifies in its domain, in no other, and never
//      as a raw signature.
//   2. The ADR 0008 profile is enforced, on the pair that is load-bearing in EVERY language:
//      profile-mixed-order-A-k-divisible and profile-identity-R, oracle bytes verbatim.
//      Every implementation measured before 0008 accepted both, so nothing but archon's own
//      check can refuse them. For this core that check is libsodium's
//      crypto_core_ed25519_is_valid_point, which OpenSSL cannot express at all.

#include <archon/core.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

// The package's own size-checked parsers, not a hand-rolled one: they are part of the
// surface a consumer gets, so using them here exercises more of what was installed.
archon::Bytes as_pubkey(const char* text) {
  auto value = archon::pubkey_from_hex(text);
  if (!value) { std::fprintf(stderr, "bad pubkey hex\n"); std::exit(1); }
  return *value;
}

archon::Bytes as_signature(const char* text) {
  auto value = archon::signature_from_hex(text);
  if (!value) { std::fprintf(stderr, "bad signature hex\n"); std::exit(1); }
  return *value;
}

// Messages are arbitrary length, so the package's fixed-size parsers do not apply here.
archon::Bytes raw_hex(const char* text) {
  const std::string value{text};
  archon::Bytes out;
  out.reserve(value.size() / 2);
  for (std::size_t i = 0; i + 1 < value.size(); i += 2) {
    out.push_back(static_cast<unsigned char>(std::stoul(value.substr(i, 2), nullptr, 16)));
  }
  return out;
}

void check(bool condition, const char* what) {
  if (!condition) {
    std::fprintf(stderr, "consumer assertion failed: %s\n", what);
    std::exit(1);
  }
}

// ADR 0008 class 4: A = A_good + T8, order 8L. k is divisible by 8, so BOTH the cofactored
// and uncofactored equations hold — every core that merely decodes the point accepts it.
const char* kMixedOrderA =
    "05edb8c261651304ea335a4397e0696b9fb37c99aa8023ee1583a2f3e43d9fe4";
const char* kMixedOrderMessage = "6d697865642d6f72646572233133";
const char* kMixedOrderSig =
    "b862409fb5c4c4123df2abf7462b88f041ad36dd6864ce872fd5472be363c5b1"
    "20e561d759891b93dd85ac31f464fc01adb9d3d89074eaa7795084f43661a90b";

const char* kHonestA = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

// ADR 0008 class 5: R is the identity point and S = k·a, so the equation holds under every
// formulation. RFC 8032 pure verification accepts it; no honest signer produces it.
const char* kIdentityRSig =
    "0100000000000000000000000000000000000000000000000000000000000000"
    "04201a21f9221727c221b35265ca6248968a426e9fb5168e368d7dcdaa05fa07";

}  // namespace

int main() {
  // First, and not optional: the vectors below cannot see a libsodium below 1.0.21. That version
  // refuses the 8L mixed-order key asserted below and accepts only a 2L one, so this consumer
  // would pass against it. The core's own floor check is what reports that combination.
  check(archon::libraries_meet_floors(),
        "the loaded OpenSSL and libsodium must meet archon's floors");

  archon::Bytes seed(32);
  for (int i = 0; i < 32; ++i) seed[i] = static_cast<unsigned char>(i);

  auto pubkey = archon::public_key_from_seed(seed);
  check(pubkey.has_value(), "the package must derive a public key");

  const std::string domain = "archon/test/v1";
  archon::Bytes message{'h', 'e', 'l', 'l', 'o'};

  auto signature = archon::sign_in_domain(seed, domain, message);
  check(signature.has_value(), "the package must sign in a domain");
  check(archon::verify_in_domain(*pubkey, domain, message, *signature),
        "a domain signature must verify in its own domain");
  check(!archon::verify_in_domain(*pubkey, "archon/test/v2", message, *signature),
        "a domain signature must not verify in another domain");
  check(!archon::verify(*pubkey, message, *signature),
        "a domain signature must never verify as a raw signature");

  auto raw = archon::sign(seed, message);
  check(raw.has_value() && archon::verify(*pubkey, message, *raw),
        "a raw signature must verify raw");
  check(!archon::verify_in_domain(*pubkey, domain, message, *raw),
        "a raw signature must not verify in any domain");

  check(!archon::verify(as_pubkey(kMixedOrderA), raw_hex(kMixedOrderMessage), as_signature(kMixedOrderSig)),
        "a mixed-order public key must be refused, though both equations hold");
  check(!archon::verify_in_domain(as_pubkey(kMixedOrderA), domain, raw_hex(kMixedOrderMessage),
                                  as_signature(kMixedOrderSig)),
        "a mixed-order public key must be refused in a domain too");
  check(!archon::verify(as_pubkey(kHonestA), message, as_signature(kIdentityRSig)),
        "an identity R must be refused, though RFC 8032 pure verification accepts it");

  auto text = archon::encode_key(*pubkey);
  auto back = archon::decode_key(text);
  check(back.has_value() && *back == *pubkey, "the canonical key text must round trip");

  std::printf("consumer ok: %s\n", text.c_str());
  return 0;
}
