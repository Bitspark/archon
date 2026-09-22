/*
 * archon's crypto shim. See archon_crypto.h for why it exists and what it may contain.
 */
#include "archon_crypto.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#include <sodium.h>

/*
 * The two floors, asserted where the compiler can see them.
 *
 * OpenSSL 3.2 is where OSSL_SIGNATURE_PARAM_INSTANCE and CONTEXT_STRING reach Ed25519ph; below
 * it there is no way to sign in a domain at all.
 *
 * libsodium 1.0.21 is where crypto_core_ed25519_is_valid_point stopped accepting some points
 * in mixed-order subgroups. Measured from the release tarballs' configure.ac: 1.0.20 is library
 * version 26.2, 1.0.21 is 26.3, 1.0.22 is 26.4. And measured against the oracle's four
 * mixed-order public keys: 1.0.20 refuses the 8L and 4L ones and ACCEPTS
 * profile-mixed-order-A-torsion-2-k-divisible, a point of order 2L. A shim built against 26.2
 * would compile, sign correctly, pass 104 of 105 vectors, and accept that key. Note what does
 * NOT catch it: the outside consumers' shared pair uses the 8L point, which 1.0.20 refuses. The
 * oracle's torsion-2 case does, and so do these floors.
 *
 * SwiftPM's system-library targets cannot express a version at all, so for Swift these two
 * #errors ARE the configure-time check. Cabal additionally enforces them through
 * pkgconfig-depends.
 */
#if OPENSSL_VERSION_NUMBER < 0x30200000L
#error "archon needs OpenSSL >= 3.2: Ed25519ph with a context string is unreachable below it"
#endif

#if SODIUM_LIBRARY_VERSION_MAJOR < 26 || \
    (SODIUM_LIBRARY_VERSION_MAJOR == 26 && SODIUM_LIBRARY_VERSION_MINOR < 3)
#error "archon needs libsodium >= 1.0.21 (library 26.3): older versions accept mixed-order points"
#endif

/*
 * ...and asserted AGAIN against what was actually loaded. The checks above see the headers
 * this file was compiled against; a shared library is resolved when the process starts, and a
 * binary built against libsodium 1.0.22 will run happily against a 1.0.20 that a package
 * manager put on the library path. That combination passes CI and fails in the field. So a
 * process whose loaded libraries are below the floors signs nothing and accepts nothing.
 *
 * The result is cached. Computing it twice under a race is harmless -- both threads compute
 * the same answer, and sodium_init is itself safe to call concurrently.
 */
static int libraries_checked = 0;
static int libraries_ok_value = 0;

int archon_libraries_ok(void) {
  if (!libraries_checked) {
    int ok = sodium_init() >= 0;
    int major = sodium_library_version_major();
    int minor = sodium_library_version_minor();
    ok = ok && (major > 26 || (major == 26 && minor >= 3));
    ok = ok && OpenSSL_version_num() >= 0x30200000L;
    libraries_ok_value = ok;
    libraries_checked = 1;
  }
  return libraries_ok_value;
}

/*
 * ADR 0008's point predicate, and the reason libsodium is linked at all.
 *
 * OpenSSL cannot express it: EVP_PKEY_public_check validates NOTHING for Ed25519 -- measured,
 * it accepts all eight profile classes -- and there is no public scalar multiplication for
 * the curve, so [L]P = O cannot be computed through its API. crypto_core_ed25519_is_valid_point
 * checks, in one call, that the encoding is canonical, the point is on the curve, it is not of
 * small order, and it lies in the prime-order subgroup.
 */
static int point_acceptable(const uint8_t *point) {
  return crypto_core_ed25519_is_valid_point(point) == 1;
}

/* An empty message may arrive as a NULL pointer from either host language. OpenSSL accepts
 * (NULL, 0) for one-shot operations, but not every build is equally sure of it, so an empty
 * message is always passed as a real, zero-length buffer. */
static const uint8_t empty_message[1] = {0};

static const uint8_t *message_or_empty(const uint8_t *message, size_t message_len) {
  return (message_len == 0 || message == NULL) ? empty_message : message;
}

static int domain_ok(const uint8_t *domain, size_t domain_len) {
  return domain != NULL && domain_len >= 1 && domain_len <= ARCHON_MAX_DOMAIN_SIZE;
}

static EVP_PKEY *private_key(const uint8_t *seed) {
  return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, ARCHON_SEED_SIZE);
}

static EVP_PKEY *public_key(const uint8_t *public_key_bytes) {
  return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key_bytes,
                                     ARCHON_PUBLIC_KEY_SIZE);
}

/* Ed25519ph with a context is expressed the way OpenSSL 3.2+ reaches it: parameters on an
 * ordinary Ed25519 key. There is no separate "Ed25519ph key" and no dedicated OID. */
static void ph_params(OSSL_PARAM params[3], char *instance, const uint8_t *domain,
                      size_t domain_len) {
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_INSTANCE, instance, 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                                (void *)domain, domain_len);
  params[2] = OSSL_PARAM_construct_end();
}

int archon_public_key_from_seed(const uint8_t *seed, uint8_t *out_public_key) {
  if (!archon_libraries_ok()) return 0;
  EVP_PKEY *key = private_key(seed);
  if (key == NULL) return 0;
  size_t len = ARCHON_PUBLIC_KEY_SIZE;
  int ok = EVP_PKEY_get_raw_public_key(key, out_public_key, &len) == 1 &&
           len == ARCHON_PUBLIC_KEY_SIZE;
  EVP_PKEY_free(key);
  return ok;
}

/* One-shot sign. `params` is NULL for raw Ed25519 and the ph parameters for a domain. */
static int sign_with(const uint8_t *seed, const OSSL_PARAM *params, const uint8_t *message,
                     size_t message_len, uint8_t *out_signature) {
  EVP_PKEY *key = private_key(seed);
  if (key == NULL) return 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = 0;
  if (ctx != NULL &&
      EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, params) == 1) {
    size_t len = ARCHON_SIGNATURE_SIZE;
    ok = EVP_DigestSign(ctx, out_signature, &len, message_or_empty(message, message_len),
                        message_len) == 1 &&
         len == ARCHON_SIGNATURE_SIZE;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

/* One-shot verify, with the profile deciding BEFORE the equation does -- so the accepted set is
 * archon's rather than OpenSSL's. R is signature[0..32]: a verifier that checks only the public
 * key accepts an identity or small-order R, which no honest signer produces. */
static int verify_with(const uint8_t *public_key_bytes, const OSSL_PARAM *params,
                       const uint8_t *message, size_t message_len, const uint8_t *signature) {
  if (!point_acceptable(public_key_bytes) || !point_acceptable(signature)) return 0;
  EVP_PKEY *key = public_key(public_key_bytes);
  if (key == NULL) return 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = 0;
  if (ctx != NULL &&
      EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, params) == 1) {
    ok = EVP_DigestVerify(ctx, signature, ARCHON_SIGNATURE_SIZE,
                          message_or_empty(message, message_len), message_len) == 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

int archon_sign(const uint8_t *seed, const uint8_t *message, size_t message_len,
                uint8_t *out_signature) {
  if (!archon_libraries_ok()) return 0;
  return sign_with(seed, NULL, message, message_len, out_signature);
}

int archon_verify(const uint8_t *public_key_bytes, const uint8_t *message, size_t message_len,
                  const uint8_t *signature) {
  if (!archon_libraries_ok()) return 0;
  return verify_with(public_key_bytes, NULL, message, message_len, signature);
}

int archon_sign_in_domain(const uint8_t *seed, const uint8_t *domain, size_t domain_len,
                          const uint8_t *message, size_t message_len, uint8_t *out_signature) {
  if (!archon_libraries_ok() || !domain_ok(domain, domain_len)) return 0;
  char instance[] = "Ed25519ph";
  OSSL_PARAM params[3];
  ph_params(params, instance, domain, domain_len);
  return sign_with(seed, params, message, message_len, out_signature);
}

int archon_verify_in_domain(const uint8_t *public_key_bytes, const uint8_t *domain,
                            size_t domain_len, const uint8_t *message, size_t message_len,
                            const uint8_t *signature) {
  if (!archon_libraries_ok() || !domain_ok(domain, domain_len)) return 0;
  char instance[] = "Ed25519ph";
  OSSL_PARAM params[3];
  ph_params(params, instance, domain, domain_len);
  return verify_with(public_key_bytes, params, message, message_len, signature);
}
