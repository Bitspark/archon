/*
 * archon's crypto shim, shared byte-for-byte by the Swift and Haskell cores.
 *
 * It exists for ONE reason: OpenSSL reaches Ed25519ph-with-context only through
 * signature-operation parameters, and OSSL_PARAM_construct_* return structs BY VALUE, which
 * Haskell's FFI cannot express. So the calls that touch OpenSSL and libsodium live here, and
 * everything archon defines for itself -- hex, the canonical key text, the SPKI/PKCS-8 codec --
 * stays native in each host language.
 *
 * Nothing here is curve arithmetic. Signing and the verification equation are OpenSSL's; the
 * ADR 0008 point predicate is libsodium's. This file only marshals arguments.
 *
 * The same file is compiled by SwiftPM (core/swift/Sources/CArchonCrypto) and by Cabal
 * (core/hs/cbits). CI asserts the two copies are identical: two shims that drift apart are
 * two opinions about what archon accepts, and the oracle would catch it only if a vector
 * happened to sit on the difference.
 *
 * Every function returns 1 for success / valid and 0 otherwise. Sizes are the caller's to
 * check; the host languages do so with fixed-size arrays before calling in.
 */
#ifndef ARCHON_CRYPTO_H
#define ARCHON_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define ARCHON_SEED_SIZE 32
#define ARCHON_PUBLIC_KEY_SIZE 32
#define ARCHON_SIGNATURE_SIZE 64
#define ARCHON_MAX_DOMAIN_SIZE 255

#ifdef __cplusplus
extern "C" {
#endif

/* 1 when the libraries this process actually LOADED meet archon's floors. See the .c file:
 * a check at build time cannot see a shared library swapped underneath the binary. */
int archon_libraries_ok(void);

int archon_public_key_from_seed(const uint8_t *seed, uint8_t *out_public_key);

int archon_sign(const uint8_t *seed, const uint8_t *message, size_t message_len,
                uint8_t *out_signature);
int archon_verify(const uint8_t *public_key, const uint8_t *message, size_t message_len,
                  const uint8_t *signature);

int archon_sign_in_domain(const uint8_t *seed, const uint8_t *domain, size_t domain_len,
                          const uint8_t *message, size_t message_len, uint8_t *out_signature);
int archon_verify_in_domain(const uint8_t *public_key, const uint8_t *domain, size_t domain_len,
                            const uint8_t *message, size_t message_len,
                            const uint8_t *signature);

#ifdef __cplusplus
}
#endif

#endif
