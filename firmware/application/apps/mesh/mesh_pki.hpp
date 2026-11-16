/*
 * Copyright (C) 2026 Alexey Verhogladov
 *
 * This file is part of PortaPack.
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Public-key crypto for Meshtastic direct messages: X25519 key agreement, SHA-256, and
 * AES-256-CCM (8-byte tag). Matches the meshtastic CryptoEngine so DMs interoperate:
 * shared = X25519(my_priv, their_pub); key = SHA256(shared); ct = AES-256-CCM(key, nonce, pt).
 */

#ifndef __MESH_PKI_HPP__
#define __MESH_PKI_HPP__

#include <cstdint>
#include <cstddef>

namespace meshtastic {
namespace pki {

// SHA-256 of msg -> out[32].
void sha256(const uint8_t* msg, size_t len, uint8_t out[32]);

// X25519 scalar multiply: out[32] = scalar[32] * point[32] (RFC 7748).
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

// Public key from a private key: pub = X25519(priv, basepoint 9).
void x25519_base(uint8_t pub[32], const uint8_t priv[32]);

// Clamp a 32-byte random value into a valid X25519 private key (in place).
void clamp_private(uint8_t priv[32]);

// SHA-512, streaming (Ed25519 hashes a key half and a message given in pieces).
struct Sha512 {
    uint64_t st[8];
    uint8_t buf[128];
    uint64_t total;
    size_t fill;
    void init();
    void update(const uint8_t* p, size_t len);
    void final(uint8_t out[64]);
};

// Ed25519 (RFC 8032) with the 64-byte expanded private key MeshCore keeps and exports
// (orlp/ed25519 layout): prv[0..31] = the scalar (clamped here anyway), prv[32..63] =
// the nonce prefix. From a 32-byte seed: prv = SHA-512(seed).
void ed25519_public(uint8_t pub[32], const uint8_t prv[64]);
void ed25519_sign(uint8_t sig[64], const uint8_t* msg, size_t len, const uint8_t pub[32], const uint8_t prv[64]);
// MeshCore's shared secret (orlp ed25519_key_exchange): X25519 of our scalar with the
// peer's Ed25519 key mapped to Curve25519. Used raw: AES-128 key = first 16 bytes, HMAC
// key = all 32. false when the result is all zero (a bad key).
bool ed25519_key_exchange(uint8_t shared[32], const uint8_t their_pub[32], const uint8_t prv[64]);

// AES-256-CCM (Meshtastic uses an 8-byte auth tag, 13-byte nonce).
// Encrypt: writes len ciphertext bytes to out and 8 tag bytes to tag.
void aes_ccm_encrypt(const uint8_t key[32], const uint8_t* nonce, size_t nonce_len, const uint8_t* in, size_t len, uint8_t* out, uint8_t tag[8]);
// Decrypt: writes len plaintext bytes to out; returns true if the tag verifies.
bool aes_ccm_decrypt(const uint8_t key[32], const uint8_t* nonce, size_t nonce_len, const uint8_t* in, size_t len, const uint8_t tag[8], uint8_t* out);

}  // namespace pki
}  // namespace meshtastic

#endif
