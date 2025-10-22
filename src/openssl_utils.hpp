#pragma once
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <array>
#include <vector>
#include <stdexcept>
#include <cstring>

inline void throw_ssl(const char* what) {
    throw std::runtime_error(what);
}

inline std::array<uint8_t,16> random16() {
    std::array<uint8_t,16> s{};
    if (RAND_bytes(s.data(), (int)s.size()) != 1) throw_ssl("RAND_bytes failed");
    return s;
}

inline std::array<uint8_t,32> hkdf_sha256(const std::vector<uint8_t>& ikm,
                                          const std::vector<uint8_t>& salt,
                                          const std::vector<uint8_t>& info,
                                          size_t out_len) {
    std::array<uint8_t,32> out{};
    if (out_len != 32) throw std::runtime_error("hkdf out_len must be 32 in this build");
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw_ssl("EVP_PKEY_HKDF ctx");
    if (EVP_PKEY_derive_init(pctx) <= 0) throw_ssl("HKDF derive_init");
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) throw_ssl("HKDF md");
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), (int)salt.size()) <= 0) throw_ssl("HKDF salt");
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) <= 0) throw_ssl("HKDF key");
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) <= 0) throw_ssl("HKDF info");
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0 || len != out_len) throw_ssl("HKDF derive");
    EVP_PKEY_CTX_free(pctx);
    return out;
}

inline std::array<uint8_t,12> hkdf_nonce12(const std::array<uint8_t,32>& nonce_key,
                                           const std::vector<uint8_t>& info) {
    std::vector<uint8_t> ikm(nonce_key.begin(), nonce_key.end());
    std::array<uint8_t,12> out{};
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw_ssl("HKDF ctx");
    if (EVP_PKEY_derive_init(pctx) <= 0) throw_ssl("HKDF derive_init");
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) throw_ssl("HKDF md");
    // Empty salt
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, nullptr, 0) <= 0) throw_ssl("HKDF salt");
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), (int)ikm.size()) <= 0) throw_ssl("HKDF key");
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), (int)info.size()) <= 0) throw_ssl("HKDF info");
    size_t len = out.size();
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0 || len != out.size()) throw_ssl("HKDF derive");
    EVP_PKEY_CTX_free(pctx);
    return out;
}
