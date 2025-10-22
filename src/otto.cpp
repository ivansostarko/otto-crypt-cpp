#include "openssl_utils.hpp"
#include "otto/otto.hpp"
#include <openssl/evp.h>
#include <fstream>
#include <cstring>
#include <algorithm>

namespace otto {

static const uint8_t MAGIC[5] = {'O','T','T','O','1'};
static constexpr uint8_t ALGO_ID   = 0xA1;
static constexpr uint8_t KDF_RAW   = 0x02;
static constexpr uint8_t FLAG_CHUNKED = 0x01;
static constexpr size_t  FIXED_HDR = 11;  // 5 + 1 + 1 + 1 + 1 + 2
static constexpr size_t  FILE_SALT = 16;
static constexpr size_t  TAG_LEN   = 16;
static constexpr size_t  NONCE_LEN = 12;

static inline void u16be(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)((x>>8)&0xff)); v.push_back((uint8_t)(x&0xff));
}
static inline void u32be(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)((x>>24)&0xff)); v.push_back((uint8_t)((x>>16)&0xff));
    v.push_back((uint8_t)((x>>8)&0xff));  v.push_back((uint8_t)(x&0xff));
}
static inline uint32_t be32(const uint8_t* p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | (uint32_t)p[3];
}

std::vector<uint8_t> Otto::build_header(const std::array<uint8_t,16>& file_salt, bool chunked) {
    std::vector<uint8_t> h; h.reserve(FIXED_HDR + FILE_SALT);
    h.insert(h.end(), MAGIC, MAGIC+5);
    h.push_back(ALGO_ID);
    h.push_back(KDF_RAW);
    h.push_back(chunked ? FLAG_CHUNKED : 0x00);
    h.push_back(0x00); // reserved
    u16be(h, (uint16_t)FILE_SALT);
    h.insert(h.end(), file_salt.begin(), file_salt.end());
    return h;
}

void Otto::parse_header(const std::vector<uint8_t>& header,
                        std::array<uint8_t,16>& file_salt_out,
                        bool& chunked_flag) {
    if (header.size() < FIXED_HDR) throw std::runtime_error("header too short");
    if (!std::equal(header.begin(), header.begin()+5, MAGIC)) throw std::runtime_error("bad magic");
    if (header[5] != ALGO_ID) throw std::runtime_error("algo mismatch");
    if (header[6] != KDF_RAW) throw std::runtime_error("kdf mismatch");
    chunked_flag = (header[7] & FLAG_CHUNKED) != 0;
    const uint16_t var_len = (uint16_t)header[9]<<8 | header[10];
    if (header.size() != FIXED_HDR + var_len) throw std::runtime_error("header length mismatch");
    if (var_len < FILE_SALT) throw std::runtime_error("missing file salt");
    std::copy_n(header.data()+FIXED_HDR, FILE_SALT, file_salt_out.begin());
}

std::array<uint8_t,32> Otto::hkdf(const std::vector<uint8_t>& ikm,
                                  const std::vector<uint8_t>& salt,
                                  const std::vector<uint8_t>& info,
                                  size_t out_len) {
    return hkdf_sha256(ikm, salt, info, out_len);
}

std::array<uint8_t,12> Otto::chunk_nonce(const std::array<uint8_t,32>& nonce_key, uint64_t counter) {
    std::vector<uint8_t> info; info.reserve(16+8);
    const char* label = "OTTO-CHUNK-NONCE";
    info.insert(info.end(), label, label+std::strlen(label));
    uint8_t ctr[8]; for (int i=7;i>=0;--i) { ctr[i] = (uint8_t)(counter & 0xff); counter >>= 8; }
    info.insert(info.end(), ctr, ctr+8);
    return hkdf_nonce12(nonce_key, info);
}

std::vector<uint8_t> Otto::aes_gcm_encrypt(const std::array<uint8_t,32>& key,
                                           const std::array<uint8_t,12>& nonce,
                                           const std::vector<uint8_t>& aad,
                                           const std::vector<uint8_t>& plaintext,
                                           std::array<uint8_t,16>& tag_out) {
    std::vector<uint8_t> out(plaintext.begin(), plaintext.end());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_ssl("cipher ctx");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) throw_ssl("enc init");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr) != 1) throw_ssl("set iv len");
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) throw_ssl("set key/iv");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) throw_ssl("aad");
    }
    int outlen = (int)out.size();
    if (EVP_EncryptUpdate(ctx, out.data(), &outlen, out.data(), (int)out.size()) != 1) throw_ssl("enc update");
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data()+outlen, &tmplen) != 1) throw_ssl("enc final");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag_out.data()) != 1) throw_ssl("get tag");
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> Otto::aes_gcm_decrypt(const std::array<uint8_t,32>& key,
                                           const std::array<uint8_t,12>& nonce,
                                           const std::vector<uint8_t>& aad,
                                           const std::vector<uint8_t>& ciphertext,
                                           const std::array<uint8_t,16>& tag) {
    std::vector<uint8_t> out(ciphertext.begin(), ciphertext.end());
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw_ssl("cipher ctx");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) throw_ssl("dec init");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_LEN, nullptr) != 1) throw_ssl("set iv len");
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) throw_ssl("set key/iv");

    int len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), (int)aad.size()) != 1) throw_ssl("aad");
    }
    int outlen = (int)out.size();
    if (EVP_DecryptUpdate(ctx, out.data(), &outlen, out.data(), (int)out.size()) != 1) throw_ssl("dec update");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, const_cast<uint8_t*>(tag.data())) != 1) throw_ssl("set tag");
    int final_ok = EVP_DecryptFinal_ex(ctx, out.data()+outlen, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (final_ok != 1) throw std::runtime_error("auth failed");
    return out;
}

// ==== Public API ====

EncResult Otto::encrypt_string(const std::vector<uint8_t>& plaintext,
                               const std::array<uint8_t,32>& raw_key32) {
    auto file_salt = random16();
    auto header = build_header(file_salt, /*chunked*/false);

    std::vector<uint8_t> ikm(raw_key32.begin(), raw_key32.end());
    std::vector<uint8_t> salt(file_salt.begin(), file_salt.end());
    auto enc_key   = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','E','N','C','-','K','E','Y'}, 32);
    auto nonce_key = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','N','O','N','C','E','-','K','E','Y'}, 32);

    auto nonce = chunk_nonce(nonce_key, 0);
    std::array<uint8_t,16> tag{};
    auto ct = aes_gcm_encrypt(enc_key, nonce, header, plaintext, tag);

    std::vector<uint8_t> cipher_and_tag(ct.begin(), ct.end());
    cipher_and_tag.insert(cipher_and_tag.end(), tag.begin(), tag.end());
    return EncResult{std::move(header), std::move(cipher_and_tag)};
}

std::vector<uint8_t> Otto::decrypt_string(const std::vector<uint8_t>& cipher_and_tag,
                                          const std::vector<uint8_t>& header,
                                          const std::array<uint8_t,32>& raw_key32) {
    if (cipher_and_tag.size() < TAG_LEN) throw std::runtime_error("cipher too short");
    std::array<uint8_t,16> tag{};
    std::copy_n(cipher_and_tag.data()+cipher_and_tag.size()-TAG_LEN, TAG_LEN, tag.begin());
    std::vector<uint8_t> ct(cipher_and_tag.begin(), cipher_and_tag.end()-TAG_LEN);

    std::array<uint8_t,16> file_salt{};
    bool chunked=false; parse_header(header, file_salt, chunked);

    std::vector<uint8_t> ikm(raw_key32.begin(), raw_key32.end());
    std::vector<uint8_t> salt(file_salt.begin(), file_salt.end());
    auto enc_key   = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','E','N','C','-','K','E','Y'}, 32);
    auto nonce_key = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','N','O','N','C','E','-','K','E','Y'}, 32);

    auto nonce = chunk_nonce(nonce_key, 0);
    return aes_gcm_decrypt(enc_key, nonce, header, ct, tag);
}

void Otto::encrypt_file(const std::string& in_path,
                        const std::string& out_path,
                        const std::array<uint8_t,32>& raw_key32,
                        size_t chunk_bytes) {
    auto file_salt = random16();
    auto header = build_header(file_salt, /*chunked*/true);

    std::ifstream fin(in_path, std::ios::binary);
    if (!fin) throw std::runtime_error("open input failed");
    std::ofstream fout(out_path, std::ios::binary);
    if (!fout) throw std::runtime_error("open output failed");

    fout.write(reinterpret_cast<const char*>(header.data()), (std::streamsize)header.size());

    std::vector<uint8_t> ikm(raw_key32.begin(), raw_key32.end());
    std::vector<uint8_t> salt(file_salt.begin(), file_salt.end());
    auto enc_key   = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','E','N','C','-','K','E','Y'}, 32);
    auto nonce_key = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','N','O','N','C','E','-','K','E','Y'}, 32);

    std::vector<uint8_t> buf; buf.resize(chunk_bytes);
    uint64_t counter = 0;

    while (true) {
        fin.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)buf.size());
        std::streamsize got = fin.gcount();
        if (got <= 0) break;

        std::vector<uint8_t> pt(buf.begin(), buf.begin()+got);
        auto nonce = chunk_nonce(nonce_key, counter++);
        std::array<uint8_t,16> tag{};
        auto ct = aes_gcm_encrypt(enc_key, nonce, header, pt, tag);

        std::vector<uint8_t> lenb; lenb.reserve(4); u32be(lenb, (uint32_t)ct.size());
        fout.write(reinterpret_cast<const char*>(lenb.data()), 4);
        fout.write(reinterpret_cast<const char*>(ct.data()), (std::streamsize)ct.size());
        fout.write(reinterpret_cast<const char*>(tag.data()), TAG_LEN);
    }
    fout.flush();
}

void Otto::decrypt_file(const std::string& in_path,
                        const std::string& out_path,
                        const std::array<uint8_t,32>& raw_key32) {
    std::ifstream fin(in_path, std::ios::binary);
    if (!fin) throw std::runtime_error("open input failed");

    std::vector<uint8_t> fixed; fixed.resize(FIXED_HDR);
    fin.read(reinterpret_cast<char*>(fixed.data()), (std::streamsize)fixed.size());
    if (fin.gcount() != (std::streamsize)fixed.size()) throw std::runtime_error("bad header");
    if (!std::equal(fixed.begin(), fixed.begin()+5, MAGIC)) throw std::runtime_error("bad magic");
    if (fixed[5]!=ALGO_ID || fixed[6]!=KDF_RAW) throw std::runtime_error("algo/kdf mismatch");
    uint16_t varlen = ((uint16_t)fixed[9]<<8) | fixed[10];

    std::vector<uint8_t> var; var.resize(varlen);
    fin.read(reinterpret_cast<char*>(var.data()), (std::streamsize)var.size());
    if (fin.gcount() != (std::streamsize)var.size()) throw std::runtime_error("truncated header");

    std::vector<uint8_t> header; header.reserve(FIXED_HDR+varlen);
    header.insert(header.end(), fixed.begin(), fixed.end());
    header.insert(header.end(), var.begin(), var.end());

    std::array<uint8_t,16> file_salt{};
    bool chunked=false; parse_header(header, file_salt, chunked);

    std::ofstream fout(out_path, std::ios::binary);
    if (!fout) throw std::runtime_error("open output failed");

    std::vector<uint8_t> ikm(raw_key32.begin(), raw_key32.end());
    std::vector<uint8_t> salt(file_salt.begin(), file_salt.end());
    auto enc_key   = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','E','N','C','-','K','E','Y'}, 32);
    auto nonce_key = hkdf(ikm, salt, std::vector<uint8_t>{'O','T','T','O','-','N','O','N','C','E','-','K','E','Y'}, 32);

    uint64_t counter = 0;
    for (;;) {
        uint8_t lenb[4];
        fin.read(reinterpret_cast<char*>(lenb), 4);
        if (!fin) break; // EOF is OK
        uint32_t clen = be32(lenb);
        if (clen == 0) break;

        std::vector<uint8_t> ct(clen);
        fin.read(reinterpret_cast<char*>(ct.data()), (std::streamsize)ct.size());
        if (fin.gcount() != (std::streamsize)ct.size()) throw std::runtime_error("truncated ciphertext");

        std::array<uint8_t,16> tag{};
        fin.read(reinterpret_cast<char*>(tag.data()), TAG_LEN);
        if (fin.gcount() != (std::streamsize)TAG_LEN) throw std::runtime_error("missing tag");

        auto nonce = chunk_nonce(nonce_key, counter++);
        auto pt = aes_gcm_decrypt(enc_key, nonce, header, ct, tag);
        fout.write(reinterpret_cast<const char*>(pt.data()), (std::streamsize)pt.size());
    }
    fout.flush();
}

// X25519

std::pair<std::array<uint8_t,32>, std::array<uint8_t,32>> Otto::x25519_generate() {
    std::array<uint8_t,32> sk{}, pk{};
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!kctx) throw_ssl("x25519 ctx");
    if (EVP_PKEY_keygen_init(kctx) <= 0) throw_ssl("x25519 keygen init");
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) throw_ssl("x25519 keygen");
    EVP_PKEY_CTX_free(kctx);

    size_t sklen=32, pklen=32;
    if (EVP_PKEY_get_raw_private_key(pkey, sk.data(), &sklen) <= 0 || sklen!=32) throw_ssl("get sk");
    if (EVP_PKEY_get_raw_public_key (pkey, pk.data(), &pklen) <= 0 || pklen!=32) throw_ssl("get pk");
    EVP_PKEY_free(pkey);
    return {sk, pk};
}

std::array<uint8_t,32> Otto::x25519_shared(const std::array<uint8_t,32>& my_secret,
                                           const std::array<uint8_t,32>& their_public) {
    std::array<uint8_t,32> out{};
    EVP_PKEY* pvt = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, my_secret.data(), 32);
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key (EVP_PKEY_X25519, nullptr, their_public.data(), 32);
    if (!pvt || !pub) throw_ssl("x25519 raw keys");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pvt, nullptr);
    if (!ctx) throw_ssl("x25519 derive ctx");
    if (EVP_PKEY_derive_init(ctx) <= 0) throw_ssl("x25519 derive init");
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) throw_ssl("x25519 set peer");

    size_t outlen = out.size();
    if (EVP_PKEY_derive(ctx, out.data(), &outlen) <= 0 || outlen!=out.size()) throw_ssl("x25519 derive");
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pvt); EVP_PKEY_free(pub);
    return out;
}

std::array<uint8_t,32> Otto::hkdf_session(const std::vector<uint8_t>& shared,
                                          const std::vector<uint8_t>& salt) {
    return hkdf_sha256(shared, salt, std::vector<uint8_t>{'O','T','T','O','-','P','2','P','-','S','E','S','S','I','O','N'}, 32);
}

} // namespace otto
