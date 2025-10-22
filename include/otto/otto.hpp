#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <utility>

namespace otto {

struct EncResult {
    std::vector<uint8_t> header;          // AAD (OTTO header)
    std::vector<uint8_t> cipher_and_tag;  // ciphertext || tag[16]
};

class Otto {
public:
    // In-memory (single-chunk) API
    static EncResult encrypt_string(const std::vector<uint8_t>& plaintext,
                                    const std::array<uint8_t,32>& raw_key32);
    static std::vector<uint8_t> decrypt_string(const std::vector<uint8_t>& cipher_and_tag,
                                               const std::vector<uint8_t>& header,
                                               const std::array<uint8_t,32>& raw_key32);

    // Streaming file API
    static void encrypt_file(const std::string& in_path,
                             const std::string& out_path,
                             const std::array<uint8_t,32>& raw_key32,
                             size_t chunk_bytes = (1u<<20)); // 1 MiB
    static void decrypt_file(const std::string& in_path,
                             const std::string& out_path,
                             const std::array<uint8_t,32>& raw_key32);

    // X25519 helpers
    static std::pair<std::array<uint8_t,32>, std::array<uint8_t,32>> x25519_generate();
    static std::array<uint8_t,32> x25519_shared(const std::array<uint8_t,32>& my_secret,
                                                const std::array<uint8_t,32>& their_public);
    static std::array<uint8_t,32> hkdf_session(const std::vector<uint8_t>& shared,
                                               const std::vector<uint8_t>& salt);

private:
    static std::vector<uint8_t> build_header(const std::array<uint8_t,16>& file_salt, bool chunked);
    static void parse_header(const std::vector<uint8_t>& header,
                             std::array<uint8_t,16>& file_salt_out,
                             bool& chunked_flag);

    static std::array<uint8_t,32> hkdf(const std::vector<uint8_t>& ikm,
                                       const std::vector<uint8_t>& salt,
                                       const std::vector<uint8_t>& info,
                                       size_t out_len);
    static std::array<uint8_t,12> chunk_nonce(const std::array<uint8_t,32>& nonce_key, uint64_t counter);

    static std::vector<uint8_t> aes_gcm_encrypt(const std::array<uint8_t,32>& key,
                                                const std::array<uint8_t,12>& nonce,
                                                const std::vector<uint8_t>& aad,
                                                const std::vector<uint8_t>& plaintext,
                                                std::array<uint8_t,16>& tag_out);
    static std::vector<uint8_t> aes_gcm_decrypt(const std::array<uint8_t,32>& key,
                                                const std::array<uint8_t,12>& nonce,
                                                const std::vector<uint8_t>& aad,
                                                const std::vector<uint8_t>& ciphertext,
                                                const std::array<uint8_t,16>& tag);
};

} // namespace otto
