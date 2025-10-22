#include "otto/otto.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <array>
#include <cstring>
#include <openssl/evp.h>

static std::vector<uint8_t> b64decode(const std::string& s) {
    std::vector<uint8_t> out(((s.size()+3)/4)*3);
    int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(s.data()), (int)s.size());
    if (len < 0) throw std::runtime_error("b64 decode");
    out.resize(len);
    // OpenSSL's EVP_DecodeBlock includes padding in output size; adjust by counting '='
    size_t pad = 0;
    if (!s.empty() && s[s.size()-1] == '=') pad++;
    if (s.size() > 1 && s[s.size()-2] == '=') pad++;
    if (pad) out.resize(len - pad);
    return out;
}
static std::string b64encode(const std::vector<uint8_t>& v) {
    std::string out; out.resize(((v.size()+2)/3)*4);
    int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), v.data(), (int)v.size());
    out.resize(len);
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr <<
"otto-cli\n"
"USAGE:\n"
"  otto-cli enc-str <b64rawkey32> <utf8_plaintext>\n"
"  otto-cli dec-str <b64rawkey32> <b64header> <b64cipher_and_tag>\n"
"  otto-cli enc-file <b64rawkey32> <in> <out> [chunk_bytes]\n"
"  otto-cli dec-file <b64rawkey32> <in> <out>\n";
        return 1;
    }
    std::string cmd = argv[1];

    try {
        if (cmd == std::string("enc-str")) {
            if (argc < 4) throw std::runtime_error("args");
            auto key = b64decode(argv[2]);
            if (key.size()!=32) throw std::runtime_error("raw key must be 32 bytes");
            std::array<uint8_t,32> k{}; std::copy(key.begin(), key.end(), k.begin());
            std::vector<uint8_t> pt(argv[3], argv[3]+std::strlen(argv[3]));
            auto res = otto::Otto::encrypt_string(pt, k);
            std::cout << "HEADER_B64=" << b64encode(res.header) << "\n";
            std::cout << "CIPHER_B64=" << b64encode(res.cipher_and_tag) << "\n";
        } else if (cmd == std::string("dec-str")) {
            if (argc < 5) throw std::runtime_error("args");
            auto key = b64decode(argv[2]); if (key.size()!=32) throw std::runtime_error("key");
            auto header = b64decode(argv[3]);
            auto cipher = b64decode(argv[4]);
            std::array<uint8_t,32> k{}; std::copy(key.begin(), key.end(), k.begin());
            auto pt = otto::Otto::decrypt_string(cipher, header, k);
            std::cout << std::string(pt.begin(), pt.end()) << "\n";
        } else if (cmd == std::string("enc-file")) {
            if (argc < 5) throw std::runtime_error("args");
            auto key = b64decode(argv[2]); if (key.size()!=32) throw std::runtime_error("key");
            std::array<uint8_t,32> k{}; std::copy(key.begin(), key.end(), k.begin());
            size_t chunk = (argc >= 6) ? std::stoul(argv[5]) : (1u<<20);
            otto::Otto::encrypt_file(argv[3], argv[4], k, chunk);
            std::cout << "OK\n";
        } else if (cmd == std::string("dec-file")) {
            if (argc < 5) throw std::runtime_error("args");
            auto key = b64decode(argv[2]); if (key.size()!=32) throw std::runtime_error("key");
            std::array<uint8_t,32> k{}; std::copy(key.begin(), key.end(), k.begin());
            otto::Otto::decrypt_file(argv[3], argv[4], k);
            std::cout << "OK\n";
        } else {
            throw std::runtime_error("unknown command");
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 2;
    }
    return 0;
}
