# otto-crypt-cpp

C++ implementation of **OTTO** (AES-256-GCM + HKDF nonces)

## Build
```bash
cmake -S . -B build
cmake --build build -j
```

## CLI
```bash
# 32-byte key
openssl rand -out key.bin 32
KEYB64=$(base64 -w0 key.bin)

# Encrypt a string
./build/otto-cli enc-str "$KEYB64" "Hello from C++"
# Decrypt a string (paste output values)
./build/otto-cli dec-str "$KEYB64" "$HEADER_B64" "$CIPHER_B64"

# Encrypt / Decrypt files (photo/audio/video/anything)
./build/otto-cli enc-file "$KEYB64" input.mp4 output.mp4.otto
./build/otto-cli dec-file "$KEYB64" output.mp4.otto output.mp4
```

### Format
- Header = `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- Per-object keys via HKDF-SHA256
- Per-chunk nonce via HKDF(nonceKey, info="OTTO-CHUNK-NONCE"||counter_be64) → 12 bytes
- AAD = header; AES-256-GCM tag = 16 bytes

MIT © 2025 Ivan Sostarko
