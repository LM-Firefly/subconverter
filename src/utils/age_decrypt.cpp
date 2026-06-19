// age_decrypt.cpp — age X25519 armor-format decryption (age-encryption.org/v1)
// Uses OpenSSL for X25519, HKDF-SHA-256, ChaCha20-Poly1305, and HMAC-SHA-256.

#include "age_decrypt.h"

#include <cstring>
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

// Weak logging — overridden by the real logger when linked into the full project
__attribute__((weak)) void writeLog(int, const std::string &, int);

static void ageLog(const std::string &msg, int level = 3)
{
    if (writeLog)
        writeLog(0, "age: " + msg, level);
    else if (level <= 2)
        fprintf(stderr, "[age] %s\n", msg.c_str());
}

// ===================== Bech32 =====================

static const std::string BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const std::vector<uint8_t> &values)
{
    uint32_t chk = 1;
    const uint32_t gen[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    for (auto v : values)
    {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ uint32_t(v);
        for (int i = 0; i < 5; i++)
        {
            if ((top >> i) & 1)
                chk ^= gen[i];
        }
    }
    return chk;
}

static std::vector<uint8_t> bech32_hrp_expand(const std::string &hrp)
{
    std::vector<uint8_t> ret;
    for (char c : hrp)
        ret.push_back(uint8_t(c) >> 5);
    ret.push_back(0);
    for (char c : hrp)
        ret.push_back(uint8_t(c) & 31);
    return ret;
}

static bool bech32_verify_checksum(const std::string &hrp, const std::vector<uint8_t> &data)
{
    auto expanded = bech32_hrp_expand(hrp);
    expanded.insert(expanded.end(), data.begin(), data.end());
    return bech32_polymod(expanded) == 1;
}

static bool bech32_decode(const std::string &s, std::string &hrp, std::vector<uint8_t> &data)
{
    // Must be all-lowercase or all-uppercase
    bool has_lower = false, has_upper = false;
    for (char c : s)
    {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
    }
    if (has_lower && has_upper)
        return false;
    std::string sl = s;
    // Convert to lowercase for processing
    for (auto &c : sl)
        if (c >= 'A' && c <= 'Z')
            c = c - 'A' + 'a';
    // Find separator
    size_t pos = sl.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > sl.size())
        return false;
    hrp = sl.substr(0, pos);
    std::vector<uint8_t> values;
    for (size_t i = pos + 1; i < sl.size(); i++)
    {
        size_t idx = BECH32_CHARSET.find(sl[i]);
        if (idx == std::string::npos)
            return false;
        values.push_back(static_cast<uint8_t>(idx));
    }
    if (!bech32_verify_checksum(hrp, values))
        return false;
    // Remove 6-char checksum
    values.resize(values.size() - 6);
    // Convert 5-bit to 8-bit
    data.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (auto v : values)
    {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8)
        {
            bits -= 8;
            data.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
        }
    }
    return true;
}

// ===================== Base64 =====================

static std::vector<uint8_t> base64_decode(const std::string &input)
{
    // Use OpenSSL for standard base64
    std::string inp = input;
    // Remove any whitespace/newlines
    inp.erase(std::remove_if(inp.begin(), inp.end(), [](char c) { return c == '\n' || c == '\r' || c == ' ' || c == '\t'; }), inp.end());
    // Add padding if needed
    while (inp.size() % 4 != 0)
        inp += '=';
    int out_len = static_cast<int>(inp.size() / 4 * 3);
    if (!inp.empty() && inp.back() == '=')
    {
        out_len--;
        if (inp.size() >= 2 && inp[inp.size() - 2] == '=')
            out_len--;
    }
    std::vector<uint8_t> output(out_len);
    int actual = EVP_DecodeBlock(output.data(), reinterpret_cast<const uint8_t *>(inp.data()), static_cast<int>(inp.size()));
    if (actual < 0)
        return {};
    output.resize(std::min(actual, out_len));
    return output;
}

// Raw base64 (no padding) — used for age stanza args/body
static std::vector<uint8_t> base64_raw_decode(const std::string &input)
{
    std::string padded = input;
    while (padded.size() % 4 != 0)
        padded += '=';
    int out_len = static_cast<int>(padded.size() / 4 * 3);
    if (!padded.empty() && padded.back() == '=')
    {
        out_len--;
        if (padded.size() >= 2 && padded[padded.size() - 2] == '=')
            out_len--;
    }
    std::vector<uint8_t> output(out_len);
    int actual = EVP_DecodeBlock(output.data(), reinterpret_cast<const uint8_t *>(padded.data()), static_cast<int>(padded.size()));
    if (actual < 0)
        return {};
    output.resize(std::min(actual, out_len));
    return output;
}

// ===================== HKDF-SHA-256 =====================

static bool hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len)
{
    // Use OpenSSL EVP_KDF for HKDF (OpenSSL 3.0+)
    // Fall back to manual HKDF for older versions
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return false;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return false;
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>("SHA256"), 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t *>(ikm), ikm_len);
    // salt must not be nullptr — use empty string for zero-length salt
    uint8_t empty_salt = 0;
    if (!salt || salt_len == 0) { salt = &empty_salt; salt_len = 0; }
    *p++ = OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t *>(salt), salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", const_cast<uint8_t *>(info), info_len);
    *p = OSSL_PARAM_construct_end();
    int ret = EVP_KDF_derive(ctx, okm, okm_len, params);
    EVP_KDF_CTX_free(ctx);
    return ret == 1;
#else
    // Manual HKDF (RFC 5869) for OpenSSL 1.1.x
    // Step 1: Extract
    uint8_t prk[32];
    unsigned int prk_len = 32;
    HMAC_CTX *hmac = HMAC_CTX_new();
    if (!hmac) return false;

    // If salt is empty, use default (32 zero bytes)
    uint8_t default_salt[32] = {0};
    const uint8_t *actual_salt = salt && salt_len > 0 ? salt : default_salt;
    size_t actual_salt_len = salt && salt_len > 0 ? salt_len : 32;

    HMAC_Init_ex(hmac, actual_salt, static_cast<int>(actual_salt_len), EVP_sha256(), nullptr);
    HMAC_Update(hmac, ikm, ikm_len);
    HMAC_Final(hmac, prk, &prk_len);
    HMAC_CTX_free(hmac);

    // Step 2: Expand
    size_t N = (okm_len + 31) / 32;
    uint8_t prev[32];
    size_t done = 0;
    for (size_t i = 1; i <= N; i++)
    {
        HMAC_CTX *h = HMAC_CTX_new();
        HMAC_Init_ex(h, prk, 32, EVP_sha256(), nullptr);
        if (i > 1)
            HMAC_Update(h, prev, 32);
        HMAC_Update(h, info, info_len);
        uint8_t c = static_cast<uint8_t>(i);
        HMAC_Update(h, &c, 1);
        unsigned int prev_len = 32;
        HMAC_Final(h, prev, &prev_len);
        HMAC_CTX_free(h);

        size_t copy = std::min(size_t(32), okm_len - done);
        memcpy(okm + done, prev, copy);
        done += copy;
    }
    return true;
#endif
}

// ===================== ChaCha20-Poly1305 =====================

static bool chacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *ciphertext, size_t ciphertext_len, const uint8_t *aad, size_t aad_len, uint8_t *plaintext, size_t &plaintext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
        goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1)
        goto fail;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
        goto fail;
    if (aad && aad_len > 0)
    {
        int outl;
        if (EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len)) != 1)
            goto fail;
    }
    {
        int outl;
        if (EVP_DecryptUpdate(ctx, plaintext, &outl, ciphertext, static_cast<int>(ciphertext_len - 16)) != 1)
            goto fail;
        plaintext_len = outl;
        // Set tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t *>(ciphertext + ciphertext_len - 16)) != 1)
            goto fail;
        if (EVP_DecryptFinal_ex(ctx, plaintext + outl, &outl) != 1)
            goto fail;
        plaintext_len += outl;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

// ===================== X25519 =====================

static bool x25519_derive_public(const uint8_t secret_key[32], uint8_t public_key[32])
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret_key, 32);
    if (!pkey) return false;
    size_t len = 32;
    bool ok = (EVP_PKEY_get_raw_public_key(pkey, public_key, &len) == 1);
    EVP_PKEY_free(pkey);
    return ok;
}

static bool x25519_shared_secret(const uint8_t secret_key[32], const uint8_t peer_public[32], uint8_t shared[32])
{
    EVP_PKEY *my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret_key, 32);
    if (!my_key) return false;
    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_public, 32);
    if (!peer_key) { EVP_PKEY_free(my_key); return false; }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, nullptr);
    if (!ctx) { EVP_PKEY_free(my_key); EVP_PKEY_free(peer_key); return false; }
    bool ok = false;
    if (EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, peer_key) == 1)
    {
        size_t len = 32;
        ok = (EVP_PKEY_derive(ctx, shared, &len) == 1 && len == 32);
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(my_key);
    EVP_PKEY_free(peer_key);
    return ok;
}

// ===================== Age Header Parsing =====================

struct AgeStanza
{
    std::string type;
    std::vector<std::string> args;
    std::vector<uint8_t> body;
};

struct AgeHeader
{
    std::vector<AgeStanza> recipients;
    std::vector<uint8_t> mac;
    std::string raw_header;  // Everything up to and including "---"
};

static bool parse_age_header(const std::vector<uint8_t> &data, AgeHeader &hdr, size_t &payload_offset)
{
    std::string text(data.begin(), data.end());
    // Check intro
    const std::string intro = "age-encryption.org/v1\n";
    if (text.substr(0, intro.size()) != intro)
    {
        ageLog("missing intro line", 1);
        return false;
    }
    size_t pos = intro.size();
    bool found_mac = false;
    while (pos < text.size())
    {
        // Check for footer "---"
        if (text[pos] == '-' && text[pos + 1] == '-' && text[pos + 2] == '-')
        {
            // Parse MAC line: "--- <base64mac>\n"
            size_t mac_start = text.find(' ', pos);
            if (mac_start == std::string::npos)
            {
                ageLog("malformed MAC line", 1);
                return false;
            }
            mac_start++;
            size_t mac_end = text.find('\n', mac_start);
            if (mac_end == std::string::npos)
                mac_end = text.size();
            std::string mac_b64 = text.substr(mac_start, mac_end - mac_start);
            hdr.mac = base64_raw_decode(mac_b64);
            if (hdr.mac.size() != 32)
            {
                ageLog("invalid MAC length", 1);
                return false;
            }
            // raw_header includes everything up to and including "---"
            hdr.raw_header = text.substr(0, pos + 3);
            payload_offset = mac_end + 1;
            found_mac = true;
            break;
        }
        // Parse stanza: "-> TYPE ARG1 ARG2...\n<body_b64>\n"
        if (text[pos] == '-' && text[pos + 1] == '>')
        {
            AgeStanza stanza;
            size_t line_end = text.find('\n', pos);
            if (line_end == std::string::npos) return false;
            std::string stanza_line = text.substr(pos + 2, line_end - pos - 2);
            // Split by spaces
            std::vector<std::string> parts;
            size_t sp = 0;
            while (sp < stanza_line.size())
            {
                while (sp < stanza_line.size() && stanza_line[sp] == ' ') sp++;
                size_t ep = sp;
                while (ep < stanza_line.size() && stanza_line[ep] != ' ') ep++;
                if (ep > sp)
                    parts.push_back(stanza_line.substr(sp, ep - sp));
                sp = ep;
            }
            if (parts.empty()) return false;
            stanza.type = parts[0];
            for (size_t i = 1; i < parts.size(); i++)
                stanza.args.push_back(parts[i]);
            pos = line_end + 1;
            // Read body lines until we hit the footer "---" or next stanza "->"
            // The age format has NO empty line between stanza body and footer.
            std::string body_b64;
            while (pos < text.size())
            {
                size_t bl_end = text.find('\n', pos);
                if (bl_end == std::string::npos) bl_end = text.size();
                std::string line = text.substr(pos, bl_end - pos);
                // Stop at footer or next stanza
                if (line.size() >= 3 && line[0] == '-' && line[1] == '-' && line[2] == '-')
                    break;
                if (line.size() >= 2 && line[0] == '-' && line[1] == '>')
                    break;
                body_b64 += line;
                pos = bl_end + 1;
            }

            stanza.body = base64_raw_decode(body_b64);
            hdr.recipients.push_back(std::move(stanza));
            continue;
        }

        // Skip unexpected lines
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }

    return found_mac;
}

// ===================== STREAM Decryption =====================

static bool stream_decrypt(const uint8_t *stream_key, const uint8_t *payload, size_t payload_len,
                           std::vector<uint8_t> &plaintext)
{
    const size_t chunk_size = 64 * 1024;                    // 65536
    const size_t overhead = 16;                              // Poly1305 tag
    const size_t enc_chunk_size = chunk_size + overhead;     // 65552

    plaintext.clear();

    uint8_t nonce[12] = {0}; // 12-byte nonce, starts at zero

    size_t offset = 0;
    while (offset < payload_len)
    {
        size_t remaining = payload_len - offset;
        size_t this_chunk_len = std::min(enc_chunk_size, remaining);
        bool is_last = (this_chunk_len < enc_chunk_size) || (offset + this_chunk_len >= payload_len);

        if (is_last)
            nonce[11] = 0x01; // Set last-chunk flag

        uint8_t decrypted[64 * 1024];
        size_t dec_len = 0;

        if (!chacha20poly1305_decrypt(stream_key, nonce,
                                      payload + offset, this_chunk_len,
                                      nullptr, 0,
                                      decrypted, dec_len))
        {
            ageLog("STREAM chunk decryption failed", 1);
            return false;
        }

        plaintext.insert(plaintext.end(), decrypted, decrypted + dec_len);
        offset += this_chunk_len;

        // Increment nonce (big-endian counter in bytes [3..10])
        for (int i = 10; i >= 3; i--)
        {
            nonce[i]++;
            if (nonce[i] != 0) break;
        }

        if (is_last) break;
    }

    return true;
}

// ===================== Main Decryption =====================

std::string ageDecrypt(const std::string &armoredData, const std::string &secretKey, std::string *errorMsg)
{
    const std::string armor_header = "-----BEGIN AGE ENCRYPTED FILE-----";
    const std::string armor_footer = "-----END AGE ENCRYPTED FILE-----";

    // Not armored — return as-is
    if (armoredData.substr(0, armor_header.size()) != armor_header)
        return armoredData;

    auto set_error = [&](const std::string &msg) -> std::string {
        if (errorMsg) *errorMsg = msg;
        ageLog("decrypt: " + msg, 1);
        return "";
    };

    // 1. Strip armor: extract base64 between header and footer
    size_t body_start = armoredData.find('\n');
    if (body_start == std::string::npos) return set_error("missing newline after armor header");
    body_start++;

    size_t footer_pos = armoredData.find(armor_footer, body_start);
    if (footer_pos == std::string::npos) return set_error("missing armor footer");

    std::string b64_body = armoredData.substr(body_start, footer_pos - body_start);

    // Base64 decode (standard encoding with whitespace)
    std::vector<uint8_t> binary = base64_decode(b64_body);
    if (binary.empty()) return set_error("base64 decode failed");

    // 2. Parse secret key from bech32
    std::string sk_hrp;
    std::vector<uint8_t> sk_bytes;
    if (!bech32_decode(secretKey, sk_hrp, sk_bytes))
        return set_error("invalid bech32 secret key");
    if (sk_hrp != "age-secret-key-" || sk_bytes.size() != 32)
        return set_error("invalid secret key format (expected AGE-SECRET-KEY-1...)");

    uint8_t secret_key[32];
    memcpy(secret_key, sk_bytes.data(), 32);

    // Compute public key
    uint8_t public_key[32];
    if (!x25519_derive_public(secret_key, public_key))
        return set_error("failed to derive public key from secret key");

    // 3. Parse age header
    AgeHeader hdr;
    size_t payload_offset = 0;
    if (!parse_age_header(binary, hdr, payload_offset))
        return set_error("failed to parse age header");

    // 4. Try to unwrap file key from each X25519 stanza
    std::vector<uint8_t> file_key;
    bool unwrapped = false;

    for (const auto &stanza : hdr.recipients)
    {
        if (stanza.type != "X25519")
            continue;
        if (stanza.args.size() != 1)
            continue;

        // Decode ephemeral public key
        std::vector<uint8_t> epk = base64_raw_decode(stanza.args[0]);
        if (epk.size() != 32) continue;

        // ECDH
        uint8_t shared_secret[32];
        if (!x25519_shared_secret(secret_key, epk.data(), shared_secret))
            continue;

        // HKDF: salt = epk || public_key, info = "age-encryption.org/v1/X25519"
        uint8_t salt[64];
        memcpy(salt, epk.data(), 32);
        memcpy(salt + 32, public_key, 32);

        const char *x25519_label = "age-encryption.org/v1/X25519";
        uint8_t wrapping_key[32];
        if (!hkdf_sha256(shared_secret, 32,
                         salt, 64,
                         reinterpret_cast<const uint8_t *>(x25519_label), strlen(x25519_label),
                         wrapping_key, 32))
            continue;

        // AEAD decrypt: ChaCha20-Poly1305 with zero nonce
        uint8_t zero_nonce[12] = {0};
        uint8_t fk[32];
        size_t fk_len = 0;

        // The body is the wrapped file key (ciphertext + 16-byte tag)
        if (stanza.body.size() < 16) continue;
        if (!chacha20poly1305_decrypt(wrapping_key, zero_nonce,
                                      stanza.body.data(), stanza.body.size(),
                                      nullptr, 0, fk, fk_len))
            continue;

        if (fk_len != 16) continue;

        file_key.assign(fk, fk + 16);
        unwrapped = true;
        break;
    }

    if (!unwrapped)
        return set_error("no matching X25519 stanza found (key mismatch?)");

    // 5. Verify header MAC
    {
        // HKDF: IKM=file_key, salt=nil, info="header" → hmac_key
        uint8_t hmac_key[32];
        const char *header_info = "header";
        if (!hkdf_sha256(file_key.data(), file_key.size(),
                         nullptr, 0,
                         reinterpret_cast<const uint8_t *>(header_info), 6,
                         hmac_key, 32))
            return set_error("HKDF for header MAC failed");

        // HMAC-SHA-256(hmac_key, header_without_mac)
        // header_without_mac is hdr.raw_header (everything up to and including "---")
        unsigned char mac[32];
        unsigned int mac_len = 32;
        HMAC(EVP_sha256(), hmac_key, 32,
             reinterpret_cast<const uint8_t *>(hdr.raw_header.data()), hdr.raw_header.size(),
             mac, &mac_len);

        if (mac_len != 32 || CRYPTO_memcmp(mac, hdr.mac.data(), 32) != 0)
            return set_error("header MAC verification failed");
    }

    // 6. Derive stream key and decrypt payload
    {
        // Read 16-byte nonce from payload
        if (payload_offset + 16 > binary.size())
            return set_error("payload too short for nonce");

        const uint8_t *nonce = binary.data() + payload_offset;
        const uint8_t *payload = nonce + 16;
        size_t payload_len = binary.size() - payload_offset - 16;

        // HKDF: IKM=file_key, salt=nonce, info="payload" → stream_key
        uint8_t stream_key[32];
        const char *payload_info = "payload";
        if (!hkdf_sha256(file_key.data(), file_key.size(),
                         nonce, 16,
                         reinterpret_cast<const uint8_t *>(payload_info), 7,
                         stream_key, 32))
            return set_error("HKDF for stream key failed");

        // STREAM decrypt
        std::vector<uint8_t> plaintext;
        if (!stream_decrypt(stream_key, payload, payload_len, plaintext))
            return set_error("STREAM payload decryption failed");

        return std::string(plaintext.begin(), plaintext.end());
    }
}
