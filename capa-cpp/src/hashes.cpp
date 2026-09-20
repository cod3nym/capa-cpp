#include "hashes.h"

#include <array>
#include <cstring>

namespace capa::hashes {

namespace {

std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(kHex[p[i] >> 4]);
        s.push_back(kHex[p[i] & 0x0F]);
    }
    return s;
}

std::uint32_t rotl32(std::uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }
std::uint32_t rotr32(std::uint32_t v, int c) { return (v >> c) | (v << (32 - c)); }

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------

const std::uint32_t kMd5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391};

const int kMd5S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void md5_block(std::uint32_t st[4], const std::uint8_t* blk) {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i) std::memcpy(&m[i], blk + i * 4, 4);  // little-endian

    std::uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f;
        int g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        f += a + kMd5K[i] + m[g];
        a = d;
        d = c;
        c = b;
        b += rotl32(f, kMd5S[i]);
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-4)
// ---------------------------------------------------------------------------

void sha1_block(std::uint32_t st[5], const std::uint8_t* blk) {
    std::uint32_t w[80];
    for (int i = 0; i < 16; ++i)  // big-endian
        w[i] = (std::uint32_t(blk[i * 4]) << 24) | (std::uint32_t(blk[i * 4 + 1]) << 16) |
               (std::uint32_t(blk[i * 4 + 2]) << 8) | std::uint32_t(blk[i * 4 + 3]);
    for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    std::uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
    for (int i = 0; i < 80; ++i) {
        std::uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        const std::uint32_t t = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = t;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const std::uint32_t kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

void sha256_block(std::uint32_t st[8], const std::uint8_t* blk) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)  // big-endian
        w[i] = (std::uint32_t(blk[i * 4]) << 24) | (std::uint32_t(blk[i * 4 + 1]) << 16) |
               (std::uint32_t(blk[i * 4 + 2]) << 8) | std::uint32_t(blk[i * 4 + 3]);
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
    std::uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + S1 + ch + kSha256K[i] + w[i];
        const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// The padding all three share: a 0x80 byte, zeros, then the message length in bits.
// The only difference is that MD5 writes that length little-endian and the SHA family
// big-endian, so both tails are built from the same partial block.
struct Tail {
    std::array<std::uint8_t, 128> le{};  // MD5
    std::array<std::uint8_t, 128> be{};  // SHA-1, SHA-256
    std::size_t total = 64;              // 64 or 128 bytes of padding
};

Tail make_tail(const std::uint8_t* rest, std::size_t rem, std::uint64_t len) {
    Tail t;
    std::memcpy(t.le.data(), rest, rem);
    t.le[rem] = 0x80;
    // The length needs 8 bytes at the end of a block; if it does not fit after the
    // 0x80, the padding runs into a second block.
    t.total = (rem + 1 + 8 <= 64) ? 64 : 128;
    t.be = t.le;  // identical up to the length field

    const std::uint64_t bits = len * 8;
    for (int k = 0; k < 8; ++k) {
        const std::uint8_t byte = static_cast<std::uint8_t>(bits >> (k * 8));
        t.le[t.total - 8 + k] = byte;
        t.be[t.total - 1 - k] = byte;
    }
    return t;
}

std::string md5_hex(const std::uint32_t st[4]) {
    std::uint8_t out[16];
    for (int i = 0; i < 4; ++i) std::memcpy(out + i * 4, &st[i], 4);  // little-endian
    return to_hex(out, 16);
}

template <int N>
std::string be_hex(const std::uint32_t st[N]) {
    std::uint8_t out[N * 4];
    for (int i = 0; i < N; ++i)
        for (int k = 0; k < 4; ++k)
            out[i * 4 + k] = static_cast<std::uint8_t>(st[i] >> (24 - k * 8));
    return to_hex(out, N * 4);
}

}  // namespace

Digests all(const std::uint8_t* data, std::size_t len) {
    std::uint32_t m[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    std::uint32_t s1[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    std::uint32_t s2[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // The one pass over the data. Every byte is touched once and fed to all three.
    std::size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        md5_block(m, data + i);
        sha1_block(s1, data + i);
        sha256_block(s2, data + i);
    }

    const Tail t = make_tail(data + i, len - i, len);
    md5_block(m, t.le.data());
    sha1_block(s1, t.be.data());
    sha256_block(s2, t.be.data());
    if (t.total == 128) {
        md5_block(m, t.le.data() + 64);
        sha1_block(s1, t.be.data() + 64);
        sha256_block(s2, t.be.data() + 64);
    }

    return {md5_hex(m), be_hex<5>(s1), be_hex<8>(s2)};
}

std::string md5(const std::uint8_t* data, std::size_t len) { return all(data, len).md5; }
std::string sha1(const std::uint8_t* data, std::size_t len) { return all(data, len).sha1; }
std::string sha256(const std::uint8_t* data, std::size_t len) { return all(data, len).sha256; }

}  // namespace capa::hashes
