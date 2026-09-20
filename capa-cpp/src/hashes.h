// MD5 / SHA-1 / SHA-256 over a byte buffer.
//
// capa's ResultDocument identifies what was analysed by its hashes, and every other
// backend gets them for free: the TTD report carries them as strings, and IDA knows
// its own input file. A minidump backend has neither -- it has the dump -- so the
// three digests are computed here.
//
// Self-contained rather than CNG/OpenSSL on purpose: the rest of this parser is
// host-agnostic (it reads 32-bit dumps on a 64-bit host and vice versa), and a
// hundred lines of well-specified arithmetic is a smaller liability than a platform
// crypto dependency in a build that is already fiddly. These are used to LABEL
// evidence, never to protect anything, so MD5 and SHA-1 being broken for collision
// resistance does not matter -- they are here because capa's document format has
// fields for them.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace capa::hashes {

struct Digests {
    std::string md5, sha1, sha256;
};

// All three digests of [data, data + len) in ONE pass.
//
// Not three calls, because `data` is a memory-mapped .dmp that can be several
// gigabytes: three passes means faulting the whole file in three times, which on a
// full-memory dump costs minutes of I/O after the analysis has already finished.
Digests all(const std::uint8_t* data, std::size_t len);

// Lowercase hex digests of [data, data + len), one algorithm at a time.
std::string md5(const std::uint8_t* data, std::size_t len);
std::string sha1(const std::uint8_t* data, std::size_t len);
std::string sha256(const std::uint8_t* data, std::size_t len);

}  // namespace capa::hashes
