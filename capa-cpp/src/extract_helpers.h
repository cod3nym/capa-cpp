// Backend-neutral extraction helpers for capa-cpp.
//
// These are the pieces of capa's feature extraction that depend only on bytes and
// graph shape, not on a particular disassembler: the FLOSS-style string scan, the
// embedded-PE carve, the loop test, and the printable-run test behind stack strings.
// Both static backends (Zydis/`static/`, IDA/`ida/`) use them, so they live here
// rather than in either one.
//
// Callers build the capa Address themselves: the Zydis path reports at
// `absolute(base + offset)`, the IDA path at `file_offset(...)`, so these functions
// deliberately return raw offsets rather than Addresses.
#pragma once

#include <functional>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace capa::helpers {

// ---- shared limits (capa/features/{common,insn}.py, extractors/helpers.py) ----
inline constexpr std::int64_t MAX_STRUCTURE_SIZE = 0x10000;
inline constexpr std::size_t MAX_BYTES_FEATURE_SIZE = 0x100;
inline constexpr int MIN_STACKSTRING_LEN = 8;
inline constexpr int THUNK_CHAIN_DEPTH_DELTA = 5;
inline constexpr std::uint64_t SECURITY_COOKIE_BYTES_DELTA = 0x40;
// capa/features/extractors/strings.py: 4-character minimum for both encodings.
inline constexpr std::size_t MIN_STRING_LEN = 4;

// ---- printability (capa/features/extractors/strings.py ASCII_BYTE) ----
bool is_printable_char(std::uint8_t c);
bool is_printable_ascii_bytes(const std::uint8_t* b, int len);
bool is_printable_utf16le_bytes(const std::uint8_t* b, int len);

// True if every byte of `b` is zero (and `b` is non-empty).
bool all_zeros(const std::vector<std::uint8_t>& b);

// Number of printable characters a `size`-byte immediate `value` contributes to a
// stack string: `size` if it is printable ASCII, `size / 2` if printable UTF-16LE,
// else 0. Ports get_printable_len() from capa's viv/IDA basicblock extractors.
int printable_len(std::uint64_t value, int size);

// A string found by scanning a buffer, and its byte offset within that buffer.
struct FoundString {
    std::string s;
    std::size_t offset = 0;
};

// FLOSS-style scans, minimum length MIN_STRING_LEN.
// These take a span so a caller can scan a region of a larger shared memory image
// without copying it out; `const std::vector<std::uint8_t>&` converts implicitly.
//
// The callback forms hand each string over as it is found and keep nothing. That is not
// a micro-optimisation on the static path: a reconstructed region can be a whole module
// image, every four-byte printable run in it is a string, and the vector forms hold all
// of them at once -- once per snapshot, for every snapshot in the manifest. A caller
// that is going to discard most of them (see FeatureFilter) should never have paid to
// collect them.
void scan_ascii_strings(std::span<const std::uint8_t> buf,
                        const std::function<void(std::string&&, std::size_t)>& on_string);
void scan_unicode_strings(std::span<const std::uint8_t> buf,
                          const std::function<void(std::string&&, std::size_t)>& on_string);

std::vector<FoundString> scan_ascii_strings(std::span<const std::uint8_t> buf);
std::vector<FoundString> scan_unicode_strings(std::span<const std::uint8_t> buf);

// Offsets of every embedded PE (an MZ header whose e_lfanew points at "PE\0\0").
// Mirrors capa's PE.carve(buf, 1): the scan starts at offset 1 so a container's own
// header is not reported as an embedded PE.
std::vector<std::size_t> carve_embedded_pe(std::span<const std::uint8_t> buf);

// Does the directed graph described by `edges` contain a cycle? Ports
// capa/features/extractors/loops.py has_loop(): true when any strongly connected
// component has >= 2 nodes (plus the self-edge case).
bool has_loop(const std::vector<std::pair<std::uint64_t, std::uint64_t>>& edges);

}  // namespace capa::helpers
