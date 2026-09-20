// Scan-code manifest model for capa-cpp's static path.
//
// Parses the JSON that `ttdcapa-extract --scan-code` writes (see ttd/src/codescan/
// CodeScan.cpp) and defines the per-region capability record that the Python
// `ttd_static_scan.py -o` emits for `ttd-timeline.py --code` to fold in.
//
// Each region owns one or more `.bin` dumps: a flat image of [base, base+size) as it
// looked when code first ran in it. `entries` are generation-start RIPs (function-entry
// candidates); `executed` is every instruction address seen (code seeds).
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace capa::stat {

struct Dump {
    std::string file;      // e.g. "code_<seq>_<steps>_<base>.bin"
    std::string position;  // navigable TTD position "Sequence:Steps" (hex)
    std::uint64_t entry = 0;
};

struct Region {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string classification = "exec";  // "exec" | "data"
    std::vector<std::uint64_t> entries;   // sorted function-entry candidate VAs
    std::vector<std::uint64_t> executed;  // sorted executed instruction VAs
    std::vector<Dump> dumps;
};

// One module the trace loaded, with its named exports.
//
// A reconstructed region is not self-describing: shellcode that resolved its imports
// with GetProcAddress holds a table of bare addresses, and every one of them points
// OUTSIDE the region -- into kernel32, ntdll, ws2_32. Only the trace knows what lives
// there, so the recorder writes it here and the scan uses it to turn those addresses
// back into `api:` features.
//
// Optional: a manifest written before this existed simply has no `modules` and scans
// exactly as it did before.
struct ModuleInfo {
    std::string name;  // base name, e.g. "kernel32.dll"
    std::string path;  // full path the module was loaded from
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::string arch;  // "x86" / "x64" / "arm64"; empty when the headers were unreadable
    // Exports as (RVA, name). RVA because the module's own base is right here, and a
    // busy trace records tens of thousands of these.
    std::vector<std::pair<std::uint32_t, std::string>> exports;
};

struct Manifest {
    int version = 0;
    std::string trace;
    // "x86" / "i386" / "32" for 32-bit, anything else (incl. the "x64" default) for
    // 64-bit. Drives the Zydis decode mode; see stat::arch_from_string.
    std::string arch = "x64";
    std::vector<ModuleInfo> modules;
    std::vector<Region> regions;

    static Manifest from_json(const nlohmann::json& j);
};

// One capability record, schema-compatible with ttd_static_scan.py's `-o` output.
struct CapabilityRecord {
    std::string rule;
    std::string namespace_;
    std::string position;       // earliest position at which the rule fired in the region
    std::uint64_t base = 0;
    std::string classification;
    bool has_offset = false;    // false -> JSON null (no int-able match location)
    std::int64_t offset = 0;    // offset into the dump (min match VA - base)
    int scans_matched = 0;
    // All absolute executable match VAs (instruction/bb/function scope), for the
    // execute-hit tracing pass. Empty for file/data-scope matches (strings, bytes).
    //
    // These are *container* addresses: capa locates a match at its scope's address, so
    // a function-scope rule sits at the entry of the function that contains the
    // behaviour, not at the behaviour. `scope` says which container, and `feature_vas`
    // says where inside it the rule's own features were found.
    std::vector<std::uint64_t> vas;
    // The matched rule's static scope: "function" / "basic block" / "instruction" /
    // "file", or empty when the rule declares none. Not to be confused with `kind`,
    // which is an address *type* (code vs data) and says nothing about scope.
    std::string scope;
    // Per container VA in `vas`, the addresses the rule's own features matched at.
    // Sorted/unique, always inside the region, and possibly absent for a container:
    // a consumer that wants a precise position uses these and falls back to the
    // container VA, which is also what a record written before this field existed
    // leaves it to do.
    std::map<std::uint64_t, std::vector<std::uint64_t>> feature_vas;
    std::string kind = "data";  // "insn" if `vas` is non-empty, else "data"

    nlohmann::json to_json() const;
};

// Sort key from a position "Sequence:Steps" (hex), mirroring position_key().
std::pair<std::uint64_t, std::uint64_t> position_key(const std::string& position);

}  // namespace capa::stat
