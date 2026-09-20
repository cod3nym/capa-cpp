// TTD report data model for capa-cpp.
//
// Ports capa/features/extractors/ttd/models.py: the neutral JSON "TTD report"
// emitted by ttdcapa-extract.exe. Parsing is tolerant of unknown keys.
//
// `params` (the rich per-argument decode) is parsed for completeness but is NOT
// used for matching — rule matching runs off `TtdCall.args` (mirrors capa).
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace capa::ttd {

// Deduplicating store for the strings a report repeats.
//
// A trace's call records are overwhelmingly made of a small vocabulary said over and over:
// on a beacon trace there are 25 distinct module names, 804 distinct API names, and the
// string arguments repeat 15.7 times each. Held inline, each of those costs a 32-byte
// std::string per call plus a heap block whenever it exceeds the small-string buffer --
// which two thirds of API names do. Held here, each distinct string is stored once and
// referred to by a 4-byte index.
//
// Index 0 is always the empty string, so a default-constructed record resolves to "".
class StringPool {
public:
    StringPool() { intern(std::string{}); }

    std::uint32_t intern(std::string s) {
        auto it = index_.find(s);
        if (it != index_.end()) return it->second;
        const auto id = static_cast<std::uint32_t>(strings_.size());
        strings_.push_back(std::move(s));
        index_.emplace(strings_.back(), id);
        return id;
    }

    const std::string& get(std::uint32_t id) const {
        return id < strings_.size() ? strings_[id] : strings_[0];
    }

    std::size_t size() const { return strings_.size(); }

    // Drops the lookup table, keeping the strings. Interning is a parse-time activity;
    // once the report is built the map is dead weight -- and on a large report it is the
    // same order of size as the strings it indexes.
    void seal() {
        index_.clear();
        index_.rehash(0);
    }

private:
    std::vector<std::string> strings_;
    // Owns its keys rather than viewing into `strings_`: a view would dangle for any
    // string short enough to live inside the std::string object, since growing the vector
    // moves those objects. The second copy is bounded by the *distinct* vocabulary --
    // tens of thousands of strings, single-digit MB even on a huge trace -- and seal()
    // returns it as soon as parsing is done.
    std::unordered_map<std::string, std::uint32_t> index_;
};

// One call argument: a JSON int or string (bools are tracked so they can be skipped
// at feature-extraction time, matching capa's `isinstance(arg, bool)` guard).
//
// 16 bytes rather than 48: only about 9% of arguments are strings, and an inline
// std::string charged all of them for it. `Report::arg_str` resolves the other 9%.
struct Arg {
    enum class Kind : std::uint8_t { Int, Str, Bool };
    Kind kind = Kind::Int;
    // Int/Bool: the value (unsigned > INT64_MAX stored bit-cast; see models.cpp).
    // Str: the index of the text in Report::strings.
    std::int64_t i = 0;
};

struct Import {
    std::string dll;
    std::string name;
    std::uint64_t va = 0;
};

struct Export {
    std::string name;
    std::uint64_t va = 0;
};

struct Section {
    std::string name;
    std::uint64_t va = 0;
};

struct File {
    std::vector<Import> imports;
    std::vector<Export> exports;
    std::vector<Section> sections;
    std::vector<std::string> strings;
};

struct Sample {
    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string name;
};

struct Trace {
    std::string path;
    std::string arch = "x64";
    std::string os = "windows";
};

// 80 bytes rather than the 152 an inline-everything Call costs.
//
// `module` and `api` are indices into Report::strings: a trace has a couple of dozen
// distinct modules and a few hundred distinct APIs, and holding each inline cost 64 bytes
// per call plus a heap block for the two thirds of API names too long for the small-string
// buffer.
//
// The arguments are a window into Report::args rather than a vector of their own. A
// per-call vector is 24 bytes of header plus a heap block each, and a trace has one per
// call -- two million allocations whose only content is a handful of 16-byte values.
// Report::args_of() reads the window back.
//
// `position` stays inline: it is distinct per call, so pooling it would store the same
// number of strings behind an extra indirection, and it always fits the small-string
// buffer anyway.
struct Call {
    std::int64_t tid = 0;
    std::int64_t seq = 0;
    std::string position;
    std::uint32_t module = 0;     // index into Report::strings
    std::uint32_t api = 0;        // index into Report::strings
    std::uint32_t arg_offset = 0;  // start of this call's window into Report::args
    std::uint32_t arg_count = 0;
    std::optional<std::int64_t> ret;
    // `params` intentionally omitted: display-only, not needed for matching or the
    // renderers we implement.
};

struct Process {
    std::int64_t pid = 0;
    std::int64_t ppid = 0;
    std::string name;
    std::vector<std::string> environ_strings;
    std::vector<std::int64_t> threads;
    std::vector<Call> calls;
};

struct Report {
    int version = 0;
    Trace trace;
    Sample sample;
    File file;
    std::vector<Process> processes;

    // Every repeated string in the call records: module names, API names, and string
    // arguments. Both parsers fill it; nothing else writes to it.
    StringPool strings;

    // Every call's arguments, back to back, in call order. A Call names its own run by
    // (arg_offset, arg_count); see args_of().
    std::vector<Arg> args;

    // Resolve a pooled index, and an Arg's text. `arg_str` is empty for a non-string
    // argument, whose `i` is a value rather than an index.
    const std::string& str(std::uint32_t id) const { return strings.get(id); }
    const std::string& arg_str(const Arg& a) const {
        return strings.get(a.kind == Arg::Kind::Str ? static_cast<std::uint32_t>(a.i) : 0);
    }

    // The arguments of `c`. Empty if the call recorded none.
    std::span<const Arg> args_of(const Call& c) const {
        return std::span<const Arg>(args).subspan(c.arg_offset, c.arg_count);
    }

    // Parse from a decoded JSON document (throws nlohmann exceptions on gross type
    // errors; tolerant of missing/unknown keys otherwise).
    static Report from_json(const nlohmann::json& j);
};

}  // namespace capa::ttd
