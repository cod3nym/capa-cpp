#include "render.h"

#include "match_retention.h"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

#include "render_tree.h"

namespace capa::render {

using nlohmann::json;

namespace {

constexpr const char* CAPA_CPP_VERSION = "capa-cpp 0.1.0";

// ---------------------------------------------------------------------------
// JSON serialization of addresses / features / statements / match trees
// ---------------------------------------------------------------------------

json address_json(const Address& a) {
    json j;
    switch (a.type) {
        case AddressType::NO_ADDRESS:
            j["type"] = "no address";
            j["value"] = nullptr;
            break;
        case AddressType::ABSOLUTE:
            j["type"] = "absolute";
            j["value"] = a.value;
            break;
        case AddressType::PROCESS:
            j["type"] = "process";
            j["value"] = json::array({a.ppid, a.pid});
            break;
        case AddressType::THREAD:
            j["type"] = "thread";
            j["value"] = json::array({a.ppid, a.pid, a.tid});
            break;
        case AddressType::CALL:
            j["type"] = "call";
            j["value"] = json::array({a.ppid, a.pid, a.tid, a.id});
            break;
        case AddressType::FILE_OFFSET:
            j["type"] = "file";
            j["value"] = a.value;
            break;
    }
    return j;
}

json addresses_json(const AddressSet& addrs) {
    // capa sorts locations; AddressSet already orders by Address::operator<.
    json arr = json::array();
    for (const auto& a : addrs) arr.push_back(address_json(a));
    return arr;
}

json feature_json(const Feature& f) {
    json j;
    auto with_desc = [&]() {
        if (!f.description.empty()) j["description"] = f.description;
    };
    switch (f.type) {
        case FeatureType::API: j["type"] = "api"; j["api"] = f.s; break;
        case FeatureType::Number: j["type"] = "number"; j["number"] = f.i; break;
        case FeatureType::Offset: j["type"] = "offset"; j["offset"] = f.i; break;
        case FeatureType::Mnemonic: j["type"] = "mnemonic"; j["mnemonic"] = f.s; break;
        case FeatureType::OperandNumber:
            j["type"] = "operand number"; j["index"] = f.index; j["operand number"] = f.i; break;
        case FeatureType::OperandOffset:
            j["type"] = "operand offset"; j["index"] = f.index; j["operand offset"] = f.i; break;
        case FeatureType::Property:
            j["type"] = "property"; j["property"] = f.s;
            if (!f.access.empty()) j["access"] = f.access;
            break;
        case FeatureType::Export: j["type"] = "export"; j["export"] = f.s; break;
        case FeatureType::Import: j["type"] = "import"; j["import"] = f.s; break;
        case FeatureType::Section: j["type"] = "section"; j["section"] = f.s; break;
        case FeatureType::FunctionName: j["type"] = "function name"; j["function name"] = f.s; break;
        case FeatureType::String: j["type"] = "string"; j["string"] = f.s; break;
        case FeatureType::Substring: j["type"] = "substring"; j["substring"] = f.s; break;
        case FeatureType::Regex: j["type"] = "regex"; j["regex"] = f.s; break;
        case FeatureType::Bytes: {
            j["type"] = "bytes";
            std::string hex;
            char buf[4];
            for (unsigned char c : f.s) { std::snprintf(buf, sizeof(buf), "%02x", c); hex += buf; }
            j["bytes"] = hex;
            break;
        }
        case FeatureType::MatchedRule: j["type"] = "match"; j["match"] = f.s; break;
        case FeatureType::Characteristic: j["type"] = "characteristic"; j["characteristic"] = f.s; break;
        case FeatureType::Class: j["type"] = "class"; j["class"] = f.s; break;
        case FeatureType::Namespace: j["type"] = "namespace"; j["namespace"] = f.s; break;
        case FeatureType::OS: j["type"] = "os"; j["os"] = f.s; break;
        case FeatureType::Arch: j["type"] = "arch"; j["arch"] = f.s; break;
        case FeatureType::Format: j["type"] = "format"; j["format"] = f.s; break;
        case FeatureType::BasicBlock: j["type"] = "basic block"; break;
    }
    with_desc();
    return j;
}

json statement_json(const Statement& s) {
    json j;
    switch (s.type) {
        case StatementType::And: j["type"] = "and"; break;
        case StatementType::Or: j["type"] = "or"; break;
        case StatementType::Not: j["type"] = "not"; break;
        case StatementType::Some:
            if (s.count == 0) j["type"] = "optional";
            else { j["type"] = "some"; j["count"] = s.count; }
            break;
        case StatementType::Range:
            j["type"] = "range";
            j["min"] = s.range_min;
            j["max"] = s.range_max;
            j["child"] = feature_json(s.range_child);
            break;
        case StatementType::Subscope:
            j["type"] = "subscope";
            j["scope"] = scope_to_string(s.subscope);
            break;
    }
    if (!s.description.empty()) j["description"] = s.description;
    return j;
}

// Serialize a match Result tree. match: features are left as match nodes (not spliced
// inline); the tree is otherwise a faithful ResultDocument Match.
json match_json(const Result& res) {
    json j;
    j["success"] = res.success;
    if (res.node_is_statement)
        j["node"] = json{{"type", "statement"}, {"statement", statement_json(*res.stmt)}};
    else
        j["node"] = json{{"type", "feature"}, {"feature", feature_json(res.feature)}};

    // captures (regex/substring)
    json captures = json::object();
    for (const auto& [str, locs] : res.captures) captures[str] = addresses_json(locs);
    j["captures"] = captures;

    // locations: on successful feature nodes and successful range statements
    bool set_locs = res.success &&
                    (!res.node_is_statement ||
                     (res.stmt && res.stmt->type == StatementType::Range));
    j["locations"] = set_locs ? addresses_json(res.locations) : json::array();

    json children = json::array();
    for (const auto& c : res.children) children.push_back(match_json(c));
    j["children"] = children;
    return j;
}

// A whole match: its evidence, or the stub that stands in for evidence that was not kept.
//
// The stub is spelled out rather than left as an empty Match, because a Match with no
// node and no children is otherwise indistinguishable from a serializer bug. Its shape is
// unchanged from when a truncated match was an emptied-out Result rather than a null
// pointer -- the document does not know how the matcher stores things.
json match_json(const MatchEvidence& evidence) {
    if (evidence) return match_json(*evidence);
    json j;
    j["success"] = true;
    j["truncated"] = true;
    j["node"] = nullptr;
    j["captures"] = json::object();
    j["locations"] = json::array();
    j["children"] = json::array();
    return j;
}

// The compact evidence for one match: the single feature node that completed it, rather
// than the tree that contains it. `--match-evidence`.
//
// Two sources, one shape. A leaf the matcher took before dropping the tree is used as it
// stands; otherwise one is found in the tree, which is how the paths that keep every tree
// (the static backends) get this without a retention pass of their own. Null when there is
// neither -- a stub from a run that did not ask for leaves -- said as `null` rather than as
// an empty object, so "no evidence" cannot be misread as "a feature with no name".
json evidence_leaf_json(const MatchEvidence& evidence) {
    const EvidenceKind* kind = nullptr;
    const AddressSet* locations = nullptr;
    EvidenceKind from_tree;

    if (evidence.leaf && evidence.leaf->kind) {
        kind = evidence.leaf->kind.get();
        locations = &evidence.leaf->locations;
    } else if (evidence.tree) {
        const Result* node = find_evidence_leaf(*evidence.tree);
        if (!node) return json(nullptr);
        from_tree = evidence_kind_of(*node);
        kind = &from_tree;
        locations = &node->locations;
    } else {
        return json(nullptr);
    }

    json j;
    j["feature"] = feature_json(kind->feature);
    // Only for the features that have one. An empty member on every other match is one
    // more thing per match in a document whose whole point is that it is small.
    if (!kind->captured.empty()) {
        j["captured"] = kind->captured;
        if (kind->captured_truncated) j["captured_truncated"] = true;
    }
    // The feature's own addresses, not the match address: for a span-of-calls rule the two
    // differ, and that difference is what makes the leaf worth shipping.
    j["locations"] = addresses_json(*locations);
    return j;
}

// ---------------------------------------------------------------------------
// att&ck / mbc meta parsing (Tactic::Technique::Sub [ID])
// ---------------------------------------------------------------------------

struct Spec {
    std::vector<std::string> parts;
    std::string id;
};

Spec parse_spec(const std::string& raw) {
    Spec s;
    std::string body = raw;
    // trailing " [ID]"
    auto lb = raw.rfind(" [");
    if (lb != std::string::npos && !raw.empty() && raw.back() == ']') {
        s.id = raw.substr(lb + 2, raw.size() - lb - 3);
        body = raw.substr(0, lb);
    }
    std::size_t start = 0;
    while (start <= body.size()) {
        auto sep = body.find("::", start);
        if (sep == std::string::npos) {
            s.parts.push_back(body.substr(start));
            break;
        }
        s.parts.push_back(body.substr(start, sep - start));
        start = sep + 2;
    }
    return s;
}

json attack_json(const std::string& raw) {
    Spec s = parse_spec(raw);
    json j;
    j["parts"] = s.parts;
    j["tactic"] = s.parts.size() > 0 ? s.parts[0] : "";
    j["technique"] = s.parts.size() > 1 ? s.parts[1] : "";
    j["subtechnique"] = s.parts.size() > 2 ? s.parts[2] : "";
    j["id"] = s.id;
    return j;
}

json mbc_json(const std::string& raw) {
    Spec s = parse_spec(raw);
    json j;
    j["parts"] = s.parts;
    j["objective"] = s.parts.size() > 0 ? s.parts[0] : "";
    j["behavior"] = s.parts.size() > 1 ? s.parts[1] : "";
    j["method"] = s.parts.size() > 2 ? s.parts[2] : "";
    j["id"] = s.id;
    return j;
}

// ---------------------------------------------------------------------------
// layout (capa loader.compute_{dynamic,static}_layout)
//
// The walk that decides *which* processes/threads/calls or functions/blocks are
// "matched" belongs to the backend, which owns the handles; by the time a Doc
// reaches here the layout is already resolved and this is pure serialization.
// ---------------------------------------------------------------------------

json layout_json(const Doc& doc) {
    if (doc.flavor == Flavor::Dynamic) {
        json processes = json::array();
        for (const DynProcess& p : doc.dyn_layout) {
            json threads = json::array();
            for (const DynThread& t : p.matched_threads) {
                json calls = json::array();
                for (const DynCall& c : t.matched_calls)
                    calls.push_back(
                        json{{"address", address_json(c.address)}, {"name", c.name}});
                threads.push_back(
                    json{{"address", address_json(t.address)}, {"matched_calls", calls}});
            }
            processes.push_back(json{{"address", address_json(p.address)},
                                     {"name", p.name},
                                     {"matched_threads", threads}});
        }
        return json{{"processes", processes}};
    }

    json functions = json::array();
    for (const StaticFunction& f : doc.static_layout) {
        json bbs = json::array();
        for (const Address& bb : f.matched_basic_blocks)
            bbs.push_back(json{{"address", address_json(bb)}});
        json entry{{"address", address_json(f.address)}, {"matched_basic_blocks", bbs}};
        // capa-cpp extension; absent unless a minidump run set it.
        if (!f.region.empty()) entry["region"] = f.region;
        functions.push_back(std::move(entry));
    }
    return json{{"functions", functions}};
}

// ---------------------------------------------------------------------------
// per-rule meta + ResultDocument
// ---------------------------------------------------------------------------

json rule_meta_json(const Rule& r) {
    json m;
    m["name"] = r.name;
    if (!r.namespace_.empty()) m["namespace"] = r.namespace_;
    m["authors"] = r.authors;
    m["scopes"] = json{{"static", r.scopes.static_scope ? scope_to_string(*r.scopes.static_scope)
                                                        : "unsupported"},
                       {"dynamic", r.scopes.dynamic_scope ? scope_to_string(*r.scopes.dynamic_scope)
                                                          : "unsupported"}};
    json attack = json::array();
    for (const auto& a : r.attack) attack.push_back(attack_json(a));
    m["attack"] = attack;
    json mbc = json::array();
    for (const auto& b : r.mbc) mbc.push_back(mbc_json(b));
    m["mbc"] = mbc;
    m["references"] = r.references;
    m["examples"] = r.examples;
    if (!r.description.empty()) m["description"] = r.description;
    m["lib"] = r.is_lib;
    m["is_subscope_rule"] = r.is_subscope;
    return m;
}

std::string iso_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmv);
    return buf;
}

// The `meta` half of the ResultDocument.
//
// Split out from the `rules` half because the two have completely different sizes: this
// is bounded by the analysis (one entry per matched call, per rule), while `rules` is
// bounded by the trace and on a large one is two orders of magnitude bigger. Only the
// second needs streaming.
json document_meta(const RenderInput& in) {
    const Doc& doc = in.doc;
    const bool dynamic = doc.flavor == Flavor::Dynamic;

    json meta;
    meta["timestamp"] = iso_timestamp();
    meta["version"] = CAPA_CPP_VERSION;
    meta["argv"] = in.argv;
    meta["sample"] = json{{"md5", doc.hashes.md5},
                          {"sha1", doc.hashes.sha1},
                          {"sha256", doc.hashes.sha256},
                          {"path", in.input_path}};
    meta["flavor"] = dynamic ? "dynamic" : "static";

    json feature_counts;
    feature_counts["file"] = doc.file_feature_count;
    json scopes = json::array();
    for (const auto& [addr, count] : doc.scope_feature_counts)
        scopes.push_back(json{{"address", address_json(addr)}, {"count", count}});
    feature_counts[dynamic ? "processes" : "functions"] = scopes;
    // Emitted rather than left implicit: these numbers are the one part of the document
    // the filter changes, and a silently smaller count is worse than a flagged one.
    if (doc.feature_counts_filtered) feature_counts["filtered"] = true;

    json analysis;
    analysis["format"] = doc.format;
    analysis["arch"] = doc.arch;
    analysis["os"] = doc.os;
    analysis["extractor"] = doc.extractor_name;
    analysis["rules"] = doc.rule_paths;
    // No "layout" here: it is the one part of `meta` whose size follows the trace -- one
    // entry per call any rule matched at, which on a large trace is hundreds of thousands
    // -- and materializing it was, measurably, the whole of what the renderer cost after
    // the match trees began streaming. render_json_to() splices it in streamed.
    //
    // Distinguishes "the layout was not computed" from "nothing matched", which is what
    // an empty layout otherwise reads as. See Doc::layout_omitted.
    if (doc.layout_omitted) analysis["layout_omitted"] = true;
    // Says that `matches` holds addresses rather than (address, evidence) pairs. Not said
    // when the leaf shape is in force: that shape is pairs again, and a reader that keyed
    // off this one would take the second element for a match tree.
    if (doc.matches_only && !doc.match_evidence) analysis["matches_only"] = true;
    // Says that the second element of each pair is one evidence leaf, not a match tree.
    if (doc.match_evidence) analysis["match_evidence"] = true;
    // Says that an element is a pair only where a tree was kept, and a bare address
    // otherwise. Not said alongside either of the two above: they leave no placeholder to
    // drop, so it would name a shape the document does not have. As with those two, at
    // most one of the three names the element shape, and none means every element is an
    // (address, tree) pair.
    if (doc.sparse_evidence && !doc.matches_only && !doc.match_evidence)
        analysis["sparse_evidence"] = true;
    analysis["feature_counts"] = feature_counts;
    // capa-cpp extension: the memory regions a minidump run scanned.
    if (!doc.regions.empty()) {
        json regions = json::array();
        for (const RegionInfo& r : doc.regions)
            regions.push_back(json{{"base", r.base},
                                   {"size", r.size},
                                   {"name", r.name},
                                   {"kind", r.kind},
                                   {"path", r.path},
                                   {"arch", r.arch}});
        analysis["regions"] = regions;
    }
    meta["analysis"] = analysis;
    return meta;
}

// Batches the many small pieces a streamed document is made of into writes worth making.
// Serializing a match tree produces a few dozen bytes; handing each of those to a
// std::function that ends in fwrite would spend more time in the call than in the copy.
class JsonSink {
public:
    explicit JsonSink(const JsonWriter& write) : write_(write) { buf_.reserve(kChunk * 2); }

    // The flush that matters is the explicit one at the end of the document; this is only
    // the safety net for a caller who forgets. It swallows, because the writer can throw
    // and a destructor that throws while an exception is already propagating terminates
    // the process -- and on the way out of an exception a half-written document is not
    // worth completing anyway.
    ~JsonSink() noexcept {
        try {
            flush();
        } catch (...) {
        }
    }

    JsonSink(const JsonSink&) = delete;
    JsonSink& operator=(const JsonSink&) = delete;

    void put(const char* s) { put(std::string_view(s)); }
    void put(std::string_view s) {
        buf_.append(s);
        if (buf_.size() >= kChunk) flush();
    }
    // Serialized with the same settings json::dump() uses for a whole document, which is
    // what makes the streamed bytes identical to the materialized ones.
    void put(const json& j) { put(std::string_view(j.dump())); }

    void flush() {
        if (buf_.empty()) return;
        write_(buf_.data(), buf_.size());
        buf_.clear();
    }

private:
    static constexpr std::size_t kChunk = 1u << 20;  // 1 MiB
    const JsonWriter& write_;
    std::string buf_;
};

// Writes `obj`'s members without the enclosing braces, substituting `inject` for the
// value of `key`.
//
// `key` need not be present in `obj`: absent, it is written where it sorts. That is the
// point of comparing keys rather than carrying a hand-written list of the members either
// side of it -- nlohmann's default object is a sorted map, so "where it sorts" is exactly
// where a materialized document would have put it, and the streamed bytes stay identical
// to the built ones as members are added or removed over time.
// How the document's structure is spelled.
//
// JSON and MessagePack differ, for this document, in exactly two ways: JSON puts commas
// between members and MessagePack says up front how many there will be. Both are covered
// by "begin a container of n" plus a separator the encoder places or does not, so the
// walk that knows the document's shape can be written once and encoded either way.
class DocEncoder {
public:
    virtual ~DocEncoder() = default;
    virtual void begin_map(std::size_t members) = 0;
    virtual void end_map() = 0;
    virtual void begin_array(std::size_t elements) = 0;
    virtual void end_array() = 0;
    virtual void key(const std::string& k) = 0;
    virtual void value(const json& v) = 0;
};

// Emits exactly what building the whole document and calling dump() emits. The member
// counts are ignored: JSON does not declare them.
class JsonEncoder final : public DocEncoder {
public:
    explicit JsonEncoder(JsonSink& sink) : s_(sink) {}

    void begin_map(std::size_t) override { open("{"); }
    void end_map() override { close("}"); }
    void begin_array(std::size_t) override { open("["); }
    void end_array() override { close("]"); }

    void key(const std::string& k) override {
        separate();
        s_.put(json(k));  // escaped, not pasted in raw
        s_.put(":");
        after_key_ = true;
    }

    void value(const json& v) override {
        separate();
        s_.put(v);
    }

private:
    // A comma before every item except the first -- but not between a key and its value,
    // which `after_key_` absorbs.
    void separate() {
        if (after_key_) {
            after_key_ = false;
            return;
        }
        if (first_.empty()) return;
        if (!first_.back()) s_.put(",");
        first_.back() = false;
    }
    void open(const char* brace) {
        separate();
        s_.put(brace);
        first_.push_back(true);
    }
    void close(const char* brace) {
        s_.put(brace);
        first_.pop_back();
    }

    JsonSink& s_;
    std::vector<bool> first_;
    bool after_key_ = false;
};

// The same document as MessagePack. Containers declare their size, so nothing is written
// until the walk knows how many members it is about to produce -- which it always does,
// every count here being a container's size.
class MsgpackEncoder final : public DocEncoder {
public:
    explicit MsgpackEncoder(JsonSink& sink) : s_(sink) {}

    void begin_map(std::size_t n) override { header(n, 0x80, 0xde, 0xdf); }
    void end_map() override {}
    void begin_array(std::size_t n) override { header(n, 0x90, 0xdc, 0xdd); }
    void end_array() override {}

    void key(const std::string& k) override { str(k); }

    void value(const json& v) override {
        // A scalar or a small subtree; the containers this document is made of are
        // driven by the walk above, not encoded whole.
        const std::vector<std::uint8_t> bytes = json::to_msgpack(v);
        s_.put(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    }

private:
    void byte(std::uint8_t b) { s_.put(std::string_view(reinterpret_cast<const char*>(&b), 1)); }
    void be16(std::uint32_t v) {
        byte(static_cast<std::uint8_t>(v >> 8));
        byte(static_cast<std::uint8_t>(v));
    }
    void be32(std::uint32_t v) {
        be16(v >> 16);
        be16(v & 0xffff);
    }
    // fixmap/fixarray for the small case, then the 16- and 32-bit forms.
    void header(std::size_t n, std::uint8_t fix, std::uint8_t u16, std::uint8_t u32) {
        if (n < 16) {
            byte(static_cast<std::uint8_t>(fix | n));
        } else if (n <= 0xffff) {
            byte(u16);
            be16(static_cast<std::uint32_t>(n));
        } else {
            byte(u32);
            be32(static_cast<std::uint32_t>(n));
        }
    }
    void str(const std::string& v) {
        if (v.size() < 32) {
            byte(static_cast<std::uint8_t>(0xa0 | v.size()));
        } else if (v.size() <= 0xff) {
            byte(0xd9);
            byte(static_cast<std::uint8_t>(v.size()));
        } else if (v.size() <= 0xffff) {
            byte(0xda);
            be16(static_cast<std::uint32_t>(v.size()));
        } else {
            byte(0xdb);
            be32(static_cast<std::uint32_t>(v.size()));
        }
        s_.put(std::string_view(v));  // the bytes, not a JSON-encoded string
    }

    JsonSink& s_;
};

// Writes `obj` as a map, substituting `inject` for the value of `key`.
//
// `key` need not be present in `obj`: absent, it is written where it sorts. That is the
// point of comparing keys rather than carrying a hand-written list of the members either
// side of it -- nlohmann's default object is a sorted map, so "where it sorts" is exactly
// where a materialized document would have put it, and the streamed bytes stay identical
// to the built ones as members are added or removed over time.
template <class Inject>
void write_map_splicing(DocEncoder& e, const json& obj, const char* key, Inject&& inject) {
    const bool substituting = obj.contains(key);
    e.begin_map(obj.size() + (substituting ? 0 : 1));

    bool injected = false;
    auto put_injected = [&] {
        e.key(key);
        inject();
        injected = true;
    };
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (!injected && it.key() >= key) put_injected();
        if (it.key() == key) continue;  // substituted above
        e.key(it.key());
        e.value(it.value());
    }
    if (!injected) put_injected();

    e.end_map();
}

// The analysis layout, streamed. Shape-for-shape identical to layout_json().
void write_layout(DocEncoder& e, const Doc& doc) {
    if (doc.flavor != Flavor::Dynamic) {
        // Static layouts are bounded by the functions in an image, not by a trace, so
        // there is nothing here worth streaming.
        e.value(layout_json(doc));
        return;
    }

    e.begin_map(1);
    e.key("processes");
    e.begin_array(doc.dyn_layout.size());
    for (const DynProcess& p : doc.dyn_layout) {
        e.begin_map(3);
        e.key("address");
        e.value(address_json(p.address));
        e.key("matched_threads");
        e.begin_array(p.matched_threads.size());
        for (const DynThread& t : p.matched_threads) {
            e.begin_map(2);
            e.key("address");
            e.value(address_json(t.address));
            e.key("matched_calls");
            e.begin_array(t.matched_calls.size());
            for (const DynCall& c : t.matched_calls) {
                e.begin_map(2);
                e.key("address");
                e.value(address_json(c.address));
                e.key("name");
                e.value(json(c.name));
                e.end_map();
            }
            e.end_array();
            e.end_map();
        }
        e.end_array();
        e.key("name");
        e.value(json(p.name));
        e.end_map();
    }
    e.end_array();
    e.end_map();
}

// ---------------------------------------------------------------------------
// text-rendering helpers
// ---------------------------------------------------------------------------

// rules that were matched only as a subrule of another rule (capa find_subrule_matches):
// collect every successful match: feature value across all match trees.
std::unordered_set<std::string> collect_subrule_matches(const MatchResults& matches) {
    std::unordered_set<std::string> out;
    std::function<void(const Result&)> walk = [&](const Result& res) {
        if (!res.node_is_statement && res.feature.type == FeatureType::MatchedRule && res.success)
            out.insert(res.feature.s);
        for (const auto& c : res.children) walk(c);
    };
    for (const auto& [name, results] : matches)
        for (const auto& [addr, evidence] : results)
            if (evidence) walk(*evidence);  // a capped match kept no tree to walk
    return out;
}

// non-lib capability rules, hidden if only matched as a subrule; sorted by (namespace, name)
std::vector<std::shared_ptr<Rule>> capability_rules(const RenderInput& in) {
    // Walking in.matches only finds the `match:` features in trees that survived the
    // per-rule tree cap, so a rule whose every subrule appearance was capped away would
    // wrongly be shown as a top-level capability. The matcher collects the same set from
    // every tree; use it when it is there.
    std::unordered_set<std::string> walked;
    if (in.subrule_matches == nullptr) walked = collect_subrule_matches(in.matches);
    const std::unordered_set<std::string>& subrules =
        in.subrule_matches != nullptr ? *in.subrule_matches : walked;
    std::vector<std::shared_ptr<Rule>> out;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (!rule || rule->is_lib || rule->is_subscope) continue;
        if (subrules.count(name)) continue;
        out.push_back(rule);
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a->namespace_ != b->namespace_) return a->namespace_ < b->namespace_;
        return a->name < b->name;
    });
    return out;
}

std::size_t match_count(const MatchResults& matches, const std::string& name) {
    auto it = matches.find(name);
    return it == matches.end() ? 0 : it->second.size();
}

std::vector<std::string> split_lines(const std::string& s) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        auto nl = s.find('\n', start);
        if (nl == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, nl - start));
        start = nl + 1;
    }
    return out;
}

// simple 2-column table renderer; multi-line second-column cells align under col 2.
std::string table(const std::string& c1, const std::string& c2,
                  const std::vector<std::pair<std::string, std::string>>& rows) {
    std::size_t w1 = c1.size();
    for (const auto& [a, b] : rows) {
        for (const auto& line : split_lines(a)) w1 = std::max(w1, line.size());
    }
    std::ostringstream os;
    auto pad = [](const std::string& s, std::size_t w) {
        return s.size() >= w ? s : s + std::string(w - s.size(), ' ');
    };
    if (!c1.empty() || !c2.empty()) {
        os << pad(c1, w1) << " | " << c2 << "\n";
        os << std::string(w1, '-') << "-+-"
           << std::string(std::max<std::size_t>(c2.size(), 1), '-') << "\n";
    }
    std::string cont(w1, ' ');
    for (const auto& [a, b] : rows) {
        auto blines = split_lines(b);
        os << pad(a, w1) << " | " << (blines.empty() ? "" : blines[0]) << "\n";
        for (std::size_t k = 1; k < blines.size(); ++k)
            os << cont << " | " << blines[k] << "\n";
    }
    return os.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// public renderers
// ---------------------------------------------------------------------------

namespace {

// The document's shape, once, for either encoding.
//
// The key order is the one nlohmann::json produces for the equivalent document: its
// default object is a std::map, so members come out sorted, and "meta" < "rules",
// "matches" < "meta" < "source". Written this way the streamed JSON is identical to the
// materialized bytes rather than merely equivalent. MessagePack does not care about
// order, and follows the same one so that the two are diffable against each other.
void write_document(DocEncoder& e, const RenderInput& in) {
    // Counted first because MessagePack declares a map's size before its contents; the
    // filter here is the same one the loop below applies.
    std::size_t rule_count = 0;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (rule && rule->is_subscope) continue;
        ++rule_count;
    }

    // `meta` is small apart from the layout, which is spliced in streamed rather than
    // built -- see write_map_splicing.
    const json meta = document_meta(in);

    e.begin_map(2);
    e.key("meta");
    write_map_splicing(e, meta, "analysis", [&] {
        write_map_splicing(e, meta.at("analysis"), "layout", [&] { write_layout(e, in.doc); });
    });

    e.key("rules");
    e.begin_map(rule_count);
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (rule && rule->is_subscope) continue;  // subscope rules excluded from output

        e.key(name);
        e.begin_map(3);

        e.key("matches");
        e.begin_array(results.size());
        for (const auto& [addr, evidence] : results) {
            // Between the two: the address, and the one leaf that completed the match.
            // Three small members against a recursive tree, and it answers the question
            // the lean shape cannot -- which feature this rule actually held on.
            if (in.doc.match_evidence) {
                e.value(json::array({address_json(addr), evidence_leaf_json(evidence)}));
                continue;
            }
            // The lean shape carries the address alone. The pair's second element would
            // be a placeholder saying "no evidence was kept", which this whole mode says
            // once in `meta.analysis.matches_only` -- and repeated 673,556 times it was
            // two thirds of the document.
            if (in.doc.matches_only) {
                e.value(address_json(addr));
                continue;
            }
            // The same reasoning applied to one match rather than to the mode: a match
            // whose tree was dropped has nothing to say, and saying it costs three times
            // what the address alone costs. Only the matches that kept a tree stay pairs.
            if (in.doc.sparse_evidence && is_truncated_match(evidence)) {
                e.value(address_json(addr));
                continue;
            }
            // The one place the peak is set: a single match tree, built and dropped.
            e.value(json::array({address_json(addr), match_json(evidence)}));
        }
        e.end_array();

        e.key("meta");
        e.value(rule ? rule_meta_json(*rule) : json::object());
        e.key("source");
        e.value(json(rule ? rule->definition : std::string()));

        e.end_map();
    }
    e.end_map();

    e.end_map();
}

}  // namespace

void render_json_to(const RenderInput& in, const JsonWriter& write, DocFormat format) {
    JsonSink sink(write);
    if (format == DocFormat::MsgPack) {
        MsgpackEncoder e(sink);
        write_document(e, in);
    } else {
        JsonEncoder e(sink);
        write_document(e, in);
    }
    sink.flush();
}

std::string render_json(const RenderInput& in) {
    std::string out;
    render_json_to(in, [&out](const char* data, std::size_t size) { out.append(data, size); });
    return out;
}

std::string render_default(const RenderInput& in) {
    std::ostringstream os;

    const Doc& doc = in.doc;

    os << table("", "",
                {{"md5", doc.hashes.md5},
                 {"sha1", doc.hashes.sha1},
                 {"sha256", doc.hashes.sha256},
                 {"analysis", doc.flavor == Flavor::Dynamic ? "dynamic" : "static"},
                 {"os", doc.os},
                 {"format", doc.format},
                 {"arch", doc.arch},
                 {"path", in.input_path}});
    os << "\n";

    // ATT&CK / MBC aggregation across capability rules
    auto rules = capability_rules(in);

    std::map<std::string, std::set<std::string>> attack;  // tactic -> {technique [id]}
    std::map<std::string, std::set<std::string>> mbc;     // objective -> {behavior [id]}
    for (const auto& rule : rules) {
        for (const auto& a : rule->attack) {
            Spec s = parse_spec(a);
            if (s.parts.empty()) continue;
            std::string tech = s.parts.size() > 1 ? s.parts[1] : "";
            if (s.parts.size() > 2) tech += "::" + s.parts[2];
            if (!s.id.empty()) tech += " [" + s.id + "]";
            attack[s.parts[0]].insert(tech);
        }
        for (const auto& b : rule->mbc) {
            Spec s = parse_spec(b);
            if (s.parts.empty()) continue;
            std::string beh = s.parts.size() > 1 ? s.parts[1] : "";
            if (!s.id.empty()) beh += " [" + s.id + "]";
            mbc[s.parts[0]].insert(beh);
        }
    }
    if (!attack.empty()) {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& [tactic, techs] : attack) {
            std::string joined;
            for (const auto& t : techs) { if (!joined.empty()) joined += "\n"; joined += t; }
            std::string up = tactic;
            std::transform(up.begin(), up.end(), up.begin(), ::toupper);
            rows.emplace_back(up, joined);
        }
        os << table("ATT&CK Tactic", "ATT&CK Technique", rows) << "\n";
    }
    if (!mbc.empty()) {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& [obj, behs] : mbc) {
            std::string joined;
            for (const auto& b : behs) { if (!joined.empty()) joined += "\n"; joined += b; }
            std::string up = obj;
            std::transform(up.begin(), up.end(), up.begin(), ::toupper);
            rows.emplace_back(up, joined);
        }
        os << table("MBC Objective", "MBC Behavior", rows) << "\n";
    }

    // capability table
    if (rules.empty()) {
        os << "no capabilities found\n";
    } else {
        std::vector<std::pair<std::string, std::string>> rows;
        for (const auto& rule : rules) {
            std::size_t n = match_count(in.matches, rule->name);
            std::string cap = rule->name;
            if (n > 1) cap += " (" + std::to_string(n) + " matches)";
            rows.emplace_back(cap, rule->namespace_);
        }
        os << table("Capability", "Namespace", rows);
    }

    return os.str();
}

// ---- vverbose ----

std::string render_vverbose(const RenderInput& in) {
    std::ostringstream os;

    // rule ordering: by (namespace, name), skip subscope rules
    std::vector<std::shared_ptr<Rule>> rules;
    for (const auto& [name, results] : in.matches) {
        auto rule = in.ruleset.get(name);
        if (!rule || rule->is_subscope) continue;
        rules.push_back(rule);
    }
    std::sort(rules.begin(), rules.end(), [](const auto& a, const auto& b) {
        if (a->namespace_ != b->namespace_) return a->namespace_ < b->namespace_;
        return a->name < b->name;
    });

    for (const auto& rule : rules) {
        const auto& results = in.matches.at(rule->name);
        os << rule->name;
        if (results.size() > 1) os << " (" << results.size() << " matches)";
        if (rule->is_lib) os << " (library rule)";
        os << "\n";
        if (!rule->namespace_.empty()) os << "  namespace  " << rule->namespace_ << "\n";
        if (!rule->authors.empty()) {
            os << "  author     ";
            for (std::size_t k = 0; k < rule->authors.size(); ++k) {
                if (k) os << ", ";
                os << rule->authors[k];
            }
            os << "\n";
        }
        // the label must follow the flavor of *this* analysis: preferring the
        // dynamic scope unconditionally would mislabel every static match.
        Scope sc = in.doc.flavor == Flavor::Dynamic
                       ? rule->scopes.dynamic_scope.value_or(
                             rule->scopes.static_scope.value_or(Scope::FILE))
                       : rule->scopes.static_scope.value_or(
                             rule->scopes.dynamic_scope.value_or(Scope::FILE));
        os << "  scope      " << scope_to_string(sc) << "\n";
        for (const auto& m : rule->mbc) os << "  mbc        " << m << "\n";
        if (!rule->description.empty()) os << "  description " << rule->description << "\n";

        MatchCtx ctx{in.ruleset, in.matches};
        int shown = 0;
        for (const auto& [addr, evidence] : results) {
            if (rule->is_lib && shown >= 1) break;  // lib rules: only first match
            os << "  " << scope_to_string(sc) << " @ " << format_address(addr) << "\n";
            os << render_match_tree(ctx, evidence, 2);
            ++shown;
        }
        os << "\n";
    }

    if (rules.empty()) os << "no capabilities found\n";
    return os.str();
}

}  // namespace capa::render
