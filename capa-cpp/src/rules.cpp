#include "rules.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include <yaml-cpp/yaml.h>

namespace capa {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Scope helpers
// ---------------------------------------------------------------------------

std::string scope_to_string(Scope s) {
    switch (s) {
        case Scope::FILE: return "file";
        case Scope::PROCESS: return "process";
        case Scope::THREAD: return "thread";
        case Scope::SPAN_OF_CALLS: return "span of calls";
        case Scope::CALL: return "call";
        case Scope::FUNCTION: return "function";
        case Scope::BASIC_BLOCK: return "basic block";
        case Scope::INSTRUCTION: return "instruction";
        case Scope::GLOBAL: return "global";
        case Scope::UNSUPPORTED: return "unsupported";
    }
    return "unsupported";
}

std::optional<Scope> scope_from_string(const std::string& s) {
    if (s == "file") return Scope::FILE;
    if (s == "process") return Scope::PROCESS;
    if (s == "thread") return Scope::THREAD;
    if (s == "span of calls") return Scope::SPAN_OF_CALLS;
    if (s == "call") return Scope::CALL;
    if (s == "function") return Scope::FUNCTION;
    if (s == "basic block") return Scope::BASIC_BLOCK;
    if (s == "instruction") return Scope::INSTRUCTION;
    if (s == "global") return Scope::GLOBAL;
    return std::nullopt;
}

bool is_static_scope(Scope s) {
    return s == Scope::FILE || s == Scope::GLOBAL || s == Scope::FUNCTION ||
           s == Scope::BASIC_BLOCK || s == Scope::INSTRUCTION;
}
bool is_dynamic_scope(Scope s) {
    return s == Scope::FILE || s == Scope::GLOBAL || s == Scope::PROCESS ||
           s == Scope::THREAD || s == Scope::SPAN_OF_CALLS || s == Scope::CALL;
}

namespace {

// subscope nesting order (build_statements is_subscope_compatible)
const std::vector<Scope> STATIC_SCOPE_ORDER = {Scope::FILE, Scope::FUNCTION, Scope::BASIC_BLOCK,
                                               Scope::INSTRUCTION};
const std::vector<Scope> DYNAMIC_SCOPE_ORDER = {Scope::FILE, Scope::PROCESS, Scope::THREAD,
                                                Scope::SPAN_OF_CALLS, Scope::CALL};

int index_of(const std::vector<Scope>& order, Scope s) {
    for (int k = 0; k < static_cast<int>(order.size()); ++k)
        if (order[k] == s) return k;
    return -1;
}

bool is_subscope_compatible(std::optional<Scope> scope, Scope subscope) {
    if (!scope) return false;
    if (index_of(STATIC_SCOPE_ORDER, subscope) >= 0) {
        int a = index_of(STATIC_SCOPE_ORDER, subscope);
        int b = index_of(STATIC_SCOPE_ORDER, *scope);
        return b >= 0 && a >= b;
    }
    if (index_of(DYNAMIC_SCOPE_ORDER, subscope) >= 0) {
        int a = index_of(DYNAMIC_SCOPE_ORDER, subscope);
        int b = index_of(DYNAMIC_SCOPE_ORDER, *scope);
        return b >= 0 && a >= b;
    }
    return false;
}

// ---------------------------------------------------------------------------
// scalar parsing (parse_int / parse_range / parse_bytes / descriptions)
// ---------------------------------------------------------------------------

std::string strip(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    std::size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool ends_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::int64_t parse_int(const std::string& in) {
    // capa parses with Python int(s, base), which ignores *surrounding whitespace* but
    // rejects any other trailing junk. std::stoull / std::stoll instead stop at the first
    // invalid character, so "0x1G" would silently become 1 -- a rule matching a different
    // value than its author wrote. So: strip like Python, then require that the remainder
    // be fully consumed. (Stripping matters in practice: `- number: 2  = WH_KEYBOARD` has
    // two spaces before the `=`, leaving "2 " after the description split.)
    // InvalidRule is not a std::exception, so the throws below propagate past the catch
    // rather than being re-wrapped.
    const std::string s = strip(in);
    // We strip the `0x` prefix ourselves, which hands stoull a bare body -- and stoull
    // (strtoull) then does its *own* leading-whitespace-and-sign skip on it. Those chars
    // count toward `pos`, so the fully-consumed check below would pass "0x-1" (as -1) and
    // "0x 10" (as 16), both of which Python's int(s, 16) rejects. Require a hex digit first.
    auto hex_body = [&s](std::string body) {
        if (body.empty() || !std::isxdigit(static_cast<unsigned char>(body[0])))
            throw InvalidRule{"invalid integer: " + s};
        return body;
    };
    try {
        std::size_t pos = 0;
        if (starts_with(s, "-0x") || starts_with(s, "-0X")) {
            std::string body = hex_body(s.substr(3));
            std::uint64_t u = std::stoull(body, &pos, 16);
            if (pos != body.size()) throw InvalidRule{"invalid integer: " + s};
            // Negate in the *unsigned* domain: `-(int64)u` is signed-overflow UB once
            // u > INT64_MAX. Magnitudes past 2^63 have no int64 representation at all --
            // capa keeps them as arbitrary-precision ints, but wrapping here would yield a
            // different, small number that could spuriously match (e.g. -0xFFFFFFFFFFFFFFFF
            // -> 1), so skip the rule loudly instead. Unlike the positive branch below, the
            // wrap carries no intended meaning here. -0x8000000000000000 == INT64_MIN is
            // exactly representable and stays legal.
            if (u > (std::uint64_t{1} << 63)) throw InvalidRule{"integer out of range: " + s};
            return static_cast<std::int64_t>(std::uint64_t{0} - u);
        }
        if (starts_with(s, "0x") || starts_with(s, "0X")) {
            std::string body = hex_body(s.substr(2));
            std::uint64_t u = std::stoull(body, &pos, 16);
            if (pos != body.size()) throw InvalidRule{"invalid integer: " + s};
            return static_cast<std::int64_t>(u);  // wraps large u64 to negative (see models.cpp)
        }
        std::int64_t v = std::stoll(s, &pos, 10);
        if (pos != s.size()) throw InvalidRule{"invalid integer: " + s};
        return v;
    } catch (const std::exception&) {
        throw InvalidRule{"invalid integer: " + s};
    }
}

// returns (min, max); either may be absent (unbounded)
std::pair<std::optional<std::int64_t>, std::optional<std::int64_t>> parse_range(
    const std::string& in) {
    if (!starts_with(in, "(") || !ends_with(in, ")")) throw InvalidRule{"invalid range: " + in};
    std::string s = in.substr(1, in.size() - 2);
    auto comma = s.find(',');
    std::string min_spec = strip(comma == std::string::npos ? s : s.substr(0, comma));
    std::string max_spec = comma == std::string::npos ? "" : strip(s.substr(comma + 1));
    std::optional<std::int64_t> mn, mx;
    if (!min_spec.empty()) {
        mn = parse_int(min_spec);
        if (*mn < 0) throw InvalidRule{"range min less than zero"};
    }
    if (!max_spec.empty()) {
        mx = parse_int(max_spec);
        if (*mx < 0) throw InvalidRule{"range max less than zero"};
    }
    if (mn && mx && *mx < *mn) throw InvalidRule{"range max less than min"};
    return {mn, mx};
}

std::string parse_bytes(const std::string& in) {
    std::string hex;
    for (char c : in)
        if (c != ' ') hex += c;
    if (hex.size() % 2 != 0) throw InvalidRule{"invalid bytes: " + in};
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string raw;
    for (std::size_t k = 0; k + 1 < hex.size(); k += 2) {
        int hi = nibble(hex[k]), lo = nibble(hex[k + 1]);
        if (hi < 0 || lo < 0) throw InvalidRule{"invalid bytes hex: " + in};
        raw.push_back(static_cast<char>((hi << 4) | lo));
    }
    if (raw.size() > 0x100) throw InvalidRule{"bytes value too large"};
    return raw;
}

const char* DESCRIPTION_SEPARATOR = " = ";

// Split "value = desc" for non-string types. Returns value part; sets desc if present.
std::string split_description(const std::string& s, std::string& desc_out,
                              const std::string& existing_desc) {
    auto pos = s.find(DESCRIPTION_SEPARATOR);
    if (pos == std::string::npos) return s;
    if (!existing_desc.empty())
        throw InvalidRule{"only one description allowed: " + s};
    std::string value = s.substr(0, pos);
    std::string desc = s.substr(pos + 3);
    if (desc.empty()) throw InvalidRule{"description cannot be empty: " + s};
    desc_out = desc;
    return value;
}

// trim_dll_part: kernel32.CreateFileA -> CreateFileA (keeps ordinal `.#` and `::`)
std::string trim_dll_part(const std::string& api) {
    if (api.find(".#") != std::string::npos) return api;
    if (std::count(api.begin(), api.end(), '.') == 1 &&
        api.find("::") == std::string::npos) {
        auto dot = api.find('.');
        return api.substr(dot + 1);
    }
    return api;
}

// ---------------------------------------------------------------------------
// leaf feature construction (parse_feature + build_feature)
// ---------------------------------------------------------------------------

// Build a leaf feature (or count() Range) into a Node.
Node build_feature(const std::string& key, const std::string& raw, const std::string& node_desc);

// parse_feature dispatch for count(...) inner terms and the default branch.
// Constructs a Feature of the given `key` type from an already-parsed value/desc.
Feature make_feature(const std::string& key, const std::string& value, const std::string& desc) {
    if (key == "api") return Feature::api(trim_dll_part(value), desc);
    if (key == "string") return Feature::string_factory(value, desc);
    if (key == "substring") return Feature::substring(value, desc);
    if (key == "bytes") return Feature::bytes(parse_bytes(value), desc);
    if (key == "number") return Feature::number(parse_int(value), desc);
    if (key == "offset") return Feature::offset(parse_int(value), desc);
    if (key == "mnemonic") return Feature::mnemonic(value, desc);
    if (key == "basic block" || key == "basic blocks") return Feature::basic_block();
    if (key == "characteristic") return Feature::characteristic(value, desc);
    if (key == "export") return Feature::export_(value, desc);
    if (key == "import") return Feature::import_(value, desc);
    if (key == "section") return Feature::section(value, desc);
    if (key == "match") return Feature::matched_rule(value, desc);
    if (key == "function-name") return Feature::function_name(value, desc);
    if (key == "os") return Feature::os(value, desc);
    if (key == "format") return Feature::format(value, desc);
    if (key == "arch") return Feature::arch(value, desc);
    if (key == "class") return Feature::klass(value, desc);
    if (key == "namespace") return Feature::namespace_(value, desc);
    if (starts_with(key, "operand[") && ends_with(key, "].number")) {
        int idx = std::stoi(key.substr(8, key.size() - 8 - 8));
        return Feature::operand_number(idx, parse_int(value), desc);
    }
    if (starts_with(key, "operand[") && ends_with(key, "].offset")) {
        int idx = std::stoi(key.substr(8, key.size() - 8 - 8));
        return Feature::operand_offset(idx, parse_int(value), desc);
    }
    if (starts_with(key, "property/")) {
        std::string access = key.substr(9);
        if (access != ACCESS_READ && access != ACCESS_WRITE)
            throw InvalidRule{"unexpected property access: " + access};
        return Feature::property(value, access, desc);
    }
    throw InvalidRule{"unexpected statement: " + key};
}

Node build_feature(const std::string& key, const std::string& raw, const std::string& node_desc) {
    // count(TERM) -> Range
    if (starts_with(key, "count(") && ends_with(key, ")")) {
        std::string term = key.substr(6, key.size() - 7);
        std::string inner_key = term;
        std::string arg;
        auto paren = term.find('(');
        if (paren != std::string::npos) {
            inner_key = term.substr(0, paren);
            arg = term.substr(paren + 1);
            if (!arg.empty() && arg.back() == ')') arg.pop_back();
        }

        Feature feature = [&]() -> Feature {
            if (arg.empty()) {
                // e.g. count(basic block)
                return make_feature(inner_key, "", "");
            }
            if (inner_key == "string") {
                return Feature::string(arg);
            }
            std::string desc;
            std::string value = split_description(arg, desc, "");
            return make_feature(inner_key, value, desc);
        }();

        auto stmt = std::make_shared<Statement>();
        stmt->type = StatementType::Range;
        stmt->range_child = feature;
        stmt->description = node_desc;

        std::string count = strip(raw);
        if (ends_with(count, " or more")) {
            stmt->range_min = parse_int(count.substr(0, count.size() - 8));
            stmt->range_max = ~0ull;
        } else if (ends_with(count, " or fewer")) {
            stmt->range_min = 0;
            stmt->range_max = static_cast<std::uint64_t>(parse_int(count.substr(0, count.size() - 9)));
        } else if (starts_with(count, "(")) {
            auto [mn, mx] = parse_range(count);
            stmt->range_min = mn.value_or(0);
            stmt->range_max = mx ? static_cast<std::uint64_t>(*mx) : ~0ull;
        } else {
            std::int64_t n = parse_int(count);
            stmt->range_min = n;
            stmt->range_max = static_cast<std::uint64_t>(n);
        }
        return Node::of_statement(stmt);
    }

    if (starts_with(key, "com/")) {
        // COM features need a GUID database we do not port; skip the whole rule.
        throw InvalidRule{"com/ features not supported"};
    }

    // default: a single feature. string type takes the value verbatim (no inline desc).
    std::string desc = node_desc;
    std::string value = raw;
    bool is_string_like = (key == "string" || key == "substring");
    if (!is_string_like) {
        value = split_description(raw, desc, node_desc);
    }
    return Node::of_feature(make_feature(key, value, desc));
}

// ---------------------------------------------------------------------------
// statement tree construction (build_statements)
// ---------------------------------------------------------------------------

bool is_description_child(const YAML::Node& n) {
    return n.IsMap() && n.size() == 1 && n["description"];
}

// the single non-"description" key of a map node
std::string main_key(const YAML::Node& d) {
    for (const auto& kv : d) {
        std::string k = kv.first.as<std::string>();
        if (k != "description") return k;
    }
    return "";
}

Node build_statements(const YAML::Node& d, const Scopes& scopes);

// build children of a compound statement, extracting a statement-level description
std::vector<Node> build_children(const YAML::Node& seq, const Scopes& scopes,
                                 std::string& desc_out) {
    std::vector<Node> children;
    for (const auto& child : seq) {
        if (is_description_child(child)) {
            desc_out = child["description"].as<std::string>();
            continue;
        }
        children.push_back(build_statements(child, scopes));
    }
    return children;
}

// order-preserving dedup by a cheap structural key (best-effort; mirrors `unique`)
void dedup_children(std::vector<Node>& children) {
    // We can't cheaply hash arbitrary subtrees; dedup only exact duplicate leaf features,
    // which is the common case `unique` targets. Statements are left as-is.
    std::vector<Node> out;
    std::vector<Feature> seen;
    for (auto& c : children) {
        if (!c.is_statement) {
            bool dup = false;
            for (const auto& f : seen)
                if (f == c.feature) {
                    dup = true;
                    break;
                }
            if (dup) continue;
            seen.push_back(c.feature);
        }
        out.push_back(std::move(c));
    }
    children = std::move(out);
}

std::shared_ptr<Statement> make_compound(StatementType t, std::vector<Node> children,
                                         const std::string& desc) {
    auto s = std::make_shared<Statement>();
    s->type = t;
    s->children = std::move(children);
    s->description = desc;
    return s;
}

std::shared_ptr<Statement> make_subscope(Scope scope, Node child, const std::string& desc) {
    auto s = std::make_shared<Statement>();
    s->type = StatementType::Subscope;
    s->subscope = scope;
    s->children.push_back(std::move(child));
    s->description = desc;
    return s;
}

Node build_statements(const YAML::Node& d, const Scopes& scopes) {
    std::string key = main_key(d);

    auto subscope_child = [&](Scope sc, const Scopes& inner) -> Node {
        (void)sc;
        const YAML::Node& seq = d[key];
        if (!seq.IsSequence() || seq.size() < 1)
            throw InvalidRule{"subscope must have a child"};
        // capa requires exactly one child statement for these subscopes (only the
        // `instruction` scope below takes several, as an implicit And). Silently keeping
        // the first child would widen the rule and yield false positives, so reject the
        // rule instead -- the loader turns this into a "skipping rule" warning.
        std::vector<YAML::Node> kids;  // Node is a shared handle; copying is cheap and safe
        for (const auto& c : seq) {
            if (is_description_child(c)) continue;
            kids.push_back(c);
        }
        if (kids.size() != 1) throw InvalidRule{"subscope must have exactly one child statement"};
        return build_statements(kids[0], inner);
    };

    if (key == "and" || key == "or" || key == "optional" || key == "not" ||
        ends_with(key, " or more")) {
        std::string desc;
        std::vector<Node> children = build_children(d[key], scopes, desc);
        dedup_children(children);
        if (key == "and") return Node::of_statement(make_compound(StatementType::And, std::move(children), desc));
        if (key == "or") return Node::of_statement(make_compound(StatementType::Or, std::move(children), desc));
        if (key == "not") {
            if (children.size() != 1) throw InvalidRule{"not must have exactly one child"};
            return Node::of_statement(make_compound(StatementType::Not, std::move(children), desc));
        }
        // Some (N or more / optional)
        auto s = make_compound(StatementType::Some, std::move(children), desc);
        if (key == "optional")
            s->count = 0;
        else
            s->count = static_cast<int>(parse_int(strip(key.substr(0, key.size() - 8))));
        return Node::of_statement(s);
    }

    // subscopes
    if (key == "process") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::PROCESS))
            throw InvalidRule{"`process` subscope incompatible with scope"};
        Scopes inner; inner.dynamic_scope = Scope::PROCESS;
        return Node::of_statement(make_subscope(Scope::PROCESS, subscope_child(Scope::PROCESS, inner), ""));
    }
    if (key == "thread") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::THREAD))
            throw InvalidRule{"`thread` subscope incompatible with scope"};
        Scopes inner; inner.dynamic_scope = Scope::THREAD;
        return Node::of_statement(make_subscope(Scope::THREAD, subscope_child(Scope::THREAD, inner), ""));
    }
    if (key == "span of calls") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::SPAN_OF_CALLS))
            throw InvalidRule{"`span of calls` subscope incompatible with scope"};
        Scopes inner; inner.dynamic_scope = Scope::SPAN_OF_CALLS;
        return Node::of_statement(make_subscope(Scope::SPAN_OF_CALLS, subscope_child(Scope::SPAN_OF_CALLS, inner), ""));
    }
    if (key == "call") {
        if (!is_subscope_compatible(scopes.dynamic_scope, Scope::CALL))
            throw InvalidRule{"`call` subscope incompatible with scope"};
        Scopes inner; inner.dynamic_scope = Scope::CALL;
        return Node::of_statement(make_subscope(Scope::CALL, subscope_child(Scope::CALL, inner), ""));
    }
    if (key == "function") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::FUNCTION))
            throw InvalidRule{"`function` subscope incompatible with scope"};
        Scopes inner; inner.static_scope = Scope::FUNCTION;
        return Node::of_statement(make_subscope(Scope::FUNCTION, subscope_child(Scope::FUNCTION, inner), ""));
    }
    if (key == "basic block") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::BASIC_BLOCK))
            throw InvalidRule{"`basic block` subscope incompatible with scope"};
        Scopes inner; inner.static_scope = Scope::BASIC_BLOCK;
        return Node::of_statement(make_subscope(Scope::BASIC_BLOCK, subscope_child(Scope::BASIC_BLOCK, inner), ""));
    }
    if (key == "instruction") {
        if (!is_subscope_compatible(scopes.static_scope, Scope::INSTRUCTION))
            throw InvalidRule{"`instruction` subscope incompatible with scope"};
        Scopes inner; inner.static_scope = Scope::INSTRUCTION;
        const YAML::Node& seq = d[key];
        // collect non-description children
        std::vector<Node> kids;
        std::string desc;
        for (const auto& c : seq) {
            if (is_description_child(c)) { desc = c["description"].as<std::string>(); continue; }
            kids.push_back(build_statements(c, inner));
        }
        Node inner_node = (kids.size() == 1)
                              ? std::move(kids[0])
                              : Node::of_statement(make_compound(StatementType::And, std::move(kids), ""));
        return Node::of_statement(make_subscope(Scope::INSTRUCTION, std::move(inner_node), desc));
    }

    // leaf feature
    std::string raw = d[key].IsScalar() ? d[key].Scalar() : "";
    std::string node_desc = d["description"] ? d["description"].as<std::string>() : "";
    return build_feature(key, raw, node_desc);
}

Scopes parse_scopes(const YAML::Node& meta) {
    if (meta["scope"]) throw InvalidRule{"legacy rule.meta.scope not supported"};
    const YAML::Node& sc = meta["scopes"];
    if (!sc || !sc.IsMap()) throw InvalidRule{"rule must specify meta.scopes map"};
    if (!sc["static"]) throw InvalidRule{"static scope must be provided"};
    if (!sc["dynamic"]) throw InvalidRule{"dynamic scope must be provided"};

    std::string st = sc["static"].as<std::string>();
    std::string dy = sc["dynamic"].as<std::string>();

    Scopes out;
    if (st != "unsupported") {
        auto s = scope_from_string(st);
        if (!s || !is_static_scope(*s)) throw InvalidRule{st + " is not a valid static scope"};
        out.static_scope = *s;
    }
    if (dy != "unsupported") {
        auto s = scope_from_string(dy);
        if (!s || !is_dynamic_scope(*s)) throw InvalidRule{dy + " is not a valid dynamic scope"};
        out.dynamic_scope = *s;
    }
    if (!out.static_scope && !out.dynamic_scope)
        throw InvalidRule{"at least one scope must be specified"};
    return out;
}

std::vector<std::string> as_str_list(const YAML::Node& n) {
    std::vector<std::string> out;
    if (!n) return out;
    if (n.IsSequence()) {
        for (const auto& e : n)
            if (e.IsScalar()) out.push_back(e.Scalar());
    } else if (n.IsScalar()) {
        out.push_back(n.Scalar());
    }
    return out;
}

// ---------------------------------------------------------------------------
// feature-index scoring (capa RuleSet._score_feature / _index_rules_by_feature)
// ---------------------------------------------------------------------------

// Score a feature by expected selectivity (higher == rarer == better for indexing).
int score_feature(const std::unordered_map<std::string, int>& scores_by_rule, const Feature& f) {
    switch (f.type) {
        case FeatureType::MatchedRule: {
            auto it = scores_by_rule.find(f.s);
            // unknown dependency (e.g. a static-only derived rule referenced in dynamic
            // mode) never matches here, so treat as very selective. capa returns 9.
            return it == scores_by_rule.end() ? 9 : it->second;
        }
        case FeatureType::Number:
        case FeatureType::OperandNumber: {
            std::int64_t v = f.i;
            // small numbers, and (unsigned) values near u32-max / u64-max -> common.
            // In our signed int64 rep, capa's u64-near-max range folds into small negatives,
            // which the first check already covers.
            if ((v >= -0x8000 && v <= 0x8000) || (v >= 0xFFFFFF00LL && v <= 0xFFFFFFFFLL))
                return 3;
            return 7;
        }
        case FeatureType::Substring:
        case FeatureType::Regex:
        case FeatureType::Bytes:
            return 0;  // non-hashable; can't index by hash lookup
        case FeatureType::String: return 9;
        case FeatureType::API: return 8;
        case FeatureType::Export: return 7;
        case FeatureType::Class:
        case FeatureType::Namespace:
        case FeatureType::Property:
        case FeatureType::Import:
        case FeatureType::Section:
        case FeatureType::FunctionName: return 5;
        case FeatureType::Characteristic:
        case FeatureType::Offset:
        case FeatureType::OperandOffset: return 4;
        case FeatureType::Mnemonic: return 2;
        case FeatureType::BasicBlock: return 1;
        case FeatureType::OS:
        case FeatureType::Arch:
        case FeatureType::Format: return 0;
    }
    return 0;
}

struct ScoredFeatures {
    int score = 0;
    std::vector<Feature> features;
};

void union_feature(std::vector<Feature>& into, const Feature& f) {
    for (const auto& e : into)
        if (e == f) return;
    into.push_back(f);
}

// Walk a rule's logic tree, choosing the minimal set of most-selective features that
// must be present for the rule to match. Returns nullopt for un-indexable subtrees
// (not / optional / count-with-min-0). Ports RuleSet._index_rules_by_feature::rec.
std::optional<ScoredFeatures> index_rec(const Node& node,
                                        const std::unordered_map<std::string, int>& scores) {
    if (!node.is_statement) {
        return ScoredFeatures{score_feature(scores, node.feature), {node.feature}};
    }
    const Statement& s = *node.stmt;
    switch (s.type) {
        case StatementType::Not:
            return std::nullopt;
        case StatementType::Subscope:
            return std::nullopt;  // lowered away before indexing; be safe
        case StatementType::Some:
            if (s.count == 0) return std::nullopt;
            break;  // count>0 handled as OR below
        case StatementType::Range:
            if (s.range_min == 0) return std::nullopt;  // min 0 -> optional/not-like
            return ScoredFeatures{score_feature(scores, s.range_child), {s.range_child}};
        case StatementType::And: {
            std::optional<ScoredFeatures> best;
            for (const auto& c : s.children) {
                auto r = index_rec(c, scores);
                if (!r) continue;
                if (!best || r->score > best->score ||
                    (r->score == best->score && r->features.size() < best->features.size()))
                    best = std::move(r);
            }
            return best;  // may be nullopt if all children un-indexable
        }
        case StatementType::Or:
            break;  // handled below
    }
    // Or / Some(count>0): must index every branch (union), score = min branch score.
    ScoredFeatures out;
    out.score = 1000000;
    for (const auto& c : s.children) {
        auto r = index_rec(c, scores);
        if (!r) {
            // an un-indexable OR branch means the rule can match without any indexed
            // feature; fall back to always-evaluate.
            return std::nullopt;
        }
        out.score = std::min(out.score, r->score);
        for (const auto& f : r->features) union_feature(out.features, f);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

std::vector<std::string> Rule::namespace_prefixes() const {
    std::vector<std::string> out;
    std::string ns = namespace_;
    while (!ns.empty()) {
        out.push_back(ns);
        auto pos = ns.rfind('/');
        if (pos == std::string::npos) break;
        ns = ns.substr(0, pos);
    }
    return out;
}

MatchableRule Rule::matchable() const {
    return MatchableRule{name, namespace_prefixes(), &root};
}

Rule Rule::from_yaml(const std::string& yaml_text) {
    YAML::Node doc;
    try {
        doc = YAML::Load(yaml_text);
    } catch (const std::exception& e) {
        throw InvalidRule{std::string("yaml parse error: ") + e.what()};
    }
    if (!doc["rule"]) throw InvalidRule{"missing top-level `rule`"};
    const YAML::Node& r = doc["rule"];
    const YAML::Node& meta = r["meta"];
    if (!meta || !meta["name"]) throw InvalidRule{"missing rule.meta.name"};

    Rule rule;
    rule.name = meta["name"].as<std::string>();
    rule.scopes = parse_scopes(meta);
    if (meta["namespace"]) rule.namespace_ = meta["namespace"].as<std::string>();
    if (meta["description"]) rule.description = meta["description"].as<std::string>();
    rule.authors = as_str_list(meta["authors"]);
    rule.attack = as_str_list(meta["att&ck"]);
    rule.mbc = as_str_list(meta["mbc"]);
    rule.references = as_str_list(meta["references"]);
    rule.examples = as_str_list(meta["examples"]);
    if (meta["lib"]) rule.is_lib = meta["lib"].as<bool>();
    rule.definition = yaml_text;

    const YAML::Node& features = r["features"];
    if (!features || !features.IsSequence() || features.size() != 1)
        throw InvalidRule{"rule must begin with a single top-level statement"};

    rule.root = build_statements(features[0], rule.scopes);
    if (rule.root.is_statement && rule.root.stmt->type == StatementType::Subscope)
        throw InvalidRule{"top level statement may not be a subscope"};
    return rule;
}

// ---------------------------------------------------------------------------
// dependencies / subscope extraction / ordering
// ---------------------------------------------------------------------------

namespace {

void collect_deps(const Node& node, std::set<std::string>& out) {
    if (!node.is_statement) {
        if (node.feature.type == FeatureType::MatchedRule) out.insert(node.feature.s);
        return;
    }
    const Statement& s = *node.stmt;
    if (s.type == StatementType::Range) {
        if (s.range_child.type == FeatureType::MatchedRule) out.insert(s.range_child.s);
        return;
    }
    for (const auto& c : s.children) collect_deps(c, out);
}

// resolve a rule's direct dependency rule-names (expanding namespaces)
std::set<std::string> rule_dependencies(
    const Rule& rule,
    const std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>>& by_ns) {
    std::set<std::string> raw;
    collect_deps(rule.root, raw);
    std::set<std::string> deps;
    for (const auto& d : raw) {
        auto it = by_ns.find(d);
        if (it != by_ns.end()) {
            for (const auto& r : it->second) deps.insert(r->name);
        } else {
            deps.insert(d);
        }
    }
    return deps;
}

// walk tree, replace Subscope children with MatchedRule features, yield new rules
void extract_subscopes_rec(Node& node, const std::string& parent_name, int& counter,
                           std::vector<std::shared_ptr<Rule>>& out) {
    if (!node.is_statement) return;
    Statement& s = *node.stmt;
    for (auto& child : s.children) {
        if (child.is_statement && child.stmt->type == StatementType::Subscope) {
            Statement& sub = *child.stmt;
            std::string name = parent_name + "/subscope-" + std::to_string(counter++);

            auto nr = std::make_shared<Rule>();
            nr->name = name;
            if (is_static_scope(sub.subscope))
                nr->scopes.static_scope = sub.subscope;
            else
                nr->scopes.dynamic_scope = sub.subscope;
            nr->root = std::move(sub.children.at(0));
            nr->is_lib = true;
            nr->is_subscope = true;
            nr->parent = parent_name;

            // replace the subscope child with a match: reference
            child = Node::of_feature(Feature::matched_rule(name));

            out.push_back(nr);
        }
    }
    // recurse into remaining children (replaced ones are now features, so they stop)
    for (auto& child : s.children) extract_subscopes_rec(child, parent_name, counter, out);
}

}  // namespace

// ---------------------------------------------------------------------------
// RuleSet
// ---------------------------------------------------------------------------

RuleSet::RuleSet(std::vector<std::shared_ptr<Rule>> rules) {
    source_rule_count_ = rules.size();

    // 1. extract subscope rules (mutates parents, appends synthetic lib rules)
    int counter = 0;
    std::vector<std::shared_ptr<Rule>> all = rules;
    // process like a stack so nested subscopes are handled
    std::vector<std::shared_ptr<Rule>> stack = rules;
    while (!stack.empty()) {
        auto rule = stack.back();
        stack.pop_back();
        std::vector<std::shared_ptr<Rule>> produced;
        extract_subscopes_rec(rule->root, rule->name, counter, produced);
        for (auto& nr : produced) {
            all.push_back(nr);
            stack.push_back(nr);
        }
    }
    rules_ = std::move(all);

    // 2. index by name + namespace
    for (const auto& r : rules_) by_name_[r->name] = r;
    for (const auto& r : rules_) {
        std::string ns = r->namespace_;
        while (!ns.empty()) {
            by_namespace_[ns].push_back(r);
            auto pos = ns.rfind('/');
            if (pos == std::string::npos) break;
            ns = ns.substr(0, pos);
        }
    }

    // 2b. report `match:` targets that no loaded rule provides. Nothing downstream fails
    //     loudly on these: the topological walk below skips unknown names, and match() just
    //     never produces the matched_rule feature -- so every dependent silently stops
    //     matching and the report still looks clean. capa instead raises (its
    //     topologically_order_rules does rules_by_name[dep]). We keep loading, since a
    //     skipped rule shouldn't take the whole run down, but say what it hollowed out.
    {
        std::map<std::string, std::vector<std::string>> unresolved;  // dep -> dependents
        for (const auto& r : rules_)
            for (const auto& dep : rule_dependencies(*r, by_namespace_))
                if (!by_name_.count(dep)) unresolved[dep].push_back(r->name);
        for (const auto& [dep, dependents] : unresolved) {
            std::string who;
            for (std::size_t i = 0; i < dependents.size() && i < 3; ++i)
                who += (i ? ", " : "") + dependents[i];
            if (dependents.size() > 3)
                who += " (+" + std::to_string(dependents.size() - 3) + " more)";
            std::fprintf(stderr,
                         "warning: no rule provides `%s`; %zu rule(s) can never match: %s\n",
                         dep.c_str(), dependents.size(), who.c_str());
        }
    }

    // 3. topological order over all rules (deps before dependents)
    std::vector<std::shared_ptr<Rule>> ordered;
    {
        std::unordered_set<std::string> seen;
        std::function<void(const std::shared_ptr<Rule>&)> rec =
            [&](const std::shared_ptr<Rule>& r) {
                if (seen.count(r->name)) return;
                seen.insert(r->name);  // insert before recursion to tolerate cycles
                for (const auto& dep : rule_dependencies(*r, by_namespace_)) {
                    auto it = by_name_.find(dep);
                    if (it != by_name_.end()) rec(it->second);
                }
                ordered.push_back(r);
            };
        for (const auto& r : rules_) rec(r);
    }

    // 4. build the per-scope feature index. Index scopes small->large (capa order) with
    // a shared scores_by_rule map, so a MatchedRule dependency's selectivity score is
    // available when a higher-scope rule that references it is indexed.
    // Index every lower scope (static and dynamic) before FILE, which may reference
    // matched rules from any of them. Each rule lives in exactly one scope, so the two
    // scope chains never collide in the shared scores_by_rule map.
    const Scope scopes[] = {Scope::INSTRUCTION, Scope::BASIC_BLOCK, Scope::FUNCTION,
                            Scope::CALL,        Scope::SPAN_OF_CALLS, Scope::THREAD,
                            Scope::PROCESS,     Scope::FILE};
    std::unordered_map<std::string, int> scores_by_rule;
    for (Scope sc : scopes) build_scope_index(sc, ordered, scores_by_rule);
}

void RuleSet::build_scope_index(Scope scope, const std::vector<std::shared_ptr<Rule>>& ordered,
                                std::unordered_map<std::string, int>& scores_by_rule) {
    ScopeIndex& si = scope_index_[scope];

    // topologically-ordered rules for this scope
    for (const auto& r : ordered)
        if (r->scopes.contains(scope)) si.matchables.push_back(r->matchable());
    si.ptrs.reserve(si.matchables.size());
    for (const auto& m : si.matchables) si.ptrs.push_back(&m);
    for (int i = 0; i < static_cast<int>(si.matchables.size()); ++i)
        si.index_by_name[si.matchables[i].name] = i;

    // index each rule by its most-selective feature(s)
    for (int i = 0; i < static_cast<int>(si.matchables.size()); ++i) {
        const MatchableRule& mr = si.matchables[i];
        auto scored = mr.root ? index_rec(*mr.root, scores_by_rule) : std::nullopt;
        if (!scored || scored->features.empty()) {
            si.always_rules.push_back(i);
            scores_by_rule[mr.name] = 9;  // couldn't index; assume selective
            continue;
        }
        scores_by_rule[mr.name] = scored->score;

        std::vector<Feature> string_feats;
        for (const auto& f : scored->features) {
            if (f.type == FeatureType::Regex || f.type == FeatureType::Substring) {
                string_feats.push_back(f);
            } else if (f.type == FeatureType::Bytes) {
                // no bytes features on the dynamic path; treat as always-evaluate if seen
                si.always_rules.push_back(i);
            } else {
                si.rules_by_feature[f].push_back(i);
            }
        }
        if (!string_feats.empty()) si.string_rules.emplace_back(i, std::move(string_feats));
    }
}

const std::vector<const MatchableRule*>& RuleSet::rules_for_scope(Scope scope) const {
    static const std::vector<const MatchableRule*> empty;
    auto it = scope_index_.find(scope);
    return it == scope_index_.end() ? empty : it->second.ptrs;
}

// capa RuleSet._match: evaluate only the candidate rules whose selective feature is
// present, in topological order, re-queuing dependents as their prerequisites match.
//
// Rather than copying the (possibly large) feature set to hold the match features added
// during matching, we add them into `features` in place and undo those exact additions
// before returning, so `features` is observably unchanged to the caller.
MatchResults RuleSet::match_indexed(const ScopeIndex& si, FeatureSet& features,
                                    const Address& addr) const {
    // worklist of candidate rule indices, processed smallest-index (topological) first.
    // std::set dedups on insert, so no separate "seen" set is needed: dependents always
    // have a larger topo index than the rule that produced them, so an already-processed
    // (smaller) index is never re-queued.
    std::set<int> worklist;
    auto add = [&](int i) { worklist.insert(i); };

    for (int i : si.always_rules) add(i);
    for (const auto& [f, locs] : features) {
        auto it = si.rules_by_feature.find(f);
        if (it != si.rules_by_feature.end())
            for (int idx : it->second) add(idx);
    }

    // rules indexed only by regex/substring: scan them against the String features.
    if (!si.string_rules.empty()) {
        FeatureSet string_features;
        for (const auto& [f, locs] : features)
            if (f.type == FeatureType::String) string_features[f] = locs;
        if (!string_features.empty()) {
            for (const auto& [idx, wanted] : si.string_rules) {
                for (const auto& w : wanted) {
                    if (eval_feature(w, string_features, true).success) {
                        add(idx);
                        break;
                    }
                }
            }
        }
    }

    MatchResults results;
    if (worklist.empty()) return results;

    // record match features we insert, so we can undo them before returning.
    struct Undo {
        Feature feat;
        bool key_created;
        bool addr_inserted;
    };
    std::vector<Undo> undo_log;
    auto add_match_feature = [&](const Feature& mf) {
        auto [it, created] = features.try_emplace(mf);
        bool inserted = it->second.insert(addr);
        if (created || inserted) undo_log.push_back({mf, created, inserted});
    };

    while (!worklist.empty()) {
        auto itmin = worklist.begin();
        int idx = *itmin;
        worklist.erase(itmin);

        const MatchableRule& rule = si.matchables[idx];
        if (!rule.root) continue;

        Result res = eval_node(*rule.root, features, /*short_circuit=*/true);
        if (!res.success) continue;

        res = eval_node(*rule.root, features, /*short_circuit=*/false);
        results[rule.name].emplace_back(addr, std::make_unique<Result>(std::move(res)));

        // add match features in place so dependent rules can match on them
        add_match_feature(Feature::matched_rule(rule.name));
        for (const auto& ns : rule.namespaces) add_match_feature(Feature::matched_rule(ns));

        // re-queue any rules indexed by this match (rule name or its namespaces)
        auto queue_dependents = [&](const Feature& mf) {
            auto it = si.rules_by_feature.find(mf);
            if (it != si.rules_by_feature.end())
                for (int di : it->second) add(di);
        };
        queue_dependents(Feature::matched_rule(rule.name));
        for (const auto& ns : rule.namespaces) queue_dependents(Feature::matched_rule(ns));
    }

    // undo our in-place additions (reverse order), restoring `features` exactly.
    for (auto it = undo_log.rbegin(); it != undo_log.rend(); ++it) {
        if (it->key_created) {
            features.erase(it->feat);
        } else if (it->addr_inserted) {
            auto f = features.find(it->feat);
            if (f != features.end()) f->second.erase(addr);
        }
    }

    return results;
}

MatchResults RuleSet::match(Scope scope, FeatureSet& features, const Address& addr) const {
    auto it = scope_index_.find(scope);
    if (it == scope_index_.end()) return {};
    return match_indexed(it->second, features, addr);
}

std::shared_ptr<Rule> RuleSet::get(const std::string& name) const {
    auto it = by_name_.find(name);
    return it == by_name_.end() ? nullptr : it->second;
}

std::set<std::string> RuleSet::dependencies_of(const std::string& name) const {
    auto it = by_name_.find(name);
    if (it == by_name_.end()) return {};
    return rule_dependencies(*it->second, by_namespace_);
}

RuleSet RuleSet::load_from_directory(const std::string& dir) {
    std::vector<std::shared_ptr<Rule>> rules;
    int skipped = 0;
    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".yml" && ext != ".yaml") continue;

        std::ifstream f(entry.path(), std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        try {
            rules.push_back(std::make_shared<Rule>(Rule::from_yaml(ss.str())));
        } catch (const InvalidRule& e) {
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: %s\n",
                         entry.path().string().c_str(), e.message.c_str());
        } catch (const std::exception& e) {
            // Rule::from_yaml only guards YAML::Load; a bad scalar (`lib: maybe` ->
            // YAML::TypedBadConversion) or a malformed key (`operand[x].number` ->
            // std::invalid_argument from stoi) escapes as a plain std::exception. Skip
            // that rule like any other unparseable one rather than killing the whole run.
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: %s\n",
                         entry.path().string().c_str(), e.what());
        } catch (...) {
            ++skipped;
            std::fprintf(stderr, "warning: skipping rule %s: unknown parse error\n",
                         entry.path().string().c_str());
        }
    }
    if (skipped)
        std::fprintf(stderr, "note: skipped %d unparseable rule(s)\n", skipped);
    if (rules.empty()) throw InvalidRule{"no rules found under " + dir};
    return RuleSet(std::move(rules));
}

}  // namespace capa
