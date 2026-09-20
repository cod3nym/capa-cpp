// Rules layer for capa-cpp.
//
// Ports capa/rules/__init__.py: Scope/Scopes, YAML rule parsing (build_statements /
// build_feature / parse_feature / parse_description / parse_int / parse_range /
// parse_bytes / count(...)), subscope extraction, dependency checking, topological
// ordering, namespace indexing, and per-scope partitioning (RuleSet).
//
// The optimized feature-index matcher is intentionally NOT ported; RuleSet::match
// runs the naive engine.match over the topologically-ordered rules for a scope.
#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine.h"

namespace capa {

// ---- Scope <-> string ----
std::string scope_to_string(Scope s);
std::optional<Scope> scope_from_string(const std::string& s);  // nullopt if unknown

bool is_static_scope(Scope s);
bool is_dynamic_scope(Scope s);

struct Scopes {
    std::optional<Scope> static_scope;
    std::optional<Scope> dynamic_scope;

    bool contains(Scope s) const {
        return (static_scope && *static_scope == s) || (dynamic_scope && *dynamic_scope == s);
    }
};

// Raised when a rule cannot be parsed (mirrors capa InvalidRule). Rules using
// unsupported constructs (e.g. com/) throw this and are skipped by the loader.
struct InvalidRule {
    std::string message;
};

struct Rule {
    std::string name;
    Scopes scopes;
    Node root;  // the top-level statement tree

    // meta (fields used by matching + renderers)
    std::string namespace_;
    std::vector<std::string> authors;
    std::string description;
    std::vector<std::string> attack;      // raw "att&ck" strings
    std::vector<std::string> mbc;         // raw "mbc" strings
    std::vector<std::string> references;
    std::vector<std::string> examples;
    bool is_lib = false;
    bool is_subscope = false;
    std::string parent;  // capa/parent for subscope rules

    std::string definition;  // raw YAML source (for -j / rendering)

    // namespace prefixes, e.g. "c2/file-transfer" -> {"c2/file-transfer", "c2"}
    std::vector<std::string> namespace_prefixes() const;

    // engine view (root pointer is stable while this Rule lives)
    MatchableRule matchable() const;

    // Parse one rule from YAML text. Throws InvalidRule on failure.
    static Rule from_yaml(const std::string& yaml_text);
};

class RuleSet {
public:
    RuleSet() = default;  // empty; assign from load_from_directory. Move is safe:
                          // internal pointers live in vector/map buffers that survive moves.
    explicit RuleSet(std::vector<std::shared_ptr<Rule>> rules);

    // Match the rules for `scope` against `features` at `addr`, using capa's feature
    // index to evaluate only candidate rules. `features` is mutated during matching
    // (match features are added so dependent rules can match) but restored to its
    // original contents before returning, so callers may keep using it.
    MatchResults match(Scope scope, FeatureSet& features, const Address& addr) const;

    const std::vector<const MatchableRule*>& rules_for_scope(Scope scope) const;

    std::shared_ptr<Rule> get(const std::string& name) const;
    bool contains(const std::string& name) const { return by_name_.count(name) != 0; }

    // Direct dependency rule-names of a rule (namespaces expanded). Used by the
    // span-of-calls dedup logic. Empty set if the rule is unknown.
    std::set<std::string> dependencies_of(const std::string& name) const;
    std::size_t size() const { return by_name_.size(); }
    std::size_t source_rule_count() const { return source_rule_count_; }

    const std::vector<std::shared_ptr<Rule>>& all_rules() const { return rules_; }

    // namespace -> rules (each prefix), for dependency expansion + rendering.
    const std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>>&
    rules_by_namespace() const {
        return by_namespace_;
    }

    // Load every .yml/.yaml rule under a directory tree. Skips rules that fail to
    // parse (e.g. com/ features), logging a warning. Throws on no rules found.
    static RuleSet load_from_directory(const std::string& dir);

private:
    // Per-scope: topologically-ordered rules plus capa's feature index, so match()
    // only evaluates the few candidate rules whose selective feature is present.
    struct ScopeIndex {
        std::vector<MatchableRule> matchables;      // topo order; index == position
        std::vector<const MatchableRule*> ptrs;     // same, as pointers
        std::unordered_map<std::string, int> index_by_name;
        // hashable selective feature -> rule indices that require it
        std::unordered_map<Feature, std::vector<int>> rules_by_feature;
        // rule index -> regex/substring features to scan against String features
        std::vector<std::pair<int, std::vector<Feature>>> string_rules;
        // rules that could not be indexed (rare); always treated as candidates
        std::vector<int> always_rules;
    };

    void build_scope_index(Scope scope, const std::vector<std::shared_ptr<Rule>>& ordered,
                           std::unordered_map<std::string, int>& scores_by_rule);
    MatchResults match_indexed(const ScopeIndex& si, FeatureSet& features,
                               const Address& addr) const;

    std::vector<std::shared_ptr<Rule>> rules_;  // owns all rules (incl. subscope rules)
    std::unordered_map<std::string, std::shared_ptr<Rule>> by_name_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<Rule>>> by_namespace_;

    std::map<Scope, ScopeIndex> scope_index_;

    std::size_t source_rule_count_ = 0;
};

}  // namespace capa
