// Running capa over the open IDA database, and modelling the results the way capa's
// own IDA plugin does.
//
// capa explorer shows one tree: rule -> the scope it matched in -> the statements and
// features that made it match, three columns wide ("Rule Information", "Address",
// "Details"). ResultNode is that tree. It is built once, by porting capa's
// model.py::render_capa_doc_*, so the display strings match the Python plugin's.
//
// The tree holds finished text rather than live match objects: a capa Result points
// into the RuleSet that produced it, so keeping strings means the windows never have
// to hold rules alive, and the whole tree serializes into the database for free.
#pragma once

#include "pch.h"

#include <string>
#include <vector>

namespace idacapa {

// What a row stands for. Drives the icon-ish prefix, whether the row participates in
// annotation, and how "by function" regroups things.
enum class NodeKind {
    Rule,          // a matched rule
    RuleMatch,     // a `match:` reference to another rule
    Function,      // function(name) scope node
    BasicBlock,    // basic block(loc_...) scope node
    Instruction,   // instruction(loc_...) scope node
    Subscope,      // subscope(basic block) and friends
    Statement,     // and / or / optional / N or more / count(...)
    Feature,       // a leaf feature
};

struct ResultNode {
    NodeKind kind = NodeKind::Feature;
    std::string info;     // column 0, "Rule Information"
    std::string details;  // column 2, "Details"
    ea_t address = BADADDR;

    // capa highlights exactly the rows that stand for something at an address you can
    // look at: instruction, byte and string views. Those are the rows this plugin
    // colours and comments too.
    bool highlightable = false;

    std::vector<ResultNode> children;
};

// Bumped whenever the shape of the cached JSON changes. A cache written by an older
// build parses as valid JSON but means something else, so it has to be recognised and
// discarded rather than read as if it were current — otherwise every field comes back
// empty and the window fills with blank rows.
// 3: added ResultsDoc::skipped_note (the system-module filter).
inline constexpr int RESULTS_CACHE_VERSION = 3;

struct ResultsDoc {
    std::string rules_dir;
    // "skipped N function(s) in M system module(s): ..." when the system-module filter
    // dropped anything, else empty. Kept in the doc so the cached results explain
    // themselves too, not just the run that produced them.
    std::string skipped_note;
    std::size_t function_count = 0;
    std::size_t feature_count = 0;
    std::size_t rules_loaded = 0;
    std::size_t match_count = 0;  // rules that matched, i.e. rules.size()
    std::vector<ResultNode> rules;

    bool empty() const { return rules.empty(); }

    std::string to_json() const;
    // Returns an empty doc — `valid` false — for anything that is not a cache this
    // build wrote: unparseable, or written by a different schema version.
    static ResultsDoc from_json(const std::string& text);

    bool valid = false;
};

// "name (N matches)" -> "name". A rule row's label carries its match count, so anything
// that needs the rule's actual name has to take it back off again.
std::string strip_match_count(const std::string& label);

// The same results regrouped as capa's "show results by function" checkbox does:
// one node per function, with the rules that matched inside it beneath. Rule matches
// that are not inside a function are dropped, as in capa.
ResultsDoc group_by_function(const ResultsDoc& doc);

// Run capa over the open database. Shows a wait box and honours cancellation, so it
// must be called from the UI thread. Returns false and fills `error` on failure or
// when the user cancelled (with `error` empty in the cancel case).
bool run_analysis(const std::string& rules_dir, ResultsDoc& out, std::string& error);

// Is the open database something this plugin can analyse at all?
bool database_is_supported(std::string& why_not);

// Does this look like a .NET assembly? capa analyses those with its dnfile backend,
// which is not ported, so the IDA path sees only the native stub and finds nothing.
bool database_is_dotnet();

}  // namespace idacapa
