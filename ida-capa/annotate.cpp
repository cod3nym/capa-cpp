#include "annotate.h"

#include <map>
#include <set>
#include <vector>

#include "settings.h"

using nlohmann::json;

namespace idacapa {

const char* const ANNOTATION_PREFIX = "capa: ";

namespace {

// Gathered before anything is written so each address gets one comment and one colour
// change however many rules hit it.
using Pending = std::map<ea_t, std::set<std::string>>;

std::string rule_name_of(const ResultNode& rule) { return strip_match_count(rule.info); }

// Walk a rule's subtree, collecting what to write where.
void collect(const ResultNode& node, const std::string& rule_label, Pending& out,
             bool is_root) {
    if (!is_root && node.address != BADADDR && is_mapped(node.address)) {
        // The scope nodes (function/basic block/instruction) say where the rule
        // matched; the highlightable feature rows say what made it match. Both are
        // worth pointing at, and everything else has no location of its own.
        const bool is_scope = node.kind == NodeKind::Function ||
                              node.kind == NodeKind::BasicBlock ||
                              node.kind == NodeKind::Instruction;
        if (is_scope) {
            out[node.address].insert(ANNOTATION_PREFIX + rule_label);
        } else if (node.highlightable) {
            out[node.address].insert(ANNOTATION_PREFIX + rule_label + " - " + node.info);
        }
    }
    for (const ResultNode& child : node.children) collect(child, rule_label, out, false);
}

// The record we keep so removal is exact: address -> the colour that was there before.
json load_record() {
    const std::string text = annotation_record();
    if (text.empty()) return json::array();
    try {
        json j = json::parse(text);
        if (j.is_array()) return j;
    } catch (const std::exception&) {
    }
    return json::array();
}

// Strip our own lines out of a comment, leaving anything the user wrote.
std::string strip_our_lines(const std::string& cmt) {
    std::string out;
    std::size_t pos = 0;
    while (pos <= cmt.size()) {
        std::size_t nl = cmt.find('\n', pos);
        std::string line = cmt.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (line.rfind(ANNOTATION_PREFIX, 0) != 0) {
            if (!out.empty()) out.push_back('\n');
            out += line;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return out;
}

}  // namespace

bool has_annotations() { return !load_record().empty(); }

AnnotationMap collect_annotations(const ResultsDoc& doc, const ResultNode* subtree) {
    Pending pending;
    if (subtree != nullptr) {
        collect(*subtree, rule_name_of(*subtree), pending, /*is_root=*/true);
    } else {
        for (const ResultNode& rule : doc.rules) {
            if (rule.kind == NodeKind::Function) {
                // "by function" view: the rules are one level down.
                for (const ResultNode& r : rule.children)
                    collect(r, rule_name_of(r), pending, /*is_root=*/true);
            } else {
                collect(rule, rule_name_of(rule), pending, /*is_root=*/true);
            }
        }
    }

    AnnotationMap out;
    for (const auto& [ea, lines] : pending)
        out[ea].assign(lines.begin(), lines.end());
    return out;
}

AnnotationStats annotate(const ResultsDoc& doc, const ResultNode* subtree) {
    // Start from a clean slate so colours are always restored to the user's own, never
    // to a previous capa highlight.
    remove_annotations();

    const AnnotationMap pending = collect_annotations(doc, subtree);

    AnnotationStats stats;
    json record = json::array();

    for (const auto& [ea, lines] : pending) {
        // remember the colour that was there, so removal can put it back
        record.push_back(json{{"ea", static_cast<std::uint64_t>(ea)},
                              {"color", static_cast<std::uint64_t>(get_item_color(ea))}});

        set_item_color(ea, CAPA_HIGHLIGHT);

        qstring existing;
        std::string cmt;
        if (get_cmt(&existing, ea, /*rptble=*/true) > 0) cmt = strip_our_lines(existing.c_str());
        for (const std::string& line : lines) {
            if (!cmt.empty()) cmt.push_back('\n');
            cmt += line;
            ++stats.comments;
        }
        set_cmt(ea, cmt.c_str(), /*rptble=*/true);
        ++stats.addresses;
    }

    set_annotation_record(record.dump());
    return stats;
}

std::size_t remove_annotations() {
    json record = load_record();
    std::size_t n = 0;

    for (const json& entry : record) {
        ea_t ea = static_cast<ea_t>(entry.value("ea", std::uint64_t{BADADDR}));
        if (ea == BADADDR || !is_mapped(ea)) continue;

        // Only put the old colour back if the current one is still ours: the user may
        // have recoloured it since, and that choice wins. "Ours" includes the colour
        // older builds wrote, so annotations made before the change can still be
        // removed by the build that comes after it.
        const bgcolor_t now = get_item_color(ea);
        if (now == CAPA_HIGHLIGHT || now == CAPA_HIGHLIGHT_LEGACY) {
            const bgcolor_t was =
                static_cast<bgcolor_t>(entry.value("color", std::uint64_t{DEFCOLOR}));
            // DEFCOLOR is what get_item_color() reports for an item with no colour of
            // its own, so setting it back would mark the item as *explicitly* coloured
            // white rather than leaving it plain. Clearing is what reverts it.
            if (was == DEFCOLOR)
                del_item_color(ea);
            else
                set_item_color(ea, was);
        }

        qstring existing;
        if (get_cmt(&existing, ea, /*rptble=*/true) > 0) {
            const std::string kept = strip_our_lines(existing.c_str());
            set_cmt(ea, kept.c_str(), /*rptble=*/true);
        }
        ++n;
    }

    clear_annotation_record();
    return n;
}

}  // namespace idacapa
