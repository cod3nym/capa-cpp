// Writing capa's findings into the database: a colour and a comment at every address
// capa matched something at, so the results are visible while reading disassembly
// rather than only in the results window.
//
// Every change is recorded in a netnode so it can be undone exactly: colours are
// restored to whatever they were, and only the comment lines this plugin wrote are
// removed.
#pragma once

#include "pch.h"

#include <map>
#include <string>
#include <vector>

#include "analysis.h"

namespace idacapa {

// What capa has to say about each address, gathered from a results tree. The same map
// drives the disassembly comments and the pseudocode markers, so the two always agree.
using AnnotationMap = std::map<ea_t, std::vector<std::string>>;

// `subtree`, when given, restricts the walk to one rule.
AnnotationMap collect_annotations(const ResultsDoc& doc, const ResultNode* subtree = nullptr);

// The background colour written at every matched address.
//
// bgcolor_t is 0x00BBGGRR -- BLUE first, not red. Read as RGB, the constant below is a
// dark green (#1B5E20) and the one above it the bright cyan capa's own plugin uses;
// getting the order backwards is how a "green" ends up drawn in orange.
//
// Dark, because the line's text keeps its own colour: against a bright background a
// dark theme's light-grey disassembly is unreadable, which is the whole reason this
// changed.
inline constexpr bgcolor_t CAPA_HIGHLIGHT = 0x205E1B;

// What earlier builds wrote (capa's own #00C7E6). A database annotated by one of them
// still carries it, and removal has to recognise it or those highlights can never be
// taken back -- the colour is how removal tells its own work from the user's.
inline constexpr bgcolor_t CAPA_HIGHLIGHT_LEGACY = 0xE6C700;

// Every comment line this plugin writes starts with this, which is how removal knows
// what is ours.
extern const char* const ANNOTATION_PREFIX;

struct AnnotationStats {
    std::size_t addresses = 0;   // distinct addresses touched
    std::size_t comments = 0;    // comment lines added
};

// Colour and comment every match in `doc`. `subtree`, when given, restricts the work
// to one rule (the node and everything under it). Replaces any previous annotation.
AnnotationStats annotate(const ResultsDoc& doc, const ResultNode* subtree = nullptr);

// Undo whatever the last annotate() wrote: restore colours and strip our comment
// lines. Returns how many addresses were reverted.
std::size_t remove_annotations();

// Is there anything to remove?
bool has_annotations();

}  // namespace idacapa
