// Streaming reader for the TTD report JSON.
//
// Report::from_json takes a decoded nlohmann document, which means the whole report is
// materialized as a DOM and then copied into the model, both live at once. On a
// two-million-call slice of a real trace that is a 310 MB file costing 2.9 GB of peak --
// about nine and a half times the bytes on disk -- and it is the largest single
// allocation in a capa-cpp run.
//
// Nothing needs the DOM. The model is a strict subset of the document, and one field of
// the document is a large subset of the file: `params`, the per-argument decode, which
// models.h explicitly does not keep ("display-only, not needed for matching"). The DOM
// path parses every byte of it -- names, types, hex byte strings, decoded flag arrays --
// and then drops it.
//
// So read the report with a SAX handler that fills the model directly and skips `params`
// on the way past. Peak becomes the model alone, and the parse gets faster for the same
// reason.
//
// Report::from_json stays: embedders use it, and it is what this is checked against.
#pragma once

#include <istream>
#include <string>

#include "ttd/models.h"

namespace capa::ttd {

// Fills `out` from the report at `path`. Returns false and sets `error` on a parse
// failure or an unreadable file; `out` is then unspecified.
bool read_report_streaming(const std::string& path, Report& out, std::string& error);

}  // namespace capa::ttd
