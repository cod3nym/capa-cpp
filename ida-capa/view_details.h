// The capa details pane: why the selected match matched.
//
// The explorer window files matches into folders by namespace, which IDA renders with
// a dirtree — and a dirtree's folders are not rows, so they cannot carry the statement
// and feature tree beneath a match. That tree lives here instead, in a plain custom
// viewer docked beside the explorer.
#pragma once

#include "pch.h"

#include <string>

#include "analysis.h"

namespace idacapa {

extern const char* const DETAILS_TITLE;

class DetailsView {
public:
    ~DetailsView();

    // Show one match: `rule` names it, `match` is the subtree to render.
    // `activate` raises the window; the explorer passes false when it is only
    // following the cursor, so focus stays where the user put it.
    void show(const std::string& rule_name, const std::string& ns, const ResultNode& match,
              bool activate);

    void show_message(const std::string& text, bool activate);

    void close();
    bool is_open() const { return m_widget != nullptr; }
    bool owns(TWidget* w) const { return w != nullptr && w == m_widget; }

    // IDA destroyed the window; forget it without touching it.
    void forget() { m_widget = nullptr; }

private:
    void render(const qstrvec_t& lines, bool activate);

    TWidget* m_widget = nullptr;
    strvec_t m_lines;
};

}  // namespace idacapa
