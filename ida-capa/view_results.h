// The capa explorer window.
//
// A dockable form built with open_form(), holding the buttons and an embedded chooser.
// The chooser has a dirtree behind it — the same pairing IDA's Functions window uses —
// so matches are filed into folders by rule namespace, and expanding a folder is the
// tree control's own gesture rather than something bolted onto double-click.
//
// Rows are individual matches. A dirtree's folders are not rows and cannot carry the
// Address/Details columns, so the statement-and-feature tree beneath a match lives in
// the details pane (view_details.h) instead.
//
// **The dirtree object is created once and never replaced.** IDA keeps the pointer it
// was handed by get_dirtree(); swapping it under a live widget leaves IDA walking freed
// memory, which shows up as an access violation in ida.dll or as a wild allocation.
// When the results change, the tree's *contents* are emptied and refilled instead
// (unlink/rmdir, then mkdir/link) — the same operations IDA's own Functions window
// performs at runtime. Closing and reopening the window is not an alternative: the
// trigger is usually one of that window's own callbacks, and a fresh open_form() before
// IDA has finished tearing the old widget down hands back one that is already dying.
#pragma once

#include "pch.h"

#include <memory>
#include <string>
#include <vector>

#include "analysis.h"

namespace idacapa {

class PluginCtx;

// Window title. It is also the handle IDA identifies the widget by, so it must not
// change: find_widget() and refresh_chooser() both take it.
extern const char* const RESULTS_TITLE;

class ResultsView {
public:
    explicit ResultsView(PluginCtx& plugin);
    ~ResultsView();

    // Build the window from `doc`. For a window that is already open, use set_doc().
    void open(const ResultsDoc& doc, bool activate = true);

    // Show different results in the window that is already open.
    void set_doc(const ResultsDoc& doc);

    // Re-evaluate which rows are visible (the "limit to current function" filter)
    // using the contents already on display.
    void refresh_rows();

private:
    // Push the chooser's current contents to the screen.
    void repaint();

public:

    void close();

    bool is_open() const { return m_widget != nullptr; }
    bool owns(TWidget* w) const { return w != nullptr && w == m_widget; }

    // IDA destroyed the window.
    void forget();

    // The rule node the cursor is on, or nullptr — for "annotate selected rule".
    const ResultNode* selected_rule() const;

    PluginCtx& plugin() const { return m_plugin; }

private:
    struct Chooser;

    // Close the widget and retire the chooser. Never deletes the chooser outright:
    // IDA may still be unwinding the widget that was drawing it.
    void close_window();

    static ResultsView* s_active;

    PluginCtx& m_plugin;
    TWidget* m_widget = nullptr;

    // Owned here: the chooser sets CH_KEEP, so IDA never frees it.
    std::unique_ptr<Chooser> m_chooser;
    // The chooser from the previous window, kept one generation so it is never freed
    // while IDA could still be touching it. Disposed of by the next open().
    std::unique_ptr<Chooser> m_retired;

    ResultsDoc m_doc;       // what the window is showing
    sizevec_t m_selection;  // the embedded chooser field writes into this
};

}  // namespace idacapa
