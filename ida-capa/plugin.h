// The ida-capa plugin object.
//
// It is both the plugmod_t IDA gets back from init() and the listener for the
// database notifications we care about.
//
// ida-capa carries no UI of its own any more: it is a fast backend for the Python
// "capa explorer" plugin (../capa/capa/ida/plugin), which drives it through
// idaapi.load_and_run_plugin("ida-capa", cmd) -- see HeadlessCmd below -- passing
// parameters through the settings netnode (settings.h) since a plugin's run() takes
// only a single integer. What remains as native, interactively-triggered actions
// (Edit > Plugins > CAPA C++) is just enough to be useful standalone: running an
// analysis to have something to annotate, and annotating/removing annotations.
#pragma once

#include "pch.h"

#include "analysis.h"

namespace idacapa {

// Stamped into the binary at compile time and printed when the plugin loads.
//
// Windows keeps ida-capa.dll open for as long as IDA is running, so copying a fresh
// build over it while IDA is up does not fail loudly -- it just does not happen, and
// the next run behaves exactly like the build before. Every symptom then looks like a
// bug that was already fixed. This one line settles which binary is actually loaded.
inline constexpr const char* BUILD_STAMP = __DATE__ " " __TIME__;

extern const char* const WANTED_NAME;

// The `arg` values run() dispatches on. This is the entire contract between the
// Python bridge (native_backend.py) and this plugin; keep the two in sync by hand,
// there is no shared header between the languages.
//
//   Ui                 -- default (Alt-F5 / the native menu's "Analyze"): interactive
//                          analysis, prompting for a rules directory if none is set.
//   Ping               -- no-op, just confirms the plugin is loadable.
//   Analyze            -- headless: read settings::rules_dir()/headless_output_path(),
//                          run capa, write a ResultDocument JSON to that path.
//   AnnotateAll        -- annotate every match in the last analysis run.
//   AnnotateSelected   -- annotate only the rule named by settings::headless_rule_name().
//   RemoveAnnotations  -- undo whatever the last annotate wrote.
enum class HeadlessCmd : size_t {
    Ui = 0,
    Ping = 1,
    Analyze = 2,
    AnnotateAll = 3,
    AnnotateSelected = 4,
    RemoveAnnotations = 5,
};

class PluginCtx : public plugmod_t {
public:
    PluginCtx();
    ~PluginCtx() override;

    bool idaapi run(size_t arg) override;

    // Delivered by the two listeners below. Kept apart because ui_notification_t and
    // idb_event::event_code_t are independent dense enums whose values collide.
    ssize_t on_ui_event(ssize_t code, va_list va);
    ssize_t on_idb_event(ssize_t code, va_list va);

    // --- actions ----------------------------------------------------------
    // Interactive: prompts for a rules directory if none is set, and reports a .NET
    // warning the first time. Populates m_doc so annotate_all()/annotate_selected()
    // have something to work with, same as the headless Analyze command does.
    void analyze();

    void annotate_all();
    // Restricted to settings::headless_rule_name(); headless-only (there is no
    // interactive row selection to drive this from any more).
    void annotate_selected();
    void remove_annotations_action();

private:
    void register_actions();
    void unregister_actions();

    // (Re)build the Edit > Plugins > CAPA C++ submenu. Idempotent.
    void ensure_menu();

    // Load results from the database cache into m_doc, if there are any and they
    // still match the configured rules directory.
    bool load_cached();

    // The analysis itself, once the rules directory is settled.
    bool do_analysis(const std::string& dir);

    // The headless Analyze command: like do_analysis(), but reads its rules
    // directory from settings rather than prompting, and additionally writes a
    // ResultDocument JSON to settings::headless_output_path() for the Python bridge.
    bool run_headless_analyze();

    // Find a matched rule by name (as capa names it, not the "name (N matches)"
    // label a row shows) for annotate_selected().
    const ResultNode* find_rule_by_name(const std::string& name) const;

    // Reinstate whatever a previous session left in this database (currently the
    // pseudocode markers, which are not saved with it). Idempotent.
    void restore_session();

    ResultsDoc m_doc;      // as analysed, always "by program"
    bool m_have_results = false;
    // Set once the database is far enough along to read the netnode and resolve
    // addresses; see on_event().
    bool m_restored = false;
    // The menu path the commands are actually attached to, which is not always the
    // one they were asked to go to; empty when nothing took them. Kept so they can be
    // detached from the right place.
    std::string m_menu_path;

    // One listener per hook type, so a notification is always interpreted against the
    // enum it actually came from.
    struct UiListener : public event_listener_t {
        explicit UiListener(PluginCtx& p) : plugin(p) {}
        ssize_t idaapi on_event(ssize_t code, va_list va) override {
            return plugin.on_ui_event(code, va);
        }
        PluginCtx& plugin;
    };
    struct IdbListener : public event_listener_t {
        explicit IdbListener(PluginCtx& p) : plugin(p) {}
        ssize_t idaapi on_event(ssize_t code, va_list va) override {
            return plugin.on_idb_event(code, va);
        }
        PluginCtx& plugin;
    };
    UiListener m_ui_listener{*this};
    IdbListener m_idb_listener{*this};

    struct ActionHandler : public action_handler_t {
        using Fn = void (PluginCtx::*)();
        ActionHandler(PluginCtx& p, Fn fn) : plugin(p), fn(fn) {}
        int idaapi activate(action_activation_ctx_t*) override {
            (plugin.*fn)();
            return 1;
        }
        action_state_t idaapi update(action_update_ctx_t*) override {
            return AST_ENABLE_ALWAYS;
        }
        PluginCtx& plugin;
        Fn fn;
    };

    ActionHandler m_analyze{*this, &PluginCtx::analyze};
    ActionHandler m_annotate{*this, &PluginCtx::annotate_all};
    ActionHandler m_unannotate{*this, &PluginCtx::remove_annotations_action};
};

}  // namespace idacapa
