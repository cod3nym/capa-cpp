#include "plugin.h"

#include <fstream>

#include "annotate.h"
#include "pseudocode.h"
#include "settings.h"

namespace idacapa {

const char* const WANTED_NAME = "capa explorer (C++)";

namespace {

const char* const ACTION_ANALYZE = "capacpp:analyze";
const char* const ACTION_ANNOTATE = "capacpp:annotate";
const char* const ACTION_UNANNOTATE = "capacpp:unannotate";

// The commands a user wants without the Python capa explorer running live in a
// submenu of Edit > Plugins. It is the plugin's only entry there: PLUGIN_HIDE keeps
// IDA from adding its own beside it. "Annotate selected rule only" is not among
// them: without a results window there is no row to select it from any more, so it
// is reachable only headlessly, from the Python UI's own rule context menu.
const char* const MENU_NAME = "capacpp:menu";
const char* const MENU_LABEL = "CAPA C++";
const char* const MENU_PATH = "Edit/Plugins/CAPA C++/";
const char* const PLUGINS_PATH = "Edit/Plugins/";
// Where create_menu() puts a menu whose menupath it could not resolve: the menu bar.
const char* const MENUBAR_PATH = "CAPA C++/";
const char* const MENU_ACTIONS[] = {
    ACTION_ANALYZE,
    ACTION_ANNOTATE,
    ACTION_UNANNOTATE,
};

const int MENU_ACTION_QTY = static_cast<int>(qnumber(MENU_ACTIONS));

// SETMENU_APP appends, so the items keep the order declared above rather than coming
// out reversed. Returns how many took, rather than all-or-nothing: a path that
// accepted some of them has to be remembered as the one they are on, or the caller
// tries the next path and the successful ones end up in two menus at once.
int attach_menu_actions(const char* path) {
    int n = 0;
    for (const char* name : MENU_ACTIONS)
        if (attach_action_to_menu(path, name, SETMENU_APP)) ++n;
    return n;
}

}  // namespace

//-------------------------------------------------------------------------
PluginCtx::PluginCtx() {
    msg("capa: ida-capa loaded (build %s)\n", BUILD_STAMP);
    register_actions();
    hook_event_listener(HT_UI, &m_ui_listener);
    hook_event_listener(HT_IDB, &m_idb_listener);
}

//-------------------------------------------------------------------------
PluginCtx::~PluginCtx() {
    unhook_event_listener(HT_IDB, &m_idb_listener);
    unhook_event_listener(HT_UI, &m_ui_listener);
    shutdown_pseudocode();
    unregister_actions();
}

//-------------------------------------------------------------------------
void PluginCtx::register_actions() {
    // The labels are what the menu shows, so they are kept short; the tooltip beside
    // each one carries the detail.
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_ANALYZE, "Analyze", &m_analyze, this,
                                                "Alt-F5",
                                                "Find capabilities in this database", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_ANNOTATE, "Annotate Results", &m_annotate, this, nullptr,
        "Colour and comment every address capa matched something at", -1));
    register_action(ACTION_DESC_LITERAL_PLUGMOD(ACTION_UNANNOTATE, "Remove Results",
                                                &m_unannotate, this, nullptr,
                                                "Remove capa's annotations, restoring the "
                                                "colours and comments it changed", -1));

    // Built after the actions exist: attaching one that is not registered yet does
    // nothing.
    ensure_menu();
}

//-------------------------------------------------------------------------
// Edit > Plugins > CAPA C++.
//
// IDA owns the Edit and Plugins menus -- the SDK says as much (kernwin.hpp) -- and
// fills Plugins from the list of loaded plugins, so a submenu placed there can be
// gone by the time anyone looks. Hence: idempotent, run again when the UI reports
// itself ready, and it says in the Output window where the commands ended up, because
// "the menu is not there" is otherwise indistinguishable from "the plugin did not
// load".
void PluginCtx::ensure_menu() {
    // Removes a copy left by an earlier call, along with the items attached to it.
    // False simply means there was none.
    delete_menu(MENU_NAME);
    if (!m_menu_path.empty()) {
        for (const char* name : MENU_ACTIONS) detach_action_from_menu(m_menu_path.c_str(), name);
        m_menu_path.clear();
    }

    // Every branch below reports a partial attach, since a menu missing one of three
    // commands looks like a bug in the command that is missing rather than in this.
    auto took = [&](const char* path, int n, const char* where) {
        m_menu_path = path;
        if (n < MENU_ACTION_QTY)
            msg("capa: only %d of %d commands could be attached to %s.\n", n, MENU_ACTION_QTY,
                where);
    };

    if (create_menu(MENU_NAME, MENU_LABEL, PLUGINS_PATH)) {
        if (int n = attach_menu_actions(MENU_PATH); n > 0) {
            took(MENU_PATH, n, "Edit > Plugins > CAPA C++");
            return;  // the ordinary case; nothing else worth a line in the log
        }
        // create_menu() reports success for a menu it could not place where it was
        // asked, having appended it to the menu bar instead -- in which case the path
        // above does not name it and nothing attached.
        if (int n = attach_menu_actions(MENUBAR_PATH); n > 0) {
            took(MENUBAR_PATH, n, "the \"CAPA C++\" menu");
            msg("capa: Edit > Plugins would not take a submenu; capa's commands are in "
                "the \"%s\" menu on the menu bar.\n",
                MENU_LABEL);
            return;
        }
        delete_menu(MENU_NAME);
    }

    // No submenu anywhere. The commands still have to be reachable, so they go
    // straight into Edit > Plugins beside IDA's own entry for the plugin.
    if (int n = attach_menu_actions(PLUGINS_PATH); n > 0) {
        took(PLUGINS_PATH, n, "Edit > Plugins");
        msg("capa: could not create the \"%s\" submenu; capa's commands are in "
            "Edit > Plugins.\n",
            MENU_LABEL);
        return;
    }
    msg("capa: could not attach capa's commands to any menu.\n");
}

//-------------------------------------------------------------------------
void PluginCtx::unregister_actions() {
    // Detached before the actions go: unregistering one that is still on a menu
    // leaves a dead entry behind. delete_menu() covers the items inside our own
    // submenu, but not the ones a fallback put in a menu IDA owns.
    if (!m_menu_path.empty())
        for (const char* name : MENU_ACTIONS) detach_action_from_menu(m_menu_path.c_str(), name);
    m_menu_path.clear();
    delete_menu(MENU_NAME);
    for (const char* name : {ACTION_ANALYZE, ACTION_ANNOTATE, ACTION_UNANNOTATE})
        unregister_action(name);
}

//-------------------------------------------------------------------------
// Running the plugin interactively (Alt-F5, the menu, or a bare
// idaapi.load_and_run_plugin("ida-capa", 0) from Python) is the "Ui" HeadlessCmd:
// everything else is a headless command from the Python capa explorer bridge.
bool idaapi PluginCtx::run(size_t arg) {
    switch (static_cast<HeadlessCmd>(arg)) {
        case HeadlessCmd::Ping:
            return true;

        case HeadlessCmd::Analyze:
            return run_headless_analyze();

        case HeadlessCmd::AnnotateAll:
            if (!m_have_results && !load_cached()) {
                msg("capa: annotate requested with no analysis results available.\n");
                return false;
            }
            annotate_all();
            return true;

        case HeadlessCmd::AnnotateSelected:
            if (!m_have_results && !load_cached()) {
                msg("capa: annotate requested with no analysis results available.\n");
                return false;
            }
            annotate_selected();
            return true;

        case HeadlessCmd::RemoveAnnotations:
            remove_annotations_action();
            return true;

        case HeadlessCmd::Ui:
        default:
            analyze();
            return true;
    }
}

//-------------------------------------------------------------------------
bool PluginCtx::load_cached() {
    const std::string dir = rules_dir();
    if (dir.empty()) return false;
    // A cache produced from a different rules directory says nothing about this one.
    if (cached_results_rules_dir() != dir) return false;

    ResultsDoc doc = ResultsDoc::from_json(cached_results());
    if (!doc.valid) {
        // Written by an older build, or corrupt. Drop it so the next run replaces it
        // rather than re-reading it every time.
        clear_cached_results();
        return false;
    }
    if (doc.rules_dir != dir) return false;

    m_doc = std::move(doc);
    m_have_results = true;
    // Say where the results came from: a log full of stale counts is otherwise
    // indistinguishable from fresh ones.
    msg("capa: loaded %zu cached rule match(es) from this database.\n", m_doc.rules.size());

    // The disassembly comments were saved with the database; the pseudocode markers
    // are generated on the fly, so they have to be put back.
    if (has_annotations()) set_pseudocode_annotations(collect_annotations(m_doc));
    return true;
}

//-------------------------------------------------------------------------
void PluginCtx::analyze() {
    std::string why_not;
    if (!database_is_supported(why_not)) {
        warning("capa: %s", why_not.c_str());
        return;
    }
    if (database_is_dotnet()) {
        // capa analyses managed code with its dnfile backend, which reads CLR
        // metadata. That backend is not ported, and IDA sees only the native stub, so
        // saying so up front beats reporting "no capabilities found".
        if (ask_yn(ASKBTN_NO,
                   "HIDECANCEL\n"
                   "This looks like a .NET assembly.\n\n"
                   "capa analyses managed code with its dnfile backend, which capa-cpp does "
                   "not implement. Only the native stub will be examined, so expect few or "
                   "no results.\n\n"
                   "Analyze anyway?") != ASKBTN_YES)
            return;
    }

    std::string dir = rules_dir();
    if (dir.empty()) {
        dir = ask_rules_dir();
        if (dir.empty()) return;
        set_rules_dir(dir);
    }

    // Whatever is annotated right now describes the previous run.
    const bool was_annotated = has_annotations();

    if (!do_analysis(dir)) return;
    if (m_doc.empty()) {
        if (was_annotated) remove_annotations_action();
        info("capa found no capabilities in this database.");
        return;
    }
    if (was_annotated) annotate_all();
}

//-------------------------------------------------------------------------
// The analysis itself, once the rules directory is settled. Returns false if it
// failed or the user cancelled, having already said so.
bool PluginCtx::do_analysis(const std::string& dir) {
    ResultsDoc doc;
    std::string error;
    if (!run_analysis(dir, doc, error)) {
        if (!error.empty()) {
            warning("capa: %s", error.c_str());
            msg("capa: %s\n", error.c_str());
        } else {
            msg("capa: analysis cancelled.\n");
        }
        return false;
    }

    m_doc = std::move(doc);
    m_have_results = true;
    set_cached_results(m_doc.to_json(), dir);

    msg("capa: %zu rule(s) matched over %zu function(s); %zu rule(s) loaded from %s\n",
        m_doc.match_count, m_doc.function_count, m_doc.rules_loaded, dir.c_str());
    return true;
}

//-------------------------------------------------------------------------
// The headless Analyze command: same analysis as do_analysis(), driven entirely by
// settings the Python bridge wrote beforehand (no prompting -- this must be safe to
// call with no UI interaction at all), additionally emitting a ResultDocument JSON
// for the bridge to read back.
bool PluginCtx::run_headless_analyze() {
    const std::string dir = rules_dir();
    if (dir.empty()) {
        msg("capa: headless analyze requested with no rules directory set.\n");
        return false;
    }
    const std::string out_path = headless_output_path();
    if (out_path.empty()) {
        msg("capa: headless analyze requested with no output path set.\n");
        return false;
    }

    ResultsDoc doc;
    std::string error;
    std::string json_text;
    if (!run_analysis(dir, doc, error, &json_text)) {
        if (!error.empty()) msg("capa: %s\n", error.c_str());
        return false;
    }

    m_doc = std::move(doc);
    m_have_results = true;
    set_cached_results(m_doc.to_json(), dir);

    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        msg("capa: could not open %s for writing.\n", out_path.c_str());
        return false;
    }
    out << json_text;
    if (!out) {
        msg("capa: failed writing results to %s\n", out_path.c_str());
        return false;
    }

    msg("capa: %zu rule(s) matched over %zu function(s); wrote results to %s\n",
        m_doc.match_count, m_doc.function_count, out_path.c_str());
    return true;
}

//-------------------------------------------------------------------------
const ResultNode* PluginCtx::find_rule_by_name(const std::string& name) const {
    for (const ResultNode& r : m_doc.rules)
        if (strip_match_count(r.info) == name) return &r;
    return nullptr;
}

//-------------------------------------------------------------------------
// Put back what a previous session left in this database. Runs at most once per
// database: reading the cache is cheap, but re-reading it on every notification is
// pointless, and rebuilding the pseudocode index needs the address map to be up.
void PluginCtx::restore_session() {
    if (m_restored) return;
    m_restored = true;

    // Only worth doing if this database has annotations to put back — load_cached()
    // reinstates the pseudocode markers as a side effect when it finds them.
    if (!has_annotations()) return;
    if (!m_have_results) load_cached();
}

//-------------------------------------------------------------------------
void PluginCtx::annotate_all() {
    if (!m_have_results && !load_cached()) {
        info("capa: run an analysis first.");
        return;
    }
    AnnotationStats s = annotate(m_doc);
    // The decompiler shows none of the disassembly's comments, so the same findings go
    // into the pseudocode by a separate route.
    set_pseudocode_annotations(collect_annotations(m_doc));
    msg("capa: annotated %zu address(es) with %zu comment(s).\n", s.addresses, s.comments);
    if (s.addresses == 0) info("capa: nothing to annotate.");
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
void PluginCtx::annotate_selected() {
    const std::string name = headless_rule_name();
    if (name.empty()) {
        msg("capa: annotate_selected requested with no rule name set.\n");
        return;
    }
    const ResultNode* rule = find_rule_by_name(name);
    if (rule == nullptr) {
        msg("capa: '%s' is not among the last analysis's matched rules.\n", name.c_str());
        return;
    }

    AnnotationStats s = annotate(m_doc, rule);
    set_pseudocode_annotations(collect_annotations(m_doc, rule));
    msg("capa: annotated %zu address(es) for '%s'.\n", s.addresses, rule->info.c_str());
    if (s.addresses == 0) info("capa: that rule has no addresses to annotate.");
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
void PluginCtx::remove_annotations_action() {
    if (!has_annotations()) {
        info("capa: there are no capa annotations in this database.");
        return;
    }
    std::size_t n = remove_annotations();
    set_pseudocode_annotations(AnnotationMap{});
    msg("capa: removed annotations from %zu address(es).\n", n);
    refresh_idaview_anyway();
}

//-------------------------------------------------------------------------
// UI and database notifications are delivered through two listeners rather than one.
// ui_notification_t and idb_event::event_code_t are separate, dense, zero-based enums,
// so their values collide wholesale — a single switch over both cannot tell them apart,
// and would act on a va_list belonging to something else entirely.
ssize_t idaapi PluginCtx::on_ui_event(ssize_t code, va_list /*va*/) {
    switch (code) {
        case ui_ready_to_run:
            // The database is up. The disassembly's colours and comments were saved
            // with it, but the pseudocode markers are generated on the fly and would
            // otherwise stay missing until the user next ran the plugin.
            restore_session();
            // And the menus are up -- definitively, this time. Our submenu was built
            // while IDA was still assembling Edit > Plugins, which is exactly when it
            // rebuilds that menu from the plugin list and drops anything else in it.
            ensure_menu();
            break;
    }
    return 0;
}

//-------------------------------------------------------------------------
ssize_t idaapi PluginCtx::on_idb_event(ssize_t code, va_list /*va*/) {
    switch (code) {
        case idb_event::auto_empty_finally:
            // Belt and braces: ui_ready_to_run fires once per IDA session, so a second
            // database opened in the same session needs this one instead.
            restore_session();
            break;

        case idb_event::closebase:
            // m_doc is about to go away.
            set_pseudocode_annotations(AnnotationMap{});
            m_doc = ResultsDoc{};
            m_have_results = false;
            m_restored = false;
            break;
    }
    return 0;
}

}  // namespace idacapa

//-------------------------------------------------------------------------
static plugmod_t* idaapi init() { return new idacapa::PluginCtx; }

//-------------------------------------------------------------------------
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    // PLUGIN_MULTI: init() returns a plugmod_t.
    // PLUGIN_HIDE: keep IDA's automatic "capa explorer (C++)" entry out of
    // Edit > Plugins. Everything it did is in our own submenu there, and the name
    // below is still what IDA calls the plugin everywhere else. The plugin is loaded
    // exactly as before; run() simply has no menu entry of its own any more.
    PLUGIN_MULTI | PLUGIN_HIDE,
    init,
    nullptr,  // term: must be null for PLUGIN_MULTI
    nullptr,  // run:  must be null for PLUGIN_MULTI
    "Find capabilities in a binary with capa",
    "Runs capa's rule set against the open database. Used as a fast backend by the\n"
    "Python capa explorer plugin; also usable standalone from Edit > Plugins > CAPA C++.",
    idacapa::WANTED_NAME,
    ""  // hotkeys come from the registered actions
};
