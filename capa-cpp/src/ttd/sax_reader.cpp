#include "ttd/sax_reader.h"

#include <fstream>
#include <utility>
#include <vector>

namespace capa::ttd {

namespace {

// Where in the document the parser currently is.
//
// A dotted path string recomputed per callback would be correct and far too slow -- there
// are tens of millions of callbacks on a large report -- so the location is an enum kept
// on a stack, pushed and popped with the containers. Everything the model does not want
// becomes Skip, and Skip's children stay Skip, which is what makes ignoring `params`
// cost nothing but the lexing.
enum class Loc {
    Root,
    Trace,
    Sample,
    FileObj,
    Imports,
    ImportItem,
    Exports,
    ExportItem,
    Sections,
    SectionItem,
    Strings,
    Processes,
    ProcessItem,
    Environ,
    Threads,
    Calls,
    CallItem,
    Args,
    Skip,
};

class ReportHandler : public nlohmann::json::json_sax_t {
public:
    using Base = nlohmann::json::json_sax_t;
    using number_integer_t = Base::number_integer_t;
    using number_unsigned_t = Base::number_unsigned_t;
    using number_float_t = Base::number_float_t;
    using string_t = Base::string_t;
    using binary_t = Base::binary_t;

    explicit ReportHandler(Report& out) : out_(out) { stack_.reserve(8); }

    // ---- scalars ----

    bool null() override {
        // capa treats a null argument as the integer 0 (models.cpp parse_arg's fallback
        // for anything that is not a bool, string or number).
        if (top() == Loc::Args) out_.args.push_back(Arg{Arg::Kind::Int, 0});
        key_.clear();
        return true;
    }

    bool boolean(bool value) override {
        if (top() == Loc::Args)
            out_.args.push_back(Arg{Arg::Kind::Bool, value ? 1 : 0});
        key_.clear();
        return true;
    }

    bool number_integer(number_integer_t value) override {
        take_int(value);
        return true;
    }

    bool number_unsigned(number_unsigned_t value) override {
        // Canonicalized to int64 by bit-cast, exactly as models.cpp does, so that e.g.
        // 0xFFFFFFFFFFFFFFFE and -2 land on the same feature key.
        take_int(static_cast<std::int64_t>(value), value);
        return true;
    }

    bool number_float(number_float_t value, const string_t&) override {
        take_int(static_cast<std::int64_t>(value), static_cast<std::uint64_t>(value));
        return true;
    }

    bool string(string_t& value) override {
        switch (top()) {
            case Loc::Trace:
                if (key_ == "path") out_.trace.path = std::move(value);
                else if (key_ == "arch") out_.trace.arch = std::move(value);
                else if (key_ == "os") out_.trace.os = std::move(value);
                break;
            case Loc::Sample:
                if (key_ == "md5") out_.sample.md5 = std::move(value);
                else if (key_ == "sha1") out_.sample.sha1 = std::move(value);
                else if (key_ == "sha256") out_.sample.sha256 = std::move(value);
                else if (key_ == "name") out_.sample.name = std::move(value);
                break;
            case Loc::ImportItem:
                if (key_ == "dll") import_.dll = std::move(value);
                else if (key_ == "name") import_.name = std::move(value);
                break;
            case Loc::ExportItem:
                if (key_ == "name") export_.name = std::move(value);
                break;
            case Loc::SectionItem:
                if (key_ == "name") section_.name = std::move(value);
                break;
            case Loc::Strings:
                out_.file.strings.push_back(std::move(value));
                break;
            case Loc::ProcessItem:
                if (key_ == "name") process_.name = std::move(value);
                break;
            case Loc::Environ:
                process_.environ_strings.push_back(std::move(value));
                break;
            case Loc::CallItem:
                if (key_ == "position") call_.position = std::move(value);
                else if (key_ == "module") call_.module = out_.strings.intern(std::move(value));
                else if (key_ == "api") call_.api = out_.strings.intern(std::move(value));
                break;
            case Loc::Args:
                out_.args.push_back(
                    Arg{Arg::Kind::Str,
                        static_cast<std::int64_t>(out_.strings.intern(std::move(value)))});
                break;
            default:
                break;
        }
        key_.clear();
        return true;
    }

    bool binary(binary_t&) override {
        key_.clear();
        return true;  // not a shape this schema produces
    }

    // ---- containers ----

    bool start_object(std::size_t) override {
        const Loc child = descend(/*is_array=*/false);
        switch (child) {
            case Loc::ImportItem: import_ = Import{}; break;
            case Loc::ExportItem: export_ = Export{}; break;
            case Loc::SectionItem: section_ = Section{}; break;
            case Loc::ProcessItem: process_ = Process{}; break;
            case Loc::CallItem:
                call_ = Call{};
                // A call's arguments are appended to the report-wide arena as they are
                // read, and JSON gives them to us contiguously -- the object cannot be
                // interrupted by another call's. So the window starts wherever the arena
                // has reached, and end_object() measures how far it got.
                call_.arg_offset = static_cast<std::uint32_t>(out_.args.size());
                break;
            default: break;
        }
        stack_.push_back(child);
        key_.clear();
        return true;
    }

    bool end_object() override {
        const Loc closing = top();
        stack_.pop_back();
        switch (closing) {
            case Loc::ImportItem: out_.file.imports.push_back(std::move(import_)); break;
            case Loc::ExportItem: out_.file.exports.push_back(std::move(export_)); break;
            case Loc::SectionItem: out_.file.sections.push_back(std::move(section_)); break;
            case Loc::ProcessItem: out_.processes.push_back(std::move(process_)); break;
            case Loc::CallItem:
                call_.arg_count =
                    static_cast<std::uint32_t>(out_.args.size() - call_.arg_offset);
                process_.calls.push_back(std::move(call_));
                break;
            default: break;
        }
        key_.clear();
        return true;
    }

    bool start_array(std::size_t) override {
        stack_.push_back(descend(/*is_array=*/true));
        key_.clear();
        return true;
    }

    bool end_array() override {
        stack_.pop_back();
        key_.clear();
        return true;
    }

    bool key(string_t& value) override {
        key_ = std::move(value);
        return true;
    }

    bool parse_error(std::size_t position, const std::string& last_token,
                     const nlohmann::json::exception& ex) override {
        error_ = std::string(ex.what()) + " (at byte " + std::to_string(position) +
                 ", near '" + last_token + "')";
        return false;
    }

    const std::string& error() const { return error_; }

private:
    Loc top() const { return stack_.empty() ? Loc::Root : stack_.back(); }

    // The location a container opened under the current key belongs to. Anything not
    // named here -- `params` included -- is Skip, and Skip is absorbing.
    Loc descend(bool is_array) const {
        const Loc here = top();
        if (here == Loc::Skip) return Loc::Skip;

        if (stack_.empty()) return Loc::Root;  // the document's own object

        switch (here) {
            case Loc::Root:
                if (!is_array && key_ == "trace") return Loc::Trace;
                if (!is_array && key_ == "sample") return Loc::Sample;
                if (!is_array && key_ == "file") return Loc::FileObj;
                if (is_array && key_ == "processes") return Loc::Processes;
                return Loc::Skip;
            case Loc::FileObj:
                if (is_array && key_ == "imports") return Loc::Imports;
                if (is_array && key_ == "exports") return Loc::Exports;
                if (is_array && key_ == "sections") return Loc::Sections;
                if (is_array && key_ == "strings") return Loc::Strings;
                return Loc::Skip;
            case Loc::Imports: return is_array ? Loc::Skip : Loc::ImportItem;
            case Loc::Exports: return is_array ? Loc::Skip : Loc::ExportItem;
            case Loc::Sections: return is_array ? Loc::Skip : Loc::SectionItem;
            case Loc::Processes: return is_array ? Loc::Skip : Loc::ProcessItem;
            case Loc::ProcessItem:
                if (is_array && key_ == "environ") return Loc::Environ;
                if (is_array && key_ == "threads") return Loc::Threads;
                if (is_array && key_ == "calls") return Loc::Calls;
                return Loc::Skip;
            case Loc::Calls: return is_array ? Loc::Skip : Loc::CallItem;
            case Loc::CallItem:
                // `params` lands here, and this is the whole point: it is the largest
                // field in the document and models.h keeps none of it.
                if (is_array && key_ == "args") return Loc::Args;
                return Loc::Skip;
            default:
                return Loc::Skip;
        }
    }

    // `unsigned_value` is supplied where the source token was unsigned (or a float), for
    // the fields models.cpp reads through get_u64 rather than get_int.
    void take_int(std::int64_t value, std::uint64_t unsigned_value) {
        switch (top()) {
            case Loc::Root:
                if (key_ == "version") out_.version = static_cast<int>(value);
                break;
            case Loc::ImportItem:
                if (key_ == "va") import_.va = unsigned_value;
                break;
            case Loc::ExportItem:
                if (key_ == "va") export_.va = unsigned_value;
                break;
            case Loc::SectionItem:
                if (key_ == "va") section_.va = unsigned_value;
                break;
            case Loc::ProcessItem:
                if (key_ == "pid") process_.pid = value;
                else if (key_ == "ppid") process_.ppid = value;
                break;
            case Loc::Threads:
                process_.threads.push_back(value);
                break;
            case Loc::CallItem:
                if (key_ == "tid") call_.tid = value;
                else if (key_ == "seq") call_.seq = value;
                else if (key_ == "ret") call_.ret = value;
                break;
            case Loc::Args:
                out_.args.push_back(Arg{Arg::Kind::Int, value});
                break;
            default:
                break;
        }
        key_.clear();
    }

    void take_int(std::int64_t value) { take_int(value, static_cast<std::uint64_t>(value)); }

    Report& out_;
    std::vector<Loc> stack_;
    std::string key_;
    std::string error_;

    Import import_;
    Export export_;
    Section section_;
    Process process_;
    Call call_;
};

}  // namespace

bool read_report_streaming(const std::string& path, Report& out, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open " + path;
        return false;
    }

    ReportHandler handler(out);
    // allow_exceptions=false: parse_error() above records the message and stops the
    // parse, so a malformed report is a diagnostic rather than a throw through main.
    if (!nlohmann::json::sax_parse(in, &handler, nlohmann::json::input_format_t::json,
                                   /*strict=*/true, /*ignore_comments=*/false)) {
        error = handler.error().empty() ? "malformed JSON" : handler.error();
        return false;
    }
    out.strings.seal();  // nothing interns after parsing; the lookup table is dead weight
    return true;
}

}  // namespace capa::ttd
