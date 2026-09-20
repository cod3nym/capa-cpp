#include "static/trace_image.h"

#include <algorithm>
#include <filesystem>

namespace capa::stat {

namespace {

std::uint64_t manifest_key(std::size_t region_index, std::size_t dump_index) {
    return (static_cast<std::uint64_t>(region_index) << 32) |
           static_cast<std::uint32_t>(dump_index);
}

}  // namespace

TraceImage::TraceImage(const Manifest& manifest, const std::string& dumps_dir) {
    namespace fs = std::filesystem;

    std::size_t total = 0;
    for (const Region& r : manifest.regions) total += r.dumps.size();
    // Reserved up front, not grown: every view handed out points into a MappedFile
    // living in this vector, and a reallocation would move them.
    snaps_.reserve(total);

    for (std::size_t ri = 0; ri < manifest.regions.size(); ++ri) {
        const Region& r = manifest.regions[ri];
        for (std::size_t di = 0; di < r.dumps.size(); ++di) {
            Snap s;
            s.region = ri;
            s.dump = di;
            s.key = position_key(r.dumps[di].position);
            s.base = r.base;
            s.flags = r.classification == "exec" ? SEG_EXEC : 0;
            const std::string path = (fs::path(dumps_dir) / r.dumps[di].file).string();
            if (!s.file.open(path)) {
                missing_.push_back(path);
                continue;
            }
            ++mapped_;
            bytes_ += s.file.size();
            snaps_.push_back(std::move(s));
        }
    }

    // By region, then by position: `at()` walks each region's snapshots in trace
    // order to find the newest one that had happened yet.
    std::sort(snaps_.begin(), snaps_.end(), [](const Snap& a, const Snap& b) {
        if (a.region != b.region) return a.region < b.region;
        return a.key < b.key;
    });

    for (std::size_t i = 0; i < snaps_.size(); ++i)
        by_manifest_.emplace(manifest_key(snaps_[i].region, snaps_[i].dump), i);
}

const TraceImage::Snap* TraceImage::find(std::size_t region_index,
                                         std::size_t dump_index) const {
    auto it = by_manifest_.find(manifest_key(region_index, dump_index));
    return it == by_manifest_.end() ? nullptr : &snaps_[it->second];
}

MemoryImage TraceImage::at(std::size_t region_index, std::size_t dump_index) const {
    MemoryImage mem;

    const Snap* scanned = find(region_index, dump_index);
    if (scanned == nullptr) return mem;  // unmappable; the caller reports it as missing

    // First, and unconditionally. MemoryImage::finalize() resolves an overlap by
    // dropping the segment that starts higher, so a neighbouring region claiming
    // overlapping addresses could otherwise leave the region under analysis reading
    // somebody else's bytes -- with no diagnostic, because a dropped segment is a
    // legitimate outcome everywhere else.
    const std::uint64_t low = scanned->base;
    const std::uint64_t high = low + scanned->file.size();
    mem.add_view(low, scanned->file.data(), scanned->file.size(), scanned->flags);

    for (std::size_t i = 0; i < snaps_.size();) {
        const std::size_t region = snaps_[i].region;
        // The last snapshot of this region at or before the scanned one. None means
        // the region had not been written yet, and it stays unmapped.
        const Snap* chosen = nullptr;
        std::size_t j = i;
        for (; j < snaps_.size() && snaps_[j].region == region; ++j)
            if (snaps_[j].key <= scanned->key) chosen = &snaps_[j];
        i = j;

        if (chosen == nullptr || chosen == scanned) continue;
        if (chosen->base < high && low < chosen->base + chosen->file.size()) continue;
        mem.add_view(chosen->base, chosen->file.data(), chosen->file.size(), chosen->flags);
    }

    mem.finalize();
    return mem;
}

const MappedFile* TraceImage::snapshot(std::size_t region_index, std::size_t dump_index) const {
    const Snap* s = find(region_index, dump_index);
    return s == nullptr ? nullptr : &s->file;
}

}  // namespace capa::stat
