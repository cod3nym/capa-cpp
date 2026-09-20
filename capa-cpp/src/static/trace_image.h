// Every reconstructed region a `--scan-code` manifest names, mapped at once.
//
// Scanning one snapshot in isolation loses every edge that leaves it, and a staged
// loader is made of those edges: the first allocation decrypts a second and jumps
// into it, the second calls back into a helper the first left behind, a thunk in one
// forwards to a function in another. None of that resolves against a lone buffer --
// the target is simply unmapped, and the analysis stops at the region boundary. This
// is the lesson the minidump backend already learned: assemble the address space
// once, and let every scan read it.
//
// Time is the complication a dump does not have. A region has one snapshot per
// generation, so its contents at the moment some *other* region is being scanned are
// whatever its newest snapshot at or before that moment holds. A region with no
// snapshot yet is left unmapped rather than filled in from a later one: memory that
// has not been written cannot be the target of a call, and pretending otherwise
// invents features -- in a beacon trace the packed image runs hundreds of sequences
// before the region it unpacks into exists at all.
//
// Snapshots are mapped, not read. One trace easily carries a hundred megabytes of
// them and a scan touches a fraction, so nothing is resident that the disassembler
// did not ask for.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "static/manifest.h"
#include "static/memory.h"

namespace capa::stat {

class TraceImage {
public:
    // Maps every snapshot the manifest names, relative to `dumps_dir`. A snapshot
    // that cannot be mapped is skipped and reported by `missing()`; the rest still
    // scan.
    TraceImage(const Manifest& manifest, const std::string& dumps_dir);

    // The address space as the manifest's `[region_index].dumps[dump_index]` snapshot
    // saw it. Cheap: a MemoryImage over mapped views is a sorted vector of segments,
    // so this is built per snapshot rather than cached.
    //
    // The named snapshot is identified by index, not by looking its position back up:
    // `position` is a string out of the manifest, it may be absent or unparseable,
    // and every real position compares "at or before" the sentinel that then stands
    // in for it -- which would quietly scan one snapshot's seeds against another's
    // bytes. It is also mapped first and never displaced, so a second region claiming
    // overlapping addresses cannot take the ground out from under the scan.
    MemoryImage at(std::size_t region_index, std::size_t dump_index) const;

    // The mapping for one manifest snapshot, or null if it could not be mapped.
    // Its size is the authority on how much of the region we actually have.
    const MappedFile* snapshot(std::size_t region_index, std::size_t dump_index) const;

    std::size_t mapped_count() const { return mapped_; }
    std::uint64_t mapped_bytes() const { return bytes_; }
    const std::vector<std::string>& missing() const { return missing_; }

private:
    struct Snap {
        std::size_t region = 0;
        std::size_t dump = 0;
        std::pair<std::uint64_t, std::uint64_t> key;  // position_key(position)
        std::uint64_t base = 0;
        std::uint32_t flags = 0;
        MappedFile file;
    };

    const Snap* find(std::size_t region_index, std::size_t dump_index) const;

    // Sorted by (region, position). Never reallocated after construction, so the
    // MappedFile inside each entry -- and every view into it -- stays put.
    std::vector<Snap> snaps_;
    // (region, dump) -> index into snaps_, which the sort above scrambles.
    std::unordered_map<std::uint64_t, std::size_t> by_manifest_;
    std::size_t mapped_ = 0;
    std::uint64_t bytes_ = 0;
    std::vector<std::string> missing_;
};

}  // namespace capa::stat
