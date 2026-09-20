// A read-only view of a process's (or an image's) memory, for capa-cpp's static path.
//
// The TTD `--scan-code` path analyses one reconstructed region in isolation, so a
// single flat buffer was enough. A process minidump is different: dozens of regions
// are scanned, and resolving an API call means following an IAT slot in one module
// into the export table of another. Memory therefore has to be owned once and shared
// by every Workspace, rather than owned per Workspace — 30 scanned regions must not
// mean 30 copies of a 500 MB dump.
//
// Segments are non-overlapping and never straddled by a read: the minidump loader
// builds ONE contiguous buffer per module (SizeOfImage, zero-filled, with each
// present range blitted in) and one per non-image allocation, so an RVA is just an
// offset into a segment and pages the dump omitted read back as zeros.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace capa::stat {

enum SegFlags : std::uint32_t {
    SEG_EXEC = 1u << 0,   // executable (Protect or AllocationProtect carries an X bit)
    SEG_IMAGE = 1u << 1,  // MEM_IMAGE: backed by a mapped module
    SEG_WRITE = 1u << 2,
};

struct Segment {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint32_t flags = 0;
    // Stable for the lifetime of the owning MemoryImage.
    const std::uint8_t* data = nullptr;

    bool contains(std::uint64_t va) const { return va >= base && va - base < size; }
};

// A file's bytes, mapped rather than copied.
//
// The scan-code path maps every region snapshot a manifest names at once, so a call
// out of one reconstructed region into another can be followed. One trace easily
// carries a hundred megabytes of snapshots and the disassembler touches a fraction of
// it, so these are views the OS pages in on demand rather than buffers we read.
//
// The mapping outlives any MemoryImage segment pointing into it, which is the whole
// contract: hold the MappedFile at least as long as the image built over it.
class MappedFile {
public:
    MappedFile() = default;
    ~MappedFile() { close(); }
    MappedFile(MappedFile&& o) noexcept { *this = std::move(o); }
    MappedFile& operator=(MappedFile&& o) noexcept;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;

    // False if the file is missing, unreadable or empty. A zero-length file maps to
    // nothing on Windows, and an empty region is nothing to scan either way.
    bool open(const std::string& path);

    const std::uint8_t* data() const { return data_; }
    std::size_t size() const { return size_; }
    explicit operator bool() const { return data_ != nullptr; }

private:
    void close();

    void* file_ = nullptr;     // HANDLE, kept opaque so this header stays Windows-free
    void* mapping_ = nullptr;  // HANDLE
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
};

class MemoryImage {
public:
    MemoryImage() = default;
    MemoryImage(const MemoryImage&) = delete;
    MemoryImage& operator=(const MemoryImage&) = delete;
    // Movable: moving the deque does not relocate its elements, and moving a vector
    // preserves its heap pointer, so every Segment::data stays valid.
    MemoryImage(MemoryImage&&) = default;
    MemoryImage& operator=(MemoryImage&&) = default;

    // Takes ownership of `bytes` and maps it at [base, base + bytes.size()).
    // Call finalize() once every segment has been added.
    void add(std::uint64_t base, std::vector<std::uint8_t> bytes, std::uint32_t flags = 0);

    // Maps memory this image does NOT own; `data` must outlive it. The minidump
    // backend points these straight at the mapped .dmp file, so the bulk of a
    // multi-GB dump is never copied — only module images, which have to be
    // reassembled from several ranges, get a buffer of their own.
    void add_view(std::uint64_t base, const std::uint8_t* data, std::uint64_t size,
                  std::uint32_t flags = 0);
    // Sorts by base and drops any segment that overlaps an earlier one; where two
    // start at the same base the LARGER is kept. Reads before finalize() are
    // undefined.
    void finalize();

    // The one mapped-or-not test. nullptr if `va` is not mapped.
    const Segment* segment_at(std::uint64_t va) const;
    bool is_mapped(std::uint64_t va) const { return segment_at(va) != nullptr; }
    const std::vector<Segment>& segments() const { return segs_; }
    bool empty() const { return segs_.empty(); }

    // The bytes of the segment containing `va`, from `va` to that segment's end.
    // Empty if unmapped. Reads never straddle a segment boundary.
    std::span<const std::uint8_t> view(std::uint64_t va) const;

    // Up to `n` bytes, clamped to the end of the containing segment; empty if `va`
    // is unmapped. A short result means the segment ended, not that memory is absent.
    std::vector<std::uint8_t> read(std::uint64_t va, std::size_t n) const;

    // Little-endian pointer of `psize` bytes. Pointer width is a property of the
    // *reader*, not the image: one MemoryImage serves both the 32- and 64-bit modules
    // of a WOW64 process, so the caller supplies it.
    std::optional<std::uint64_t> read_pointer(std::uint64_t va, int psize) const;

    // vivisect read_string: an ASCII or UTF-16LE string starting at `va`, else
    // nullopt. Terminated by a NUL or by the end of the containing segment.
    std::optional<std::string> read_string(std::uint64_t va) const;
    bool is_probably_string(std::uint64_t va) const;

    // The single-region image the TTD `--scan-code` path uses.
    static MemoryImage single(std::uint64_t base, std::vector<std::uint8_t> bytes);

private:
    // deque, not vector: a vector realloc would dangle every Segment::data.
    std::deque<std::vector<std::uint8_t>> store_;
    std::vector<Segment> segs_;  // sorted by base, non-overlapping
    // Access is highly local (an instruction walk stays in one segment for a long
    // time), so remember the last hit and skip the binary search.
    mutable std::size_t last_hit_ = 0;
};

}  // namespace capa::stat
