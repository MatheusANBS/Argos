#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain {

// Pointer width of the *target*, never of the MCP process. inspect_address
// requires it explicitly: reading a WOW64 target with the host width either
// truncates a 64-bit address or over-reads a 32-bit one, and both mistakes look
// like a plausible candidate instead of an error.
enum class TargetPointerWidth : std::uint8_t { x86 = 4, x64 = 8 };

[[nodiscard]] constexpr std::size_t pointer_width_bytes(const TargetPointerWidth width) noexcept {
    return static_cast<std::size_t>(width);
}

[[nodiscard]] std::optional<TargetPointerWidth> pointer_width_from_string(std::string_view text) noexcept;

// Every classification this file produces is derived from a bounded sample of a
// mutable address space. "high" still means probable.
enum class DerivedConfidence { low, medium, high };

enum class ReferenceSource { none, index, live_scan };

// Facts observed about a candidate, never a conclusion. `observed` and
// `sampled` keep a partial sample distinguishable from a complete one.
enum class EvidenceKind {
    object_base_in_readable_region,
    object_base_in_writable_region,
    vtable_in_readable_region,
    vtable_in_non_writable_region,
    vtable_owned_by_module,
    executable_vtable_entry,
    non_executable_vtable_entry,
    short_vtable_sample,
    same_module_code_targets,
};

enum class ProvenanceKind {
    region_map_snapshot,
    module_map_snapshot,
    bounded_memory_sample,
    derived_vtable_shape,
    pointer_index_snapshot,
    live_reverse_scan,
};

// Why the analysis is less than complete. Reported instead of silently
// degrading a result into something that reads as conclusive.
enum class InspectionLimitation {
    address_not_mapped,
    region_not_readable,
    lookbehind_clamped_to_region,
    lookbehind_short_read,
    base_scan_limit_reached,
    vtable_probe_limit_reached,
    vtable_short_read,
    candidate_limit_reached,
    references_incomplete,
};

[[nodiscard]] std::string_view to_string(DerivedConfidence confidence) noexcept;
[[nodiscard]] std::string_view to_string(ReferenceSource source) noexcept;
[[nodiscard]] std::string_view to_string(EvidenceKind kind) noexcept;
[[nodiscard]] std::string_view to_string(ProvenanceKind kind) noexcept;
[[nodiscard]] std::string_view to_string(InspectionLimitation limitation) noexcept;

struct DerivedEvidence {
    EvidenceKind kind{};
    std::uint32_t observed{};
    std::uint32_t sampled{};
};

// Module identity stays an index into the normalized module map while ranking
// runs; names are materialized once, at the response boundary.
struct ModuleReference {
    std::size_t module_index{};
    std::uint64_t rva{};
};

struct ProbableObjectCandidate {
    Address object_address{};
    std::uint64_t field_offset{};
    Address vtable_address{};
    std::optional<ModuleReference> vtable_module;
    DerivedConfidence confidence{};
    std::vector<DerivedEvidence> evidence;
    std::vector<ProvenanceKind> provenance;
};

// Hard ceilings. Requests are clamped or rejected against these before any
// allocation or process read, so a hostile argument cannot size the work.
inline constexpr std::uint64_t inspection_max_lookbehind_bytes = 16U * 1024U;
inline constexpr std::size_t inspection_max_examined_bases = 4096U;
inline constexpr std::size_t inspection_max_vtable_probes = 128U;
inline constexpr std::size_t inspection_max_vtable_entries = 64U;
inline constexpr std::size_t inspection_max_object_candidates = 64U;
inline constexpr std::size_t inspection_max_evidence_per_candidate = 32U;
inline constexpr std::size_t inspection_max_provenance_per_candidate = 16U;
inline constexpr std::size_t inspection_max_limitations = 64U;

inline constexpr std::uint64_t inspection_default_lookbehind_bytes = 512U;
inline constexpr std::size_t inspection_default_vtable_probes = 16U;
inline constexpr std::size_t inspection_default_vtable_entries = 8U;
inline constexpr std::size_t inspection_default_min_executable_entries = 3U;
inline constexpr std::size_t inspection_default_object_candidates = 8U;

// The ranking score is internal and versioned: the response exposes the facts
// that produced an order, not the number itself, so the heuristic can change
// without the contract implying it did not.
inline constexpr std::uint32_t inspection_score_version = 1U;

struct InspectionLimits {
    std::uint64_t lookbehind_bytes{inspection_default_lookbehind_bytes};
    std::size_t max_examined_bases{inspection_max_examined_bases};
    std::size_t max_vtable_probes{inspection_default_vtable_probes};
    std::size_t vtable_entries{inspection_default_vtable_entries};
    std::size_t min_executable_entries{inspection_default_min_executable_entries};
    std::size_t max_candidates{inspection_default_object_candidates};
    std::size_t max_evidence{inspection_max_evidence_per_candidate / 2U};
    std::size_t max_provenance{inspection_max_provenance_per_candidate / 2U};
    std::size_t max_limitations{inspection_max_limitations / 4U};

    // Validated before any I/O. Relations between limits (notably
    // min_executable_entries <= vtable_entries) are part of the contract.
    [[nodiscard]] Result<void> validate() const;
};

// Checked address arithmetic. Every range this file derives goes through these
// instead of wrapping silently into a plausible-looking address.
[[nodiscard]] std::optional<Address> checked_add(Address address, std::uint64_t delta) noexcept;
[[nodiscard]] std::optional<Address> checked_sub(Address address, std::uint64_t delta) noexcept;

// Little-endian decode of exactly `width` bytes, byte by byte: no unaligned
// cast, and no dependence on the host's own pointer size or endianness.
[[nodiscard]] Address decode_target_pointer(
    std::span<const std::byte> bytes,
    TargetPointerWidth width
) noexcept;

// Sorted, validated view over a region map. Half-open [start, end) intervals;
// degenerate entries are dropped rather than silently matching an address.
class RegionIndex final {
public:
    RegionIndex() = default;
    [[nodiscard]] static RegionIndex create(std::span<const MemoryRegion> regions);

    [[nodiscard]] const MemoryRegion* find(Address address) const noexcept;
    [[nodiscard]] std::span<const MemoryRegion> all() const noexcept { return regions_; }
    [[nodiscard]] std::size_t size() const noexcept { return regions_.size(); }

private:
    std::vector<MemoryRegion> regions_;
};

class ModuleIndex final {
public:
    ModuleIndex() = default;
    [[nodiscard]] static ModuleIndex create(std::span<const ModuleInfo> modules);

    [[nodiscard]] std::optional<std::size_t> index_of(Address address) const noexcept;
    [[nodiscard]] const ModuleInfo* find(Address address) const noexcept;
    [[nodiscard]] std::optional<ModuleReference> reference(Address address) const noexcept;
    [[nodiscard]] std::span<const ModuleInfo> all() const noexcept { return modules_; }
    [[nodiscard]] const ModuleInfo* at(std::size_t index) const noexcept;

private:
    std::vector<ModuleInfo> modules_;
};

// Half-open byte range actually worth reading before the inspected address.
// The lookbehind limit measures distance backwards; the window may still
// include one pointer starting at the inspected address itself.
struct LookbehindWindow {
    Address start{};
    Address end{};
    bool clamped_by_region{false};

    [[nodiscard]] std::uint64_t size() const noexcept { return end > start ? end - start : 0U; }
};

[[nodiscard]] Result<LookbehindWindow> compute_lookbehind_window(
    Address address,
    TargetPointerWidth width,
    std::uint64_t lookbehind_bytes,
    const MemoryRegion& region
);

// A pointer-aligned position at or before the inspected address whose stored
// value is shaped like a vptr. Still only a shape: nothing here dereferences a
// function or claims a type.
struct BaseCandidate {
    Address object_address{};
    std::uint64_t field_offset{};
    Address vtable_address{};
    ModuleReference vtable_module;
    bool object_base_readable{false};
    bool object_base_writable{false};
};

struct BaseScanResult {
    std::vector<BaseCandidate> bases;
    std::size_t bases_examined{};
    std::size_t bases_matched{};
    bool base_limit_reached{false};
    bool probe_limit_reached{false};
};

// Pure: walks a sample already read by the caller. Bases are enumerated from
// the inspected address backwards, so when the probe budget binds it keeps the
// nearest -- and therefore smallest field_offset -- shapes.
[[nodiscard]] BaseScanResult collect_base_candidates(
    Address inspected,
    TargetPointerWidth width,
    Address sample_base,
    std::span<const std::byte> sample,
    const RegionIndex& regions,
    const ModuleIndex& modules,
    const InspectionLimits& limits
);

// One bounded read of a suspected vtable. `entries` holds only the entries that
// were read in full: a short read is reported, never zero-filled.
struct VtableProbe {
    Address vtable_address{};
    std::vector<Address> entries;
    std::uint32_t requested_entries{};
    bool short_read{false};
};

struct ClassifiedInspection {
    std::vector<ProbableObjectCandidate> candidates;
    std::size_t candidates_total{};
    bool truncated{false};
    bool short_vtable_read{false};
};

// Pure ranking over shapes plus their probes. `probes` is parallel to `bases`.
[[nodiscard]] ClassifiedInspection classify_object_candidates(
    std::span<const BaseCandidate> bases,
    std::span<const VtableProbe> probes,
    const RegionIndex& regions,
    const ModuleIndex& modules,
    const InspectionLimits& limits
);

// Opaque, server-authoritative continuation for a bounded reverse-reference
// slice. The token carries the position *and* a keyed digest of the query it
// belongs to, so a token cannot be replayed against another session, target,
// pointer width or filter set -- and a raw address can never stand in for it.
namespace resume_token {

// Building blocks so any bounded, paginated operation can bind its own
// continuation to the query that produced it.
[[nodiscard]] std::uint64_t combine(std::uint64_t seed, std::uint64_t value) noexcept;
[[nodiscard]] std::uint64_t digest(std::string_view text, std::uint64_t seed) noexcept;

[[nodiscard]] std::uint64_t binding(
    std::string_view session_id,
    Address target,
    TargetPointerWidth width,
    bool writable_only,
    std::optional<Address> start_address,
    std::optional<Address> end_address
) noexcept;

[[nodiscard]] std::string encode(std::uint64_t key, std::uint64_t binding_digest, Address next_address);

[[nodiscard]] std::optional<Address> decode(
    std::string_view token,
    std::uint64_t key,
    std::uint64_t binding_digest
) noexcept;

}  // namespace resume_token

}  // namespace argos::domain
