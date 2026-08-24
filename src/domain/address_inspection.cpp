#include "argos_mcp/domain/address_inspection.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <system_error>
#include <utility>

namespace argos::domain {
namespace {

[[nodiscard]] DebugError error(const DebugErrorCode code, std::string message) {
    return DebugError{code, std::move(message)};
}

[[nodiscard]] std::uint64_t mix64(std::uint64_t value) noexcept {
    value ^= value >> 33U;
    value *= 0xFF51AFD7ED558CCDULL;
    value ^= value >> 33U;
    value *= 0xC4CEB9FE1A85EC53ULL;
    value ^= value >> 33U;
    return value;
}

void hash_combine(std::uint64_t& seed, const std::uint64_t value) noexcept {
    seed = mix64(seed ^ (value + 0x9E3779B97F4A7C15ULL + (seed << 6U) + (seed >> 2U)));
}

[[nodiscard]] std::string hex64(const std::uint64_t value) {
    std::array<char, 16> buffer{};
    buffer.fill('0');
    const auto [ptr, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, 16);
    if (ec != std::errc{}) {
        return std::string(buffer.data(), buffer.size());
    }
    const auto written = static_cast<std::size_t>(ptr - buffer.data());
    std::string output(16U - written, '0');
    output.append(buffer.data(), written);
    return output;
}

[[nodiscard]] std::optional<std::uint64_t> parse_hex64(const std::string_view text) noexcept {
    if (text.size() != 16U) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (ec != std::errc{} || ptr != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

}  // namespace

std::optional<TargetPointerWidth> pointer_width_from_string(const std::string_view text) noexcept {
    if (text == "4") return TargetPointerWidth::x86;
    if (text == "8") return TargetPointerWidth::x64;
    return std::nullopt;
}

std::string_view to_string(const DerivedConfidence confidence) noexcept {
    switch (confidence) {
        case DerivedConfidence::low: return "low";
        case DerivedConfidence::medium: return "medium";
        case DerivedConfidence::high: return "high";
    }
    return "low";
}

std::string_view to_string(const ReferenceSource source) noexcept {
    switch (source) {
        case ReferenceSource::none: return "none";
        case ReferenceSource::index: return "index";
        case ReferenceSource::live_scan: return "live_scan";
    }
    return "none";
}

std::string_view to_string(const EvidenceKind kind) noexcept {
    switch (kind) {
        case EvidenceKind::object_base_in_readable_region: return "object_base_in_readable_region";
        case EvidenceKind::object_base_in_writable_region: return "object_base_in_writable_region";
        case EvidenceKind::vtable_in_readable_region: return "vtable_in_readable_region";
        case EvidenceKind::vtable_in_non_writable_region: return "vtable_in_non_writable_region";
        case EvidenceKind::vtable_owned_by_module: return "vtable_owned_by_module";
        case EvidenceKind::executable_vtable_entry: return "executable_vtable_entry";
        case EvidenceKind::non_executable_vtable_entry: return "non_executable_vtable_entry";
        case EvidenceKind::short_vtable_sample: return "short_vtable_sample";
        case EvidenceKind::same_module_code_targets: return "same_module_code_targets";
    }
    return "unknown";
}

std::string_view to_string(const ProvenanceKind kind) noexcept {
    switch (kind) {
        case ProvenanceKind::region_map_snapshot: return "region_map_snapshot";
        case ProvenanceKind::module_map_snapshot: return "module_map_snapshot";
        case ProvenanceKind::bounded_memory_sample: return "bounded_memory_sample";
        case ProvenanceKind::derived_vtable_shape: return "derived_vtable_shape";
        case ProvenanceKind::pointer_index_snapshot: return "pointer_index_snapshot";
        case ProvenanceKind::live_reverse_scan: return "live_reverse_scan";
    }
    return "unknown";
}

std::string_view to_string(const InspectionLimitation limitation) noexcept {
    switch (limitation) {
        case InspectionLimitation::address_not_mapped: return "address_not_mapped";
        case InspectionLimitation::region_not_readable: return "region_not_readable";
        case InspectionLimitation::lookbehind_clamped_to_region: return "lookbehind_clamped_to_region";
        case InspectionLimitation::lookbehind_short_read: return "lookbehind_short_read";
        case InspectionLimitation::base_scan_limit_reached: return "base_scan_limit_reached";
        case InspectionLimitation::vtable_probe_limit_reached: return "vtable_probe_limit_reached";
        case InspectionLimitation::vtable_short_read: return "vtable_short_read";
        case InspectionLimitation::candidate_limit_reached: return "candidate_limit_reached";
        case InspectionLimitation::references_incomplete: return "references_incomplete";
    }
    return "unknown";
}

Result<void> InspectionLimits::validate() const {
    if (lookbehind_bytes > inspection_max_lookbehind_bytes) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "lookbehind_bytes exceeds the inspection limit"
        ));
    }
    if (vtable_entries == 0U || vtable_entries > inspection_max_vtable_entries) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "vtable_entries must be between 1 and the inspection limit"
        ));
    }
    if (min_executable_entries == 0U) {
        return std::unexpected(error(
            DebugErrorCode::invalid_argument, "min_executable_entries must be positive"
        ));
    }
    // A minimum above the sample size can never be met, so the request would
    // always return an empty candidate list for a reason the caller did not
    // intend. Rejecting it is cheaper than explaining the empty result.
    if (min_executable_entries > vtable_entries) {
        return std::unexpected(error(
            DebugErrorCode::invalid_argument, "min_executable_entries must not exceed vtable_entries"
        ));
    }
    if (max_candidates == 0U || max_candidates > inspection_max_object_candidates) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "max_object_candidates must be between 1 and the inspection limit"
        ));
    }
    if (max_vtable_probes == 0U || max_vtable_probes > inspection_max_vtable_probes) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "vtable probe count must be between 1 and the inspection limit"
        ));
    }
    if (max_examined_bases == 0U || max_examined_bases > inspection_max_examined_bases) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "examined base count must be between 1 and the inspection limit"
        ));
    }
    if (max_evidence == 0U || max_evidence > inspection_max_evidence_per_candidate) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "evidence limit exceeds the inspection limit"
        ));
    }
    if (max_provenance == 0U || max_provenance > inspection_max_provenance_per_candidate) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "provenance limit exceeds the inspection limit"
        ));
    }
    if (max_limitations == 0U || max_limitations > inspection_max_limitations) {
        return std::unexpected(error(
            DebugErrorCode::limit_exceeded, "limitation limit exceeds the inspection limit"
        ));
    }
    return {};
}

std::optional<Address> checked_add(const Address address, const std::uint64_t delta) noexcept {
    if (delta > std::numeric_limits<Address>::max() - address) {
        return std::nullopt;
    }
    return address + delta;
}

std::optional<Address> checked_sub(const Address address, const std::uint64_t delta) noexcept {
    if (delta > address) {
        return std::nullopt;
    }
    return address - delta;
}

Address decode_target_pointer(const std::span<const std::byte> bytes, const TargetPointerWidth width) noexcept {
    const auto count = std::min(bytes.size(), pointer_width_bytes(width));
    Address value = 0;
    for (std::size_t index = 0; index < count; ++index) {
        value |= static_cast<Address>(std::to_integer<unsigned int>(bytes[index])) << (index * 8U);
    }
    return value;
}

RegionIndex RegionIndex::create(const std::span<const MemoryRegion> regions) {
    RegionIndex index;
    index.regions_.reserve(regions.size());
    for (const auto& region : regions) {
        // A degenerate or inverted interval cannot contain an address; keeping
        // it would make the binary search answer questions about a range that
        // does not exist.
        if (region.end > region.start) {
            index.regions_.push_back(region);
        }
    }
    std::ranges::sort(index.regions_, {}, &MemoryRegion::start);
    return index;
}

const MemoryRegion* RegionIndex::find(const Address address) const noexcept {
    const auto upper = std::ranges::upper_bound(regions_, address, {}, &MemoryRegion::start);
    if (upper == regions_.begin()) {
        return nullptr;
    }
    const auto candidate = std::prev(upper);
    return address < candidate->end ? &(*candidate) : nullptr;
}

ModuleIndex ModuleIndex::create(const std::span<const ModuleInfo> modules) {
    ModuleIndex index;
    index.modules_.reserve(modules.size());
    for (const auto& module : modules) {
        if (module.size != 0U && checked_add(module.base, module.size).has_value()) {
            index.modules_.push_back(module);
        }
    }
    std::ranges::sort(index.modules_, {}, &ModuleInfo::base);
    return index;
}

std::optional<std::size_t> ModuleIndex::index_of(const Address address) const noexcept {
    const auto upper = std::ranges::upper_bound(modules_, address, {}, &ModuleInfo::base);
    if (upper == modules_.begin()) {
        return std::nullopt;
    }
    const auto candidate = std::prev(upper);
    if (address - candidate->base >= candidate->size) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(candidate - modules_.begin());
}

const ModuleInfo* ModuleIndex::find(const Address address) const noexcept {
    const auto index = index_of(address);
    return index ? &modules_[*index] : nullptr;
}

std::optional<ModuleReference> ModuleIndex::reference(const Address address) const noexcept {
    const auto index = index_of(address);
    if (!index) {
        return std::nullopt;
    }
    return ModuleReference{*index, address - modules_[*index].base};
}

const ModuleInfo* ModuleIndex::at(const std::size_t index) const noexcept {
    return index < modules_.size() ? &modules_[index] : nullptr;
}

Result<LookbehindWindow> compute_lookbehind_window(
    const Address address,
    const TargetPointerWidth width,
    const std::uint64_t lookbehind_bytes,
    const MemoryRegion& region
) {
    if (address < region.start || address >= region.end) {
        return std::unexpected(error(
            DebugErrorCode::invalid_argument, "address is outside the supplied region"
        ));
    }
    const auto pointer_size = static_cast<std::uint64_t>(pointer_width_bytes(width));
    // The lookbehind measures distance backwards; the buffer may still include
    // one pointer that starts exactly at the inspected address.
    const auto raw_end = checked_add(address, pointer_size);
    if (!raw_end) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "address overflows a pointer read"));
    }
    const Address end = std::min(region.end, *raw_end);
    const Address requested_start = checked_sub(address, lookbehind_bytes).value_or(0U);
    const Address start = std::max(region.start, requested_start);
    LookbehindWindow window{start, end, start > requested_start};
    if (window.end <= window.start) {
        return std::unexpected(error(
            DebugErrorCode::invalid_argument, "region leaves no readable bytes at the inspected address"
        ));
    }
    return window;
}

BaseScanResult collect_base_candidates(
    const Address inspected,
    const TargetPointerWidth width,
    const Address sample_base,
    const std::span<const std::byte> sample,
    const RegionIndex& regions,
    const ModuleIndex& modules,
    const InspectionLimits& limits
) {
    BaseScanResult result;
    const auto pointer_size = static_cast<std::uint64_t>(pointer_width_bytes(width));
    if (sample.size() < pointer_size || inspected < sample_base) {
        return result;
    }
    const auto sample_end = checked_add(sample_base, sample.size());
    if (!sample_end) {
        return result;
    }

    // Alignment follows the virtual address, not the buffer offset: the sample
    // may start at an address that is not itself pointer-aligned, so the
    // aligned-down base can land *below* the window.
    Address base = inspected - (inspected % pointer_size);
    while (base > sample_base && checked_add(base, pointer_size).value_or(0U) > *sample_end) {
        base -= pointer_size;
    }
    if (base < sample_base || checked_add(base, pointer_size).value_or(0U) > *sample_end) {
        return result;
    }

    result.bases.reserve(std::min<std::size_t>(limits.max_vtable_probes, 16U));
    while (true) {
        ++result.bases_examined;
        const auto offset = static_cast<std::size_t>(base - sample_base);
        const auto stored = decode_target_pointer(sample.subspan(offset, static_cast<std::size_t>(pointer_size)), width);
        if (stored != 0U) {
            const auto* vtable_region = regions.find(stored);
            const auto vtable_module = modules.reference(stored);
            // First version keeps only shapes whose stored value could be a
            // vptr: readable, not writable and owned by a module. Anything
            // weaker would flood the ranking with heap noise.
            if (vtable_region != nullptr && vtable_region->readable && !vtable_region->writable &&
                vtable_module.has_value()) {
                const auto* base_region = regions.find(base);
                result.bases.push_back(BaseCandidate{
                    base,
                    inspected - base,
                    stored,
                    *vtable_module,
                    base_region != nullptr && base_region->readable,
                    base_region != nullptr && base_region->writable
                });
                ++result.bases_matched;
                if (result.bases.size() >= limits.max_vtable_probes) {
                    result.probe_limit_reached = true;
                    break;
                }
            }
        }
        // Distinguish "walked the whole window" from "ran out of budget with
        // bases still below": only the second is a reportable limitation.
        if (base < sample_base + pointer_size) {
            break;
        }
        if (result.bases_examined >= limits.max_examined_bases) {
            result.base_limit_reached = true;
            break;
        }
        base -= pointer_size;
    }
    return result;
}

namespace {

struct RankedCandidate {
    std::int64_t score{};
    std::uint32_t executable_entries{};
    ProbableObjectCandidate candidate;
};

void push_bounded(
    std::vector<DerivedEvidence>& evidence,
    const std::size_t limit,
    const DerivedEvidence item
) {
    if (evidence.size() < limit) {
        evidence.push_back(item);
    }
}

void push_bounded(
    std::vector<ProvenanceKind>& provenance,
    const std::size_t limit,
    const ProvenanceKind item
) {
    if (provenance.size() < limit) {
        provenance.push_back(item);
    }
}

}  // namespace

ClassifiedInspection classify_object_candidates(
    const std::span<const BaseCandidate> bases,
    const std::span<const VtableProbe> probes,
    const RegionIndex& regions,
    const ModuleIndex& modules,
    const InspectionLimits& limits
) {
    ClassifiedInspection result;
    std::vector<RankedCandidate> ranked;
    ranked.reserve(std::min(bases.size(), probes.size()));

    const auto count = std::min(bases.size(), probes.size());
    for (std::size_t index = 0; index < count; ++index) {
        const auto& base = bases[index];
        const auto& probe = probes[index];
        if (probe.vtable_address != base.vtable_address) {
            continue;
        }
        if (probe.short_read) {
            result.short_vtable_read = true;
        }

        std::uint32_t executable = 0;
        std::uint32_t same_module = 0;
        for (const auto entry : probe.entries) {
            const auto* entry_region = regions.find(entry);
            if (entry_region == nullptr || !entry_region->executable) {
                continue;
            }
            ++executable;
            const auto owner = modules.index_of(entry);
            if (owner && *owner == base.vtable_module.module_index) {
                ++same_module;
            }
        }
        // A shape that never reaches the minimum number of executable entries
        // is not reported at all: a weak signal must not become a low-confidence
        // answer that reads like one.
        if (executable < limits.min_executable_entries) {
            continue;
        }

        const auto sampled = static_cast<std::uint32_t>(probe.entries.size());
        const std::uint32_t non_executable = sampled - executable;
        const bool full_sample = !probe.short_read && sampled == probe.requested_entries;

        std::size_t signals = 0;
        if (full_sample && non_executable == 0U) ++signals;
        if (same_module >= limits.min_executable_entries) ++signals;
        if (base.object_base_writable) ++signals;

        DerivedConfidence confidence = DerivedConfidence::low;
        if (full_sample && signals >= 2U) {
            confidence = DerivedConfidence::high;
        } else if (signals >= 1U) {
            confidence = DerivedConfidence::medium;
        }

        ProbableObjectCandidate candidate;
        candidate.object_address = base.object_address;
        candidate.field_offset = base.field_offset;
        candidate.vtable_address = base.vtable_address;
        candidate.vtable_module = base.vtable_module;
        candidate.confidence = confidence;

        // Ordered strongest signal first so a tight evidence budget keeps what
        // actually justifies the ranking.
        candidate.evidence.reserve(std::min<std::size_t>(limits.max_evidence, 9U));
        push_bounded(candidate.evidence, limits.max_evidence,
            DerivedEvidence{EvidenceKind::executable_vtable_entry, executable, sampled});
        if (same_module != 0U) {
            push_bounded(candidate.evidence, limits.max_evidence,
                DerivedEvidence{EvidenceKind::same_module_code_targets, same_module, sampled});
        }
        push_bounded(candidate.evidence, limits.max_evidence,
            DerivedEvidence{EvidenceKind::vtable_owned_by_module, 1U, 1U});
        push_bounded(candidate.evidence, limits.max_evidence,
            DerivedEvidence{EvidenceKind::vtable_in_non_writable_region, 1U, 1U});
        push_bounded(candidate.evidence, limits.max_evidence,
            DerivedEvidence{EvidenceKind::vtable_in_readable_region, 1U, 1U});
        if (non_executable != 0U) {
            push_bounded(candidate.evidence, limits.max_evidence,
                DerivedEvidence{EvidenceKind::non_executable_vtable_entry, non_executable, sampled});
        }
        if (!full_sample) {
            push_bounded(candidate.evidence, limits.max_evidence,
                DerivedEvidence{EvidenceKind::short_vtable_sample, sampled, probe.requested_entries});
        }
        if (base.object_base_writable) {
            push_bounded(candidate.evidence, limits.max_evidence,
                DerivedEvidence{EvidenceKind::object_base_in_writable_region, 1U, 1U});
        }
        if (base.object_base_readable) {
            push_bounded(candidate.evidence, limits.max_evidence,
                DerivedEvidence{EvidenceKind::object_base_in_readable_region, 1U, 1U});
        }

        candidate.provenance.reserve(std::min<std::size_t>(limits.max_provenance, 4U));
        push_bounded(candidate.provenance, limits.max_provenance, ProvenanceKind::region_map_snapshot);
        push_bounded(candidate.provenance, limits.max_provenance, ProvenanceKind::module_map_snapshot);
        push_bounded(candidate.provenance, limits.max_provenance, ProvenanceKind::bounded_memory_sample);
        push_bounded(candidate.provenance, limits.max_provenance, ProvenanceKind::derived_vtable_shape);

        std::int64_t score = static_cast<std::int64_t>(executable) * 8;
        score += static_cast<std::int64_t>(same_module) * 4;
        score -= static_cast<std::int64_t>(non_executable);
        if (full_sample) score += 2;
        if (base.object_base_writable) score += 1;

        ranked.push_back(RankedCandidate{score, executable, std::move(candidate)});
    }

    result.candidates_total = ranked.size();
    std::ranges::sort(ranked, [](const RankedCandidate& lhs, const RankedCandidate& rhs) {
        if (lhs.score != rhs.score) return lhs.score > rhs.score;
        if (lhs.executable_entries != rhs.executable_entries) {
            return lhs.executable_entries > rhs.executable_entries;
        }
        if (lhs.candidate.field_offset != rhs.candidate.field_offset) {
            return lhs.candidate.field_offset < rhs.candidate.field_offset;
        }
        return lhs.candidate.object_address < rhs.candidate.object_address;
    });

    result.truncated = ranked.size() > limits.max_candidates;
    const auto kept = std::min(ranked.size(), limits.max_candidates);
    result.candidates.reserve(kept);
    for (std::size_t index = 0; index < kept; ++index) {
        result.candidates.push_back(std::move(ranked[index].candidate));
    }
    return result;
}

namespace resume_token {

std::uint64_t combine(std::uint64_t seed, const std::uint64_t value) noexcept {
    hash_combine(seed, value);
    return seed;
}

std::uint64_t digest(const std::string_view text, std::uint64_t seed) noexcept {
    for (const char ch : text) {
        hash_combine(seed, static_cast<std::uint64_t>(static_cast<unsigned char>(ch)));
    }
    return seed;
}

std::uint64_t binding(
    const std::string_view session_id,
    const Address target,
    const TargetPointerWidth width,
    const bool writable_only,
    const std::optional<Address> start_address,
    const std::optional<Address> end_address
) noexcept {
    auto value = digest(session_id, 0xCBF29CE484222325ULL);
    value = combine(value, target);
    value = combine(value, static_cast<std::uint64_t>(pointer_width_bytes(width)));
    value = combine(value, writable_only ? 1U : 0U);
    value = combine(value, start_address ? 1U : 0U);
    value = combine(value, start_address.value_or(0U));
    value = combine(value, end_address ? 1U : 0U);
    value = combine(value, end_address.value_or(0U));
    return value;
}

std::string encode(const std::uint64_t key, const std::uint64_t binding_digest, const Address next_address) {
    std::uint64_t tag = key;
    hash_combine(tag, binding_digest);
    hash_combine(tag, next_address);
    return "01" + hex64(next_address) + hex64(tag);
}

std::optional<Address> decode(
    const std::string_view token,
    const std::uint64_t key,
    const std::uint64_t binding_digest
) noexcept {
    if (token.size() != 34U || token.substr(0U, 2U) != "01") {
        return std::nullopt;
    }
    const auto next_address = parse_hex64(token.substr(2U, 16U));
    const auto tag = parse_hex64(token.substr(18U, 16U));
    if (!next_address || !tag) {
        return std::nullopt;
    }
    std::uint64_t expected = key;
    hash_combine(expected, binding_digest);
    hash_combine(expected, *next_address);
    if ((expected ^ *tag) != 0U) {
        return std::nullopt;
    }
    return *next_address;
}

}  // namespace resume_token

}  // namespace argos::domain
