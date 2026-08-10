#include "argos_mcp/domain/types.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <type_traits>
#include <utility>

namespace argos::domain {
namespace {

template <typename T>
[[nodiscard]] std::vector<std::byte> to_little_endian(const T value) {
    static_assert(std::is_trivially_copyable_v<T>);
    std::array<std::byte, sizeof(T)> raw{};
    std::memcpy(raw.data(), &value, sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        std::ranges::reverse(raw);
    }
    return std::vector<std::byte>(raw.begin(), raw.end());
}

// Integral path: parse into the widest signed/unsigned form, then range-check
// against the requested width before narrowing.
template <typename T>
[[nodiscard]] std::expected<std::vector<std::byte>, std::string> encode_integral(
    const std::string_view decimal
) {
    if constexpr (std::is_signed_v<T>) {
        std::int64_t parsed = 0;
        const auto* const first = decimal.data();
        const auto* const last = decimal.data() + decimal.size();
        const auto [ptr, ec] = std::from_chars(first, last, parsed);
        if (ec != std::errc{} || ptr != last) {
            return std::unexpected(std::string{"value must be a decimal integer"});
        }
        if (parsed < static_cast<std::int64_t>(std::numeric_limits<T>::min()) ||
            parsed > static_cast<std::int64_t>(std::numeric_limits<T>::max())) {
            return std::unexpected(std::string{"value does not fit in the requested value_type"});
        }
        return to_little_endian(static_cast<T>(parsed));
    } else {
        if (!decimal.empty() && decimal.front() == '-') {
            return std::unexpected(std::string{"negative value requires a signed value_type"});
        }
        std::uint64_t parsed = 0;
        const auto* const first = decimal.data();
        const auto* const last = decimal.data() + decimal.size();
        const auto [ptr, ec] = std::from_chars(first, last, parsed);
        if (ec != std::errc{} || ptr != last) {
            return std::unexpected(std::string{"value must be a decimal integer"});
        }
        if (parsed > static_cast<std::uint64_t>(std::numeric_limits<T>::max())) {
            return std::unexpected(std::string{"value does not fit in the requested value_type"});
        }
        return to_little_endian(static_cast<T>(parsed));
    }
}

template <typename T>
[[nodiscard]] std::expected<std::vector<std::byte>, std::string> encode_floating(
    const std::string_view decimal
) {
    double parsed = 0.0;
    const auto* const first = decimal.data();
    const auto* const last = decimal.data() + decimal.size();
    const auto [ptr, ec] = std::from_chars(first, last, parsed);
    if (ec != std::errc{} || ptr != last) {
        return std::unexpected(std::string{"value must be a decimal number"});
    }
    if (!std::isfinite(parsed)) {
        return std::unexpected(std::string{"value must be finite"});
    }
    if (parsed < static_cast<double>(std::numeric_limits<T>::lowest()) ||
        parsed > static_cast<double>(std::numeric_limits<T>::max()) ||
        (parsed != 0.0 && std::abs(parsed) < static_cast<double>(std::numeric_limits<T>::denorm_min()))) {
        return std::unexpected(std::string{"value does not fit in the requested value_type"});
    }
    const auto narrowed = static_cast<T>(parsed);
    if (!std::isfinite(narrowed) || (parsed != 0.0 && narrowed == static_cast<T>(0))) {
        return std::unexpected(std::string{"value does not fit in the requested value_type"});
    }
    return to_little_endian(narrowed);
}

[[nodiscard]] std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1U);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1U);
    return text;
}

[[nodiscard]] bool contains_ci(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    const auto lower = [](const char ch) noexcept {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    };
    for (std::size_t start = 0; start + needle.size() <= haystack.size(); ++start) {
        bool hit = true;
        for (std::size_t index = 0; index < needle.size(); ++index) {
            if (lower(haystack[start + index]) != lower(needle[index])) {
                hit = false;
                break;
            }
        }
        if (hit) return true;
    }
    return false;
}

}  // namespace

std::expected<SessionId, std::string> SessionId::create(std::string value) {
    const auto valid = !value.empty() && value.size() <= 128U &&
        std::ranges::all_of(value, [](const unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });
    if (!valid) {
        return std::unexpected("invalid session id");
    }
    return SessionId{std::move(value)};
}

std::expected<ScanSessionId, std::string> ScanSessionId::create(std::string value) {
    const auto valid = !value.empty() && value.size() <= 128U &&
        std::ranges::all_of(value, [](const unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });
    if (!valid) {
        return std::unexpected("invalid scan session id");
    }
    return ScanSessionId{std::move(value)};
}

std::expected<AnalysisJobId, std::string> AnalysisJobId::create(std::string value) {
    const auto valid = !value.empty() && value.size() <= 128U &&
        std::ranges::all_of(value, [](const unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });
    if (!valid) {
        return std::unexpected("invalid analysis job id");
    }
    return AnalysisJobId{std::move(value)};
}

std::expected<ScanResumeToken, std::string> ScanResumeToken::create(std::string value) {
    const auto valid = !value.empty() && value.size() <= 256U &&
        std::ranges::all_of(value, [](const unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '-' || ch == '_';
        });
    if (!valid) {
        return std::unexpected("invalid resume token");
    }
    return ScanResumeToken{std::move(value)};
}

std::string_view to_string(const AccessMode mode) noexcept {
    switch (mode) {
        case AccessMode::read_only: return "read_only";
        case AccessMode::read_write: return "read_write";
    }
    return "unknown";
}

std::string_view to_string(const DebugErrorCode code) noexcept {
    switch (code) {
        case DebugErrorCode::invalid_argument: return "invalid_argument";
        case DebugErrorCode::unauthorized: return "unauthorized";
        case DebugErrorCode::not_found: return "not_found";
        case DebugErrorCode::access_denied: return "access_denied";
        case DebugErrorCode::unsupported: return "unsupported";
        case DebugErrorCode::io_error: return "io_error";
        case DebugErrorCode::limit_exceeded: return "limit_exceeded";
        case DebugErrorCode::invalid_state: return "invalid_state";
        case DebugErrorCode::cancelled: return "cancelled";
        case DebugErrorCode::parse_error: return "parse_error";
    }
    return "unknown";
}

std::string_view to_string(const AsyncScanOperation operation) noexcept {
    switch (operation) {
        case AsyncScanOperation::scan_exact: return "scan_exact";
        case AsyncScanOperation::strings: return "strings";
        case AsyncScanOperation::scan_pointers_to: return "scan_pointers_to";
        case AsyncScanOperation::scan_pointer_chains: return "scan_pointer_chains";
        case AsyncScanOperation::scan_first: return "scan_first";
        case AsyncScanOperation::scan_next: return "scan_next";
    }
    return "unknown";
}

std::string_view to_string(const AnalysisJobKind kind) noexcept {
    switch (kind) {
        case AnalysisJobKind::scan: return "scan";
        case AnalysisJobKind::pointer_index: return "pointer_index";
        case AnalysisJobKind::unreal_runtime: return "unreal_runtime";
    }
    return "unknown";
}

std::string_view to_string(const AnalysisJobState state) noexcept {
    switch (state) {
        case AnalysisJobState::queued: return "queued";
        case AnalysisJobState::running: return "running";
        case AnalysisJobState::completed: return "completed";
        case AnalysisJobState::cancelled: return "cancelled";
        case AnalysisJobState::failed: return "failed";
    }
    return "unknown";
}

std::string_view to_string(const AnalysisStopReason reason) noexcept {
    switch (reason) {
        case AnalysisStopReason::operation_completed: return "operation_completed";
        case AnalysisStopReason::range_exhausted: return "range_exhausted";
        case AnalysisStopReason::byte_budget: return "byte_budget";
        case AnalysisStopReason::result_limit: return "result_limit";
        case AnalysisStopReason::deadline: return "deadline";
        case AnalysisStopReason::max_depth: return "max_depth";
        case AnalysisStopReason::max_fanout: return "max_fanout";
        case AnalysisStopReason::client_cancelled: return "client_cancelled";
        case AnalysisStopReason::session_detached: return "session_detached";
        case AnalysisStopReason::server_shutdown: return "server_shutdown";
        case AnalysisStopReason::target_exited: return "target_exited";
        case AnalysisStopReason::read_error: return "read_error";
        case AnalysisStopReason::stale_snapshot: return "stale_snapshot";
        case AnalysisStopReason::unstable_snapshot: return "unstable_snapshot";
        case AnalysisStopReason::internal_error: return "internal_error";
    }
    return "unknown";
}

std::string_view to_string(const AnalysisTruncationReason reason) noexcept {
    switch (reason) {
        case AnalysisTruncationReason::byte_budget: return "byte_budget";
        case AnalysisTruncationReason::result_limit: return "result_limit";
        case AnalysisTruncationReason::deadline: return "deadline";
        case AnalysisTruncationReason::max_depth: return "max_depth";
        case AnalysisTruncationReason::max_fanout: return "max_fanout";
    }
    return "unknown";
}

std::optional<AsyncScanOperation> async_scan_operation_from_string(const std::string_view text) noexcept {
    if (text == "scan_exact") return AsyncScanOperation::scan_exact;
    if (text == "strings") return AsyncScanOperation::strings;
    if (text == "scan_pointers_to") return AsyncScanOperation::scan_pointers_to;
    if (text == "scan_pointer_chains") return AsyncScanOperation::scan_pointer_chains;
    if (text == "scan_first") return AsyncScanOperation::scan_first;
    if (text == "scan_next") return AsyncScanOperation::scan_next;
    return std::nullopt;
}

bool is_stop_reason_valid_for_operation(
    const AsyncScanOperation operation,
    const AnalysisStopReason reason
) noexcept {
    // Reasons every scan operation may reach.
    switch (reason) {
        case AnalysisStopReason::operation_completed:
        case AnalysisStopReason::range_exhausted:
        case AnalysisStopReason::byte_budget:
        case AnalysisStopReason::result_limit:
        case AnalysisStopReason::deadline:
        case AnalysisStopReason::client_cancelled:
        case AnalysisStopReason::session_detached:
        case AnalysisStopReason::server_shutdown:
        case AnalysisStopReason::target_exited:
        case AnalysisStopReason::read_error:
        case AnalysisStopReason::internal_error:
            return true;
        case AnalysisStopReason::max_depth:
        case AnalysisStopReason::max_fanout:
            // Only the BFS reverse-pointer-chain operation has depth/fanout.
            return operation == AsyncScanOperation::scan_pointer_chains;
        case AnalysisStopReason::stale_snapshot:
        case AnalysisStopReason::unstable_snapshot:
            // Reserved for pointer_index/unreal_runtime jobs (Specs 0010/0012);
            // no scan operation ever produces these.
            return false;
    }
    return false;
}

std::string_view to_string(const ScanValueType type) noexcept {
    switch (type) {
        case ScanValueType::u8: return "u8";
        case ScanValueType::u16: return "u16";
        case ScanValueType::u32: return "u32";
        case ScanValueType::u64: return "u64";
        case ScanValueType::i8: return "i8";
        case ScanValueType::i16: return "i16";
        case ScanValueType::i32: return "i32";
        case ScanValueType::i64: return "i64";
        case ScanValueType::f32: return "f32";
        case ScanValueType::f64: return "f64";
    }
    return "unknown";
}

std::size_t scan_value_size(const ScanValueType type) noexcept {
    switch (type) {
        case ScanValueType::u8:
        case ScanValueType::i8:
            return 1U;
        case ScanValueType::u16:
        case ScanValueType::i16:
            return 2U;
        case ScanValueType::u32:
        case ScanValueType::i32:
        case ScanValueType::f32:
            return 4U;
        case ScanValueType::u64:
        case ScanValueType::i64:
        case ScanValueType::f64:
            return 8U;
    }
    return 0U;
}

std::optional<ScanValueType> scan_value_type_from_string(const std::string_view text) noexcept {
    if (text == "u8") return ScanValueType::u8;
    if (text == "u16") return ScanValueType::u16;
    if (text == "u32") return ScanValueType::u32;
    if (text == "u64") return ScanValueType::u64;
    if (text == "i8") return ScanValueType::i8;
    if (text == "i16") return ScanValueType::i16;
    if (text == "i32") return ScanValueType::i32;
    if (text == "i64") return ScanValueType::i64;
    if (text == "f32") return ScanValueType::f32;
    if (text == "f64") return ScanValueType::f64;
    return std::nullopt;
}

std::optional<ScanComparison> scan_comparison_from_string(const std::string_view text) noexcept {
    if (text == "exact") return ScanComparison::exact;
    if (text == "unknown") return ScanComparison::unknown;
    if (text == "in_range") return ScanComparison::in_range;
    if (text == "changed") return ScanComparison::changed;
    if (text == "unchanged") return ScanComparison::unchanged;
    if (text == "increased") return ScanComparison::increased;
    if (text == "decreased") return ScanComparison::decreased;
    if (text == "increased_by") return ScanComparison::increased_by;
    if (text == "decreased_by") return ScanComparison::decreased_by;
    return std::nullopt;
}

std::expected<std::vector<std::byte>, std::string> encode_scan_value(
    const ScanValueType type,
    const std::string_view decimal
) {
    const auto text = trim(decimal);
    if (text.empty()) {
        return std::unexpected(std::string{"value must not be empty"});
    }
    switch (type) {
        case ScanValueType::u8:  return encode_integral<std::uint8_t>(text);
        case ScanValueType::u16: return encode_integral<std::uint16_t>(text);
        case ScanValueType::u32: return encode_integral<std::uint32_t>(text);
        case ScanValueType::u64: return encode_integral<std::uint64_t>(text);
        case ScanValueType::i8:  return encode_integral<std::int8_t>(text);
        case ScanValueType::i16: return encode_integral<std::int16_t>(text);
        case ScanValueType::i32: return encode_integral<std::int32_t>(text);
        case ScanValueType::i64: return encode_integral<std::int64_t>(text);
        case ScanValueType::f32: return encode_floating<float>(text);
        case ScanValueType::f64: return encode_floating<double>(text);
    }
    return std::unexpected(std::string{"unsupported value_type"});
}

bool RegionFilter::matches(const MemoryRegion& region) const noexcept {
    if (readable && *readable != region.readable) return false;
    if (writable && *writable != region.writable) return false;
    if (executable && *executable != region.executable) return false;
    if (private_mapping && *private_mapping != region.private_mapping) return false;
    const auto size = region.size();
    if (size < min_size) return false;
    if (max_size && size > *max_size) return false;
    if (start_address && region.end <= *start_address) return false;
    if (end_address && region.start >= *end_address) return false;
    if (!name_contains.empty() && !contains_ci(region.name, name_contains)) return false;
    return true;
}

AddressSpaceSummary summarize_address_space(const std::span<const MemoryRegion> regions) noexcept {
    AddressSpaceSummary summary{};
    summary.region_count = regions.size();
    bool first = true;
    for (const auto& region : regions) {
        const auto size = region.size();
        summary.total_bytes += size;
        if (size > summary.largest_region_bytes) summary.largest_region_bytes = size;
        if (first) {
            summary.lowest_address = region.start;
            summary.highest_address = region.end;
            first = false;
        } else {
            summary.lowest_address = std::min(summary.lowest_address, region.start);
            summary.highest_address = std::max(summary.highest_address, region.end);
        }
        if (region.readable) {
            ++summary.readable_count;
            summary.readable_bytes += size;
            summary.scannable_bytes += size;
            if (region.writable) summary.scannable_writable_bytes += size;
        }
        if (region.writable) {
            ++summary.writable_count;
            summary.writable_bytes += size;
        }
        if (region.executable) {
            ++summary.executable_count;
            summary.executable_bytes += size;
        }
        if (region.private_mapping) {
            ++summary.private_count;
            summary.private_bytes += size;
        }
    }
    return summary;
}

RegionPage filter_regions(
    const std::span<const MemoryRegion> regions,
    const RegionFilter& filter,
    const std::size_t offset,
    const std::size_t limit
) {
    RegionPage page{};
    page.offset = offset;
    std::size_t matched = 0;
    for (const auto& region : regions) {
        if (!filter.matches(region)) continue;
        const auto index = matched;
        ++matched;
        if (index < offset) continue;
        if (page.regions.size() >= limit) continue;
        page.regions.push_back(region);
    }
    page.total_matched = matched;
    page.truncated = matched > offset && matched - offset > page.regions.size();
    return page;
}

std::pair<std::uint64_t, std::size_t> eligible_scan_bytes(
    const std::span<const MemoryRegion> regions,
    const bool writable_only,
    const std::optional<Address> start_address,
    const std::optional<Address> end_address
) noexcept {
    std::uint64_t bytes = 0;
    std::size_t count = 0;
    for (const auto& region : regions) {
        if (!region.readable || (writable_only && !region.writable) || region.size() == 0U) {
            continue;
        }
        const Address scan_start = std::max(region.start, start_address.value_or(region.start));
        const Address scan_end = std::min(region.end, end_address.value_or(region.end));
        if (scan_end <= scan_start) continue;
        bytes += scan_end - scan_start;
        ++count;
    }
    return {bytes, count};
}

}  // namespace argos::domain
