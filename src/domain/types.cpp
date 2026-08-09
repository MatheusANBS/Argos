#include "argos_mcp/domain/types.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace argos::domain {

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

}  // namespace argos::domain
