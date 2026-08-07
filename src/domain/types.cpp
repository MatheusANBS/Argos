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

}  // namespace argos::domain
