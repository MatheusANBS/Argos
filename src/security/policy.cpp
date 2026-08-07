#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <limits>
#include <string_view>

namespace argos::security {
namespace {

[[nodiscard]] bool env_flag(std::string_view name) {
    const char* value = std::getenv(std::string{name}.c_str());
    if (value == nullptr) {
        return false;
    }
    const std::string_view text{value};
    return text == "1" || text == "true" || text == "TRUE" || text == "yes" || text == "YES";
}

[[nodiscard]] std::size_t env_size(
    std::string_view name,
    std::size_t fallback,
    std::size_t hard_max
) {
    const char* value = std::getenv(std::string{name}.c_str());
    if (value == nullptr) {
        return fallback;
    }
    std::uint64_t parsed = 0;
    const std::string_view text{value};
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size() || parsed == 0U) {
        return fallback;
    }
    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, hard_max));
}

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

}  // namespace

SecurityPolicy SecurityPolicy::from_environment() {
    SecurityPolicy policy;
    policy.allow_write = env_flag("ARGOS_MCP_ALLOW_WRITE");
    policy.allow_foreign_user = env_flag("ARGOS_MCP_ALLOW_FOREIGN_USER");
    policy.max_read_bytes = env_size("ARGOS_MCP_MAX_READ_BYTES", 64U * 1024U, 1024U * 1024U);
    policy.max_write_bytes = env_size("ARGOS_MCP_MAX_WRITE_BYTES", 4U * 1024U, 64U * 1024U);
    policy.max_scan_bytes = env_size(
        "ARGOS_MCP_MAX_SCAN_BYTES", 32U * 1024U * 1024U, 256U * 1024U * 1024U
    );
    policy.max_scan_results = env_size("ARGOS_MCP_MAX_SCAN_RESULTS", 256U, 4096U);
    return policy;
}

domain::Result<void> SecurityPolicy::authorize_attach(
    const bool user_acknowledged,
    const domain::AccessMode access
) const {
    if (!user_acknowledged) {
        return std::unexpected(error(
            domain::DebugErrorCode::unauthorized,
            "attach requires explicit confirmation that the target is authorized for debugging"
        ));
    }
    if (access == domain::AccessMode::read_write && !allow_write) {
        return std::unexpected(error(
            domain::DebugErrorCode::access_denied,
            "write access is disabled; set ARGOS_MCP_ALLOW_WRITE=1 before starting the server"
        ));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_read(const std::size_t size) const {
    if (size == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "read size must be positive"));
    }
    if (size > max_read_bytes) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "read size exceeds configured limit"));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_write(
    const std::size_t size,
    const std::string_view confirmation
) const {
    if (!allow_write) {
        return std::unexpected(error(domain::DebugErrorCode::access_denied, "memory writes are disabled"));
    }
    if (confirmation != "AUTHORIZED_DEBUG_WRITE") {
        return std::unexpected(error(
            domain::DebugErrorCode::unauthorized,
            "write requires confirmation value AUTHORIZED_DEBUG_WRITE"
        ));
    }
    if (size == 0U || size > max_write_bytes) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "write size exceeds configured limit"));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_scan(
    const std::size_t byte_budget,
    const std::size_t result_limit
) const {
    if (byte_budget == 0U || byte_budget > max_scan_bytes) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "scan byte budget exceeds configured limit"));
    }
    if (result_limit == 0U || result_limit > max_scan_results) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "scan result limit exceeds configured limit"));
    }
    return {};
}

}  // namespace argos::security
