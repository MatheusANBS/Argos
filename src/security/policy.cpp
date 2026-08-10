#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <string_view>
#include <system_error>

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

[[nodiscard]] std::vector<std::string> env_dir_list(std::string_view name) {
    std::vector<std::string> output;
    const char* value = std::getenv(std::string{name}.c_str());
    if (value == nullptr) {
        return output;
    }
    const std::string_view text{value};
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto separator = text.find(';', start);
        const auto end = separator == std::string_view::npos ? text.size() : separator;
        const auto piece = text.substr(start, end - start);
        if (!piece.empty()) {
            output.emplace_back(piece);
        }
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1U;
    }
    return output;
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
    policy.max_string_result_length = env_size("ARGOS_MCP_MAX_STRING_RESULT_LENGTH", 256U, 4096U);
    policy.max_scan_session_candidates = env_size(
        "ARGOS_MCP_MAX_SCAN_SESSION_CANDIDATES", 262144U, 4U * 1024U * 1024U
    );
    policy.max_scan_sessions_per_session = env_size("ARGOS_MCP_MAX_SCAN_SESSIONS_PER_SESSION", 4U, 64U);
    policy.max_pointer_chain_depth = env_size("ARGOS_MCP_MAX_POINTER_CHAIN_DEPTH", 8U, 16U);
    policy.max_pointer_chain_fanout = env_size("ARGOS_MCP_MAX_POINTER_CHAIN_FANOUT", 16U, 64U);
    policy.allow_launch = env_flag("ARGOS_MCP_ALLOW_LAUNCH");
    policy.launch_allowed_dirs = env_dir_list("ARGOS_MCP_LAUNCH_ALLOWED_DIRS");
    policy.max_launched_processes = env_size("ARGOS_MCP_MAX_LAUNCHED_PROCESSES", 4U, 64U);
    policy.max_captured_output_bytes = env_size(
        "ARGOS_MCP_MAX_CAPTURED_OUTPUT_BYTES", 1U * 1024U * 1024U, 64U * 1024U * 1024U
    );
    policy.max_async_jobs_total = env_size("ARGOS_MCP_MAX_ASYNC_JOBS_TOTAL", 64U, 1024U);
    policy.max_async_jobs_per_session = env_size("ARGOS_MCP_MAX_ASYNC_JOBS_PER_SESSION", 8U, 128U);
    policy.max_async_queue_depth = env_size("ARGOS_MCP_MAX_ASYNC_QUEUE_DEPTH", 32U, 512U);
    policy.max_async_workers = env_size("ARGOS_MCP_MAX_ASYNC_WORKERS", 2U, 16U);
    policy.max_async_job_byte_budget = env_size(
        "ARGOS_MCP_MAX_ASYNC_JOB_BYTE_BUDGET", 256U * 1024U * 1024U, 4U * 1024U * 1024U * 1024ULL
    );
    policy.max_async_job_deadline_ms = env_size("ARGOS_MCP_MAX_ASYNC_JOB_DEADLINE_MS", 600'000U, 3'600'000U);
    policy.max_async_job_result_items = env_size("ARGOS_MCP_MAX_ASYNC_JOB_RESULT_ITEMS", 4096U, 65536U);
    policy.max_async_results_retained_bytes = env_size(
        "ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES", 64U * 1024U * 1024U, 1024U * 1024U * 1024ULL
    );
    policy.async_results_ttl_ms = env_size("ARGOS_MCP_ASYNC_RESULTS_TTL_MS", 300'000U, 3'600'000U);
    policy.async_tombstone_ttl_ms = env_size("ARGOS_MCP_ASYNC_TOMBSTONE_TTL_MS", 60'000U, 600'000U);
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

domain::Result<void> SecurityPolicy::authorize_scan_session(
    const std::size_t byte_budget,
    const std::size_t result_limit
) const {
    if (byte_budget == 0U || byte_budget > max_scan_bytes) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "scan byte budget exceeds configured limit"));
    }
    if (result_limit == 0U || result_limit > max_scan_session_candidates) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "scan session candidate limit exceeds configured limit"
        ));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_pointer_chain_scan(
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const std::size_t max_depth,
    const std::size_t max_fanout
) const {
    auto scan_authorization = authorize_scan(byte_budget, result_limit);
    if (!scan_authorization) {
        return scan_authorization;
    }
    if (max_depth == 0U || max_depth > max_pointer_chain_depth) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_depth exceeds configured pointer chain depth limit"
        ));
    }
    if (max_fanout == 0U || max_fanout > max_pointer_chain_fanout) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_fanout exceeds configured pointer chain fanout limit"
        ));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_launch(
    const bool user_acknowledged,
    const std::string_view executable_path
) const {
    if (!allow_launch) {
        return std::unexpected(error(
            domain::DebugErrorCode::access_denied,
            "process launch is disabled; set ARGOS_MCP_ALLOW_LAUNCH=1 before starting the server"
        ));
    }
    if (!user_acknowledged) {
        return std::unexpected(error(
            domain::DebugErrorCode::unauthorized,
            "launch requires explicit confirmation that starting this process is authorized"
        ));
    }
    const std::filesystem::path requested{std::string{executable_path}};
    if (!requested.is_absolute()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "executable path must be absolute"));
    }
    if (!launch_allowed_dirs.empty()) {
        std::error_code canonical_error;
        const auto canonical_requested = std::filesystem::weakly_canonical(requested, canonical_error);
        if (canonical_error) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "executable path could not be resolved"
            ));
        }
        const auto& requested_native = canonical_requested.native();
        bool allowed = false;
        for (const auto& allowed_dir : launch_allowed_dirs) {
            std::error_code dir_error;
            const auto canonical_dir = std::filesystem::weakly_canonical(
                std::filesystem::path{allowed_dir}, dir_error
            );
            if (dir_error) {
                continue;
            }
            const auto& dir_native = canonical_dir.native();
            if (requested_native.size() > dir_native.size() &&
                requested_native.compare(0, dir_native.size(), dir_native) == 0 &&
                requested_native[dir_native.size()] == std::filesystem::path::preferred_separator) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return std::unexpected(error(
                domain::DebugErrorCode::access_denied, "executable path is outside ARGOS_MCP_LAUNCH_ALLOWED_DIRS"
            ));
        }
    }
    return {};
}

domain::Result<std::size_t> SecurityPolicy::clamp_async_byte_budget(
    const std::optional<std::size_t> requested
) const {
    if (requested && *requested == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "byte_budget must be positive"));
    }
    return std::min(requested.value_or(max_async_job_byte_budget), max_async_job_byte_budget);
}

domain::Result<std::size_t> SecurityPolicy::clamp_async_deadline_ms(
    const std::optional<std::size_t> requested
) const {
    if (requested && *requested == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "deadline_ms must be positive"));
    }
    return std::min(requested.value_or(max_async_job_deadline_ms), max_async_job_deadline_ms);
}

}  // namespace argos::security
