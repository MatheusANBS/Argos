#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>

namespace argos::security {
namespace {

[[nodiscard]] std::optional<std::string_view> env_text(const std::string_view name) {
    const char* value = std::getenv(std::string{name}.c_str());
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string_view{value};
}

[[nodiscard]] bool env_flag(std::string_view name) {
    const auto value = env_text(name);
    if (!value) return false;
    const std::string_view text{*value};
    return text == "1" || text == "true" || text == "TRUE" || text == "yes" || text == "YES";
}

[[nodiscard]] std::size_t env_size(
    std::string_view name,
    std::size_t fallback,
    std::size_t hard_max
) {
    const auto value = env_text(name);
    if (!value) return fallback;
    std::uint64_t parsed = 0;
    const std::string_view text{*value};
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (ec != std::errc{} || ptr != text.data() + text.size() || parsed == 0U) {
        return fallback;
    }
    return static_cast<std::size_t>(std::min<std::uint64_t>(parsed, hard_max));
}

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

// Semicolon-separated list, used for both launch directories and the Unreal
// profile allowlist. Empty entries are dropped so a trailing separator does not
// become an entry that matches nothing -- or everything.
[[nodiscard]] std::vector<std::string> env_string_list(std::string_view name) {
    std::vector<std::string> output;
    const auto value = env_text(name);
    if (!value) return output;
    const std::string_view text{*value};
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

[[nodiscard]] std::optional<std::uint64_t> parse_u64(
    std::string_view text,
    const int base
) noexcept {
    if (base == 16 && text.starts_with("0x")) {
        text.remove_prefix(2U);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0U;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (ec != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

[[nodiscard]] std::optional<unsigned int> hex_digit(const char value) noexcept {
    if (value >= '0' && value <= '9') return static_cast<unsigned int>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned int>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<unsigned int>(value - 'A' + 10);
    return std::nullopt;
}

[[nodiscard]] std::optional<std::vector<std::byte>> parse_signature(const std::string_view text) {
    constexpr std::size_t min_signature_bytes = 8U;
    constexpr std::size_t max_signature_bytes = 64U;
    if (text.size() % 2U != 0U ||
        text.size() < min_signature_bytes * 2U ||
        text.size() > max_signature_bytes * 2U) {
        return std::nullopt;
    }
    std::vector<std::byte> bytes;
    bytes.reserve(text.size() / 2U);
    for (std::size_t index = 0; index < text.size(); index += 2U) {
        const auto high = hex_digit(text[index]);
        const auto low = hex_digit(text[index + 1U]);
        if (!high || !low) {
            return std::nullopt;
        }
        bytes.push_back(static_cast<std::byte>((*high << 4U) | *low));
    }
    return bytes;
}

[[nodiscard]] bool safe_identifier(const std::string_view text, const std::size_t max_size) noexcept {
    if (text.empty() || text.size() > max_size) return false;
    return std::ranges::all_of(text, [](const char value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.';
    });
}

[[nodiscard]] bool safe_module_name(const std::string_view text) noexcept {
    return safe_identifier(text, 260U) && !text.contains('/') && !text.contains('\\');
}

}  // namespace

std::expected<std::vector<UnrealBuildProfile>, std::string>
parse_unreal_build_profiles(const std::string_view text) {
    constexpr std::size_t field_count = 8U;
    constexpr std::size_t max_profiles = 64U;
    constexpr std::size_t max_config_bytes = 32U * 1024U;
    if (text.empty()) return std::vector<UnrealBuildProfile>{};
    if (text.size() > max_config_bytes) {
        return std::unexpected("build profile configuration exceeds the size limit");
    }

    std::vector<UnrealBuildProfile> profiles;
    std::unordered_set<std::string> build_ids;
    std::size_t record_start = 0U;
    while (record_start <= text.size()) {
        if (profiles.size() >= max_profiles) {
            return std::unexpected("too many Unreal build profiles");
        }
        const auto separator = text.find(';', record_start);
        const auto record_end = separator == std::string_view::npos ? text.size() : separator;
        const auto record = text.substr(record_start, record_end - record_start);
        if (record.empty()) {
            return std::unexpected("Unreal build profile contains an empty record");
        }

        std::array<std::string_view, field_count> fields{};
        std::size_t field_start = 0U;
        for (std::size_t field = 0U; field < field_count; ++field) {
            const auto field_separator = record.find('|', field_start);
            if (field + 1U == field_count) {
                if (field_separator != std::string_view::npos) {
                    return std::unexpected("Unreal build profile has too many fields");
                }
                fields[field] = record.substr(field_start);
            } else {
                if (field_separator == std::string_view::npos) {
                    return std::unexpected("Unreal build profile has too few fields");
                }
                fields[field] = record.substr(field_start, field_separator - field_start);
                field_start = field_separator + 1U;
            }
        }

        const auto module_size = parse_u64(fields[3], 10);
        const auto signature_rva = parse_u64(fields[4], 16);
        auto signature = parse_signature(fields[5]);
        const auto object_array_rva = parse_u64(fields[6], 16);
        const auto name_pool_rva = parse_u64(fields[7], 16);
        if (!safe_identifier(fields[0], 128U) || !safe_identifier(fields[1], 128U) ||
            !safe_module_name(fields[2]) || !module_size || *module_size == 0U ||
            !signature_rva || !signature || !object_array_rva || !name_pool_rva) {
            return std::unexpected("Unreal build profile contains an invalid field");
        }
        const auto signature_end = domain::checked_add(*signature_rva, signature->size());
        if (!signature_end || *signature_end > *module_size ||
            *object_array_rva >= *module_size || *name_pool_rva >= *module_size) {
            return std::unexpected("Unreal build profile RVA is outside the module");
        }
        if (!build_ids.emplace(fields[0]).second) {
            return std::unexpected("Unreal build profile id is duplicated");
        }

        profiles.push_back(UnrealBuildProfile{
            std::string{fields[0]}, std::string{fields[1]}, std::string{fields[2]},
            *module_size, *signature_rva, std::move(*signature),
            *object_array_rva, *name_pool_rva
        });
        if (separator == std::string_view::npos) break;
        record_start = separator + 1U;
    }
    return profiles;
}

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
    policy.launch_allowed_dirs = env_string_list("ARGOS_MCP_LAUNCH_ALLOWED_DIRS");
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
    policy.max_inspect_lookbehind_bytes = env_size(
        "ARGOS_MCP_MAX_INSPECT_LOOKBEHIND_BYTES",
        static_cast<std::size_t>(domain::inspection_max_lookbehind_bytes),
        static_cast<std::size_t>(domain::inspection_max_lookbehind_bytes)
    );
    policy.max_inspect_vtable_probes = env_size(
        "ARGOS_MCP_MAX_INSPECT_VTABLE_PROBES",
        domain::inspection_max_vtable_probes,
        domain::inspection_max_vtable_probes
    );
    policy.max_inspect_vtable_entries = env_size(
        "ARGOS_MCP_MAX_INSPECT_VTABLE_ENTRIES",
        domain::inspection_max_vtable_entries,
        domain::inspection_max_vtable_entries
    );
    policy.max_inspect_object_candidates = env_size(
        "ARGOS_MCP_MAX_INSPECT_OBJECT_CANDIDATES",
        domain::inspection_max_object_candidates,
        domain::inspection_max_object_candidates
    );
    policy.enable_unreal_runtime = env_flag("ARGOS_MCP_ENABLE_UNREAL_RUNTIME");
    policy.enable_unreal_auto_discovery = env_flag("ARGOS_MCP_ENABLE_UNREAL_AUTO_DISCOVERY");
    policy.unreal_profile_allowlist = env_string_list("ARGOS_MCP_UNREAL_PROFILES");
    if (const auto configured = env_text("ARGOS_MCP_UNREAL_BUILD_PROFILES")) {
        auto profiles = parse_unreal_build_profiles(*configured);
        policy.unreal_build_profiles_valid = profiles.has_value();
        if (profiles) {
            policy.unreal_build_profiles = std::move(*profiles);
        }
    }
    policy.max_unreal_contexts_per_session = env_size("ARGOS_MCP_MAX_UNREAL_CONTEXTS_PER_SESSION", 2U, 16U);
    policy.max_unreal_contexts_total = env_size("ARGOS_MCP_MAX_UNREAL_CONTEXTS", 8U, 64U);
    policy.max_unreal_slots_visited = env_size("ARGOS_MCP_MAX_UNREAL_SLOTS", 1000000U, 8000000U);
    policy.max_unreal_objects_stored = env_size("ARGOS_MCP_MAX_UNREAL_OBJECTS", 10000U, 100000U);
    policy.max_unreal_classes_stored = env_size("ARGOS_MCP_MAX_UNREAL_CLASSES", 20000U, 200000U);
    policy.max_unreal_properties_per_type = env_size("ARGOS_MCP_MAX_UNREAL_PROPERTIES", 1024U, 8192U);
    policy.max_unreal_super_depth = env_size("ARGOS_MCP_MAX_UNREAL_SUPER_DEPTH", 64U, 256U);
    policy.max_unreal_property_nodes = env_size("ARGOS_MCP_MAX_UNREAL_PROPERTY_NODES", 4096U, 32768U);
    policy.max_unreal_name_bytes = env_size("ARGOS_MCP_MAX_UNREAL_NAME_BYTES", 1024U, 4096U);
    policy.max_unreal_page_retries = env_size("ARGOS_MCP_MAX_UNREAL_PAGE_RETRIES", 2U, 8U);
    policy.max_unreal_root_candidates = env_size("ARGOS_MCP_MAX_UNREAL_ROOT_CANDIDATES", 64U, 256U);
    policy.max_unreal_context_bytes = env_size(
        "ARGOS_MCP_MAX_UNREAL_CONTEXT_BYTES", 64U * 1024U * 1024U, 256U * 1024U * 1024U
    );
    policy.unreal_context_ttl_seconds = env_size("ARGOS_MCP_UNREAL_CONTEXT_TTL_SECONDS", 900U, 3600U);
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

domain::Result<void> SecurityPolicy::authorize_inspection(const domain::InspectionLimits& limits) const {
    // Domain caps first: they are the invariant. The configured ceilings can
    // only narrow them further.
    auto structural = limits.validate();
    if (!structural) {
        return structural;
    }
    if (limits.lookbehind_bytes > max_inspect_lookbehind_bytes) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "lookbehind_bytes exceeds the configured limit"
        ));
    }
    if (limits.max_vtable_probes > max_inspect_vtable_probes) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "vtable probe count exceeds the configured limit"
        ));
    }
    if (limits.vtable_entries > max_inspect_vtable_entries) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "vtable_entries exceeds the configured limit"
        ));
    }
    if (limits.max_candidates > max_inspect_object_candidates) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_object_candidates exceeds the configured limit"
        ));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_unreal_runtime(const std::string_view profile_id) const {
    if (!enable_unreal_runtime) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported,
            "unreal runtime reflection is disabled; set ARGOS_MCP_ENABLE_UNREAL_RUNTIME=1 before starting the server"
        ));
    }
    if (profile_id.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "profile_id is required"));
    }
    // An empty allowlist means "no profile enabled", not "every profile
    // enabled": the operator has to name what a client may select.
    const auto allowed = std::ranges::any_of(
        unreal_profile_allowlist,
        [profile_id](const std::string& entry) { return entry == profile_id; }
    );
    if (!allowed) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported, "profile_id is not in ARGOS_MCP_UNREAL_PROFILES"
        ));
    }
    return {};
}

domain::Result<void> SecurityPolicy::authorize_unreal_auto_discovery() const {
    if (!enable_unreal_runtime) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported, "unreal runtime reflection is disabled"
        ));
    }
    if (!enable_unreal_auto_discovery) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported,
            "unreal automatic root discovery is disabled; set ARGOS_MCP_ENABLE_UNREAL_AUTO_DISCOVERY=1"
        ));
    }
    return {};
}

}  // namespace argos::security
