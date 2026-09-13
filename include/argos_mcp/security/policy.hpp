#pragma once

#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/disassembly.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace argos::security {

// Operator-owned mapping from a stable module fingerprint to roots for one
// supported Unreal layout. Clients can select an enabled layout, but they
// cannot submit or persist a build fingerprint through MCP.
struct UnrealBuildProfile {
    std::string build_id;
    std::string profile_id;
    std::string module_name;
    std::uint64_t module_size{};
    std::uint64_t signature_rva{};
    std::vector<std::byte> signature;
    std::uint64_t gu_object_array_rva{};
    std::uint64_t fname_pool_rva{};
};

// Parses the bounded server-side format documented for
// ARGOS_MCP_UNREAL_BUILD_PROFILES. Exposed for deterministic configuration
// tests; it performs no process I/O.
[[nodiscard]] std::expected<std::vector<UnrealBuildProfile>, std::string>
parse_unreal_build_profiles(std::string_view text);

// Operator-owned location of one engine build's type table. Like the Unreal
// build profile, it is server-side only: a client can neither submit nor read
// it, and the layout family it names must be one the server already knows.
struct SantaMonicaBuildProfile {
    std::string build_id;
    std::string profile_id;
    std::string module_name;
    std::uint64_t module_size{};
    std::vector<std::byte> module_digest;
    std::uint64_t table_begin_rva{};
    std::uint64_t table_end_rva{};
    std::uint64_t names_begin_rva{};
    std::uint64_t names_end_rva{};
    std::uint64_t attribute_begin_rva{};
    std::uint64_t attribute_end_rva{};
    std::uint64_t enum_begin_rva{};
    std::uint64_t enum_end_rva{};
    std::uint64_t sli_begin_rva{};
    std::uint64_t sli_end_rva{};
    // RVA of the code-addressed global that leads to the player's resource
    // store (ADR-0028). Zero means the profile does not publish resources.
    std::uint64_t resources_root_rva{};
};

// Parses the bounded server-side format documented for
// ARGOS_MCP_SANTAMONICA_BUILD_PROFILES. Pure: no process or file I/O.
[[nodiscard]] std::expected<std::vector<SantaMonicaBuildProfile>, std::string>
parse_santamonica_build_profiles(std::string_view text);

struct SecurityPolicy {
    // Default-on by the owner's explicit direction; a read-write session and
    // the per-call confirmation phrase are still required for every write.
    bool allow_write{true};
    bool allow_foreign_user{false};
    std::size_t max_read_bytes{64U * 1024U};
    std::size_t max_write_bytes{4U * 1024U};
    std::size_t max_scan_bytes{32U * 1024U * 1024U};
    std::size_t max_scan_results{256U};
    std::size_t max_string_result_length{256U};
    std::size_t max_scan_session_candidates{262144U};
    std::size_t max_scan_sessions_per_session{4U};
    std::size_t max_pointer_chain_depth{8U};
    std::size_t max_pointer_chain_fanout{16U};
    bool allow_launch{false};
    std::vector<std::string> launch_allowed_dirs;
    std::size_t max_launched_processes{4U};
    std::size_t max_captured_output_bytes{1U * 1024U * 1024U};

    // ADR-0021: opt-in, first-party debug bridge. The server never treats a
    // caller-supplied DLL as approved without both this gate and a canonical
    // allowlist match.
    bool allow_debug_bridge_injection{false};
    std::vector<std::string> debug_bridge_allowed_paths;

    // Spec 0008 -- async scan jobs (AnalysisJobManager). Every limit here is a
    // hard cap the client cannot raise: a requested execution limit is only
    // ever reduced to fit inside these, never extended.
    std::size_t max_async_jobs_total{64U};
    std::size_t max_async_jobs_per_session{8U};
    std::size_t max_async_queue_depth{32U};
    std::size_t max_async_workers{2U};
    std::size_t max_async_job_byte_budget{256U * 1024U * 1024U};
    std::size_t max_async_job_deadline_ms{600'000U};
    std::size_t max_async_job_result_items{4096U};
    std::size_t max_async_results_retained_bytes{64U * 1024U * 1024U};
    std::size_t async_results_ttl_ms{300'000U};
    std::size_t async_tombstone_ttl_ms{60'000U};

    // Ceilings for memory_debug_inspect_address. The operator can only lower
    // them: the domain hard caps remain the upper bound.
    std::uint64_t max_inspect_lookbehind_bytes{domain::inspection_max_lookbehind_bytes};
    std::size_t max_inspect_vtable_probes{domain::inspection_max_vtable_probes};
    std::size_t max_inspect_vtable_entries{domain::inspection_max_vtable_entries};
    std::size_t max_inspect_object_candidates{domain::inspection_max_object_candidates};

    // Ceilings for the read-only disassembler (ADR-0029). The operator can only
    // lower them; the domain hard caps remain the upper bound.
    std::size_t max_disassemble_instructions{domain::disassemble_max_instructions};
    std::uint64_t max_code_ref_byte_budget{domain::code_ref_max_byte_budget};
    std::size_t max_code_ref_results{domain::code_ref_max_results};

    // Unreal runtime reflection is gated off by default, and automatic root
    // discovery needs a second, independent gate. A request can never turn
    // either on; only server configuration can.
    bool enable_unreal_runtime{false};
    bool enable_unreal_auto_discovery{false};
    std::vector<std::string> unreal_profile_allowlist;
    std::vector<UnrealBuildProfile> unreal_build_profiles;
    bool unreal_build_profiles_valid{true};
    std::size_t max_unreal_contexts_per_session{2U};
    std::size_t max_unreal_contexts_total{8U};
    std::size_t max_unreal_slots_visited{1000000U};
    std::size_t max_unreal_objects_stored{10000U};
    std::size_t max_unreal_classes_stored{20000U};
    std::size_t max_unreal_properties_per_type{1024U};
    std::size_t max_unreal_super_depth{64U};
    std::size_t max_unreal_property_nodes{4096U};
    std::size_t max_unreal_name_bytes{1024U};
    std::size_t max_unreal_page_retries{2U};
    std::size_t max_unreal_root_candidates{64U};
    std::size_t max_unreal_context_bytes{64U * 1024U * 1024U};
    std::size_t unreal_context_ttl_seconds{900U};

    // Santa Monica/Kinetica runtime (Spec 0014, ADRs 0023-0025). Gated off by
    // default. The controlled peer is a server-side path chosen by the
    // operator: a request can never name an executable or raise a limit.
    bool enable_santamonica_runtime{false};
    std::string santamonica_peer_path;
    std::vector<SantaMonicaBuildProfile> santamonica_build_profiles;
    bool santamonica_build_profiles_valid{true};
    std::size_t max_santamonica_contexts_per_session{1U};
    std::size_t max_santamonica_contexts_total{2U};
    std::size_t max_santamonica_records{100000U};
    std::size_t max_santamonica_string_bytes{4096U};
    std::size_t max_santamonica_retained_bytes{32U * 1024U * 1024U};
    std::size_t max_santamonica_fields_per_type{1024U};
    std::size_t max_santamonica_values_per_enum{1024U};
    std::size_t max_santamonica_session_ms{10000U};
    std::size_t santamonica_context_ttl_seconds{900U};

    [[nodiscard]] static SecurityPolicy from_environment();

    [[nodiscard]] domain::Result<void> authorize_attach(
        bool user_acknowledged,
        domain::AccessMode access
    ) const;

    [[nodiscard]] domain::Result<void> authorize_read(std::size_t size) const;

    [[nodiscard]] domain::Result<void> authorize_write(
        std::size_t size,
        std::string_view confirmation
    ) const;

    [[nodiscard]] domain::Result<void> authorize_scan(
        std::size_t byte_budget,
        std::size_t result_limit
    ) const;

    [[nodiscard]] domain::Result<void> authorize_scan_session(
        std::size_t byte_budget,
        std::size_t result_limit
    ) const;

    [[nodiscard]] domain::Result<void> authorize_pointer_chain_scan(
        std::size_t byte_budget,
        std::size_t result_limit,
        std::size_t max_depth,
        std::size_t max_fanout
    ) const;

    [[nodiscard]] domain::Result<void> authorize_disassemble(
        std::size_t instruction_count
    ) const;

    [[nodiscard]] domain::Result<void> authorize_code_references(
        std::uint64_t byte_budget,
        std::size_t result_limit
    ) const;

    [[nodiscard]] domain::Result<void> authorize_launch(
        bool user_acknowledged,
        std::string_view executable_path
    ) const;

    [[nodiscard]] domain::Result<void> authorize_debug_bridge_injection(
        bool user_acknowledged,
        std::string_view bridge_path
    ) const;

    // Clamps a client-requested async job byte_budget/deadline down to the
    // server hard caps (never up) and rejects a zero/absent value. Does not
    // check queue/job-count backpressure -- AnalysisJobManager owns that
    // because it requires the current registry state, not just the policy.
    [[nodiscard]] domain::Result<std::size_t> clamp_async_byte_budget(
        std::optional<std::size_t> requested
    ) const;

    [[nodiscard]] domain::Result<std::size_t> clamp_async_deadline_ms(
        std::optional<std::size_t> requested
    ) const;

    // Applied before the first process read, so an oversized request never
    // allocates a buffer or touches the target.
    [[nodiscard]] domain::Result<void> authorize_inspection(
        const domain::InspectionLimits& limits
    ) const;

    [[nodiscard]] domain::Result<void> authorize_unreal_runtime(std::string_view profile_id) const;
    [[nodiscard]] domain::Result<void> authorize_unreal_auto_discovery() const;

    // Validates the gate and the operator-configured controlled peer. It never
    // accepts a path, endpoint or limit coming from an MCP request.
    [[nodiscard]] domain::Result<void> authorize_santamonica_runtime() const;

    // Checked only where the controlled peer is actually launched, so a server
    // configured with a build profile alone never needs a peer on disk.
    [[nodiscard]] domain::Result<void> authorize_santamonica_peer() const;
};

}  // namespace argos::security
