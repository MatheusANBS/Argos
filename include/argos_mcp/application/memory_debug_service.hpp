#pragma once

#include "argos_mcp/application/scan_session_manager.hpp"
#include "argos_mcp/application/session_manager.hpp"
#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/type_metadata.hpp"
#include "argos_mcp/security/policy.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stop_token>
#include <utility>
#include <vector>

namespace argos::application {

// Periodic, best-effort telemetry hook consumed by AnalysisJobManager
// (Spec 0008) to publish ScanProgress snapshots while a sweep runs in the
// background. Every synchronous scan_* method below defaults this to an
// empty std::function, which every existing call site relies on -- passing
// one never changes what a sweep reads or what matches it finds, only how
// often it reports where it is.
using ScanProgressSink = std::function<void(const domain::ScanProgress&)>;

struct ScanResult {
    std::vector<domain::ScanMatch> matches;
    std::size_t bytes_scanned{};
    bool truncated{false};
    // Best-effort, diagnostic-only cursor captured when truncated is true.
    // Never sufficient to resume correctly by itself (see Spec 0008 "Retomada
    // correta" -- a real resume needs pattern overlap/carry state this field
    // does not carry).
    std::optional<domain::Address> stopped_at;
};

struct StringMatch {
    domain::Address address{};
    std::string text;
    std::string encoding;
};

struct StringScanResult {
    std::vector<StringMatch> matches;
    std::size_t bytes_scanned{};
    bool truncated{false};
    std::optional<domain::Address> stopped_at;
};

struct BatchReadItem {
    domain::Address address{};
    std::size_t size{};
};

struct BatchReadResult {
    domain::Address address{};
    std::vector<std::byte> bytes;
    bool success{false};
    std::string error;
};

struct ScanResultsPage {
    domain::ScanSessionInfo info;
    std::size_t offset{};
    std::vector<domain::ScanMatch> matches;
    bool truncated{false};
};

struct PointerChainCandidate {
    std::string module_name;
    domain::Address module_base{};
    std::vector<std::int64_t> hop_offsets;
    domain::Address resolved_address{};
};

struct PointerChainScanResult {
    std::vector<PointerChainCandidate> candidates;
    std::size_t bytes_scanned{};
    bool truncated{false};
};

// Forward-declared only: AnalysisJobManager's header includes this one fully
// (it needs ScanResult/StringMatch/etc. and calls MemoryDebugService's scan_*
// methods), so this header must not include analysis_job_manager.hpp back --
// a std::unique_ptr to an incomplete type keeps the dependency
// one-directional. See memory_debug_service.cpp for the complete type.
class AnalysisJobManager;

class MemoryDebugService final {
public:
    MemoryDebugService(
        std::unique_ptr<domain::ProcessMemoryProvider> provider,
        security::SecurityPolicy policy,
        std::unique_ptr<domain::TypeMetadataProvider> metadata_provider = nullptr
    );
    ~MemoryDebugService();

    MemoryDebugService(const MemoryDebugService&) = delete;
    MemoryDebugService& operator=(const MemoryDebugService&) = delete;

    // Entry point for the five Spec 0008 job-control tools (scan_start,
    // job_status, job_results, job_cancel, job_release). Owned by this
    // service so its synchronous scan_* methods below can enforce "at most
    // one long scan running per session" against the same registry.
    [[nodiscard]] AnalysisJobManager& async_jobs() noexcept { return *analysis_jobs_; }

    [[nodiscard]] const security::SecurityPolicy& policy() const noexcept { return policy_; }

    [[nodiscard]] domain::Result<std::vector<domain::ProcessInfo>> list_processes(
        std::string_view filter,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<domain::SessionInfo> attach(
        domain::ProcessId pid,
        domain::AccessMode access,
        bool authorized
    );

    [[nodiscard]] domain::Result<void> detach(const domain::SessionId& id, bool terminate = false);
    [[nodiscard]] std::vector<domain::SessionInfo> list_sessions() const;

    [[nodiscard]] domain::Result<domain::SessionInfo> launch(
        const domain::LaunchSpec& spec,
        domain::AccessMode access,
        bool authorized
    );

    [[nodiscard]] domain::Result<domain::OutputChunk> read_output(
        const domain::SessionId& id,
        std::uint64_t since_cursor,
        std::size_t max_bytes
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::MemoryRegion>> regions(
        const domain::SessionId& id
    ) const;

    // Filtered/paginated view over regions(). A real target has tens of
    // thousands of regions, so the unfiltered list is not transportable.
    [[nodiscard]] domain::Result<domain::RegionPage> regions_page(
        const domain::SessionId& id,
        const domain::RegionFilter& filter,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<domain::AddressSpaceSummary> address_space_summary(
        const domain::SessionId& id
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::ModuleInfo>> modules(
        const domain::SessionId& id
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> pdb_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> unity_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> unreal_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::ReflectionMetadata> unreal_reflection(
        const domain::SessionId& id,
        std::string_view module_name,
        std::size_t max_symbols
    ) const;

    [[nodiscard]] domain::Result<domain::TypeCatalog> pdb_list_types(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view name_filter,
        std::string_view kind_filter,
        std::size_t max_symbols
    ) const;

    [[nodiscard]] domain::Result<std::vector<std::byte>> read_memory(
        const domain::SessionId& id,
        domain::Address address,
        std::size_t size
    ) const;

    [[nodiscard]] domain::Result<std::vector<BatchReadResult>> read_batch(
        const domain::SessionId& id,
        std::span<const BatchReadItem> items
    ) const;

    [[nodiscard]] domain::Result<std::size_t> write_memory(
        const domain::SessionId& id,
        domain::Address address,
        std::span<const std::byte> bytes,
        std::string_view confirmation
    );

    [[nodiscard]] domain::Result<ScanResult> scan_exact(
        const domain::SessionId& id,
        std::span<const std::byte> pattern,
        std::size_t alignment,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    [[nodiscard]] domain::Result<domain::Address> resolve_pointer_chain(
        const domain::SessionId& id,
        domain::Address base,
        std::span<const std::int64_t> offsets,
        std::size_t pointer_size
    ) const;

    [[nodiscard]] domain::Result<StringScanResult> extract_strings(
        const domain::SessionId& id,
        std::size_t min_length,
        std::string_view encoding,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    [[nodiscard]] domain::Result<ScanResult> scan_pointers_to(
        const domain::SessionId& id,
        domain::Address target,
        std::size_t pointer_size,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    [[nodiscard]] domain::Result<PointerChainScanResult> scan_pointer_chains(
        const domain::SessionId& id,
        domain::Address target,
        std::size_t pointer_size,
        std::size_t max_depth,
        std::size_t max_fanout,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    // scan_first reports coverage alongside the session because an empty
    // candidate set is ambiguous without it: the sweep may simply have run out
    // of budget before reaching the value. scan_next needs no equivalent -- it
    // always re-reads every candidate it holds, so its coverage is total.
    struct ScanFirstResult {
        domain::ScanSessionInfo info;
        domain::ScanCoverage coverage;
    };

    [[nodiscard]] domain::Result<ScanFirstResult> scan_first(
        const domain::SessionId& id,
        domain::ScanValueType value_type,
        domain::ScanComparison comparison,
        std::optional<std::vector<std::byte>> value,
        std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> scan_next(
        const domain::ScanSessionId& scan_id,
        domain::ScanComparison comparison,
        std::optional<std::vector<std::byte>> value,
        std::optional<std::vector<std::byte>> delta,
        std::stop_token cancellation = {},
        ScanProgressSink progress_sink = {},
        // Internal use only: AnalysisJobManager's worker sets this so it can
        // call the same engine it is itself running as an async job without
        // rejecting itself as "another long scan already active" (Spec 0008
        // -- see MemoryDebugService::reject_if_analysis_job_active). Every
        // protocol-layer (synchronous tool) call site leaves this false.
        bool bypass_active_job_guard = false
    ) const;

    [[nodiscard]] domain::Result<domain::ScanValueType> scan_value_type(
        const domain::ScanSessionId& scan_id
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::ScanMatch>> scan_results(
        const domain::ScanSessionId& scan_id,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<ScanResultsPage> scan_results_page(
        const domain::ScanSessionId& scan_id,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<void> scan_reset(const domain::ScanSessionId& scan_id);

private:
    [[nodiscard]] domain::Result<std::string> module_path(
        const domain::SessionId& id,
        std::string_view module_name
    ) const;

    [[nodiscard]] domain::Result<ScanResult> scan_pattern(
        const domain::SessionId& id,
        std::span<const std::byte> pattern,
        std::size_t alignment,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address,
        std::optional<domain::Address> end_address,
        std::stop_token cancellation,
        const ScanProgressSink& progress_sink,
        bool bypass_active_job_guard
    ) const;

    // Rejected with invalid_state/analysis_job_active when a background job
    // already owns the one-long-scan-per-session slot (Spec 0008,
    // "Compatibilidade com tools síncronas e eras MCP").
    [[nodiscard]] domain::Result<void> reject_if_analysis_job_active(const domain::SessionId& id) const;

    std::unique_ptr<domain::ProcessMemoryProvider> provider_;
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider_;
    security::SecurityPolicy policy_;
    SessionManager sessions_;
    mutable ScanSessionManager scan_sessions_;
    // Constructed last so it observes fully-initialized sessions_/scan_sessions_/
    // policy_ before any worker thread can touch them (workers only run once a
    // job is submitted, strictly after this constructor returns).
    std::unique_ptr<AnalysisJobManager> analysis_jobs_;
};

}  // namespace argos::application
