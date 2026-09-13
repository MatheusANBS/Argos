#pragma once

#include "argos_mcp/application/scan_session_manager.hpp"
#include "argos_mcp/application/session_manager.hpp"
#include "argos_mcp/application/santa_monica_runtime_manager.hpp"
#include "argos_mcp/application/unreal_runtime_manager.hpp"
#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/disassembly.hpp"
#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/type_metadata.hpp"
#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/domain/unreal_runtime.hpp"
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

// --- memory_debug_inspect_address ------------------------------------------

// `index` is declared here because the contract distinguishes the three modes,
// but it stays unavailable until the persistent pointer index of Spec 0010
// exists: asking for it returns `unsupported` rather than silently downgrading
// to a live scan with a different cost and coverage.
enum class ReferenceMode { none, index, live_scan };

struct ReferenceQuery {
    ReferenceMode mode{ReferenceMode::none};
    std::size_t byte_budget{};
    std::size_t result_limit{};
    bool writable_only{false};
    std::optional<domain::Address> start_address;
    std::optional<domain::Address> end_address;
    std::string resume_token;
};

struct ReferenceBudget {
    std::uint64_t byte_budget{};
    std::size_t result_limit{};
    std::string source;
};

// Why a slice stopped early. Empty means the slice ended because it ran out of
// address space to sweep, which is the only case where an empty match list is
// conclusive.
enum class ReferenceTruncation { byte_budget_exhausted, result_limit_reached, region_read_failed };

[[nodiscard]] std::string_view to_string(ReferenceTruncation reason) noexcept;

struct ReferenceReport {
    ReferenceMode mode{ReferenceMode::none};
    ReferenceBudget budget;
    std::vector<domain::Address> matches;
    domain::ScanCoverage coverage;
    std::optional<std::string> resume_token;
    // Diagnostic only: continuation always goes through resume_token, which is
    // bound to the query. A raw address would lose that binding.
    std::optional<domain::Address> next_start_address;
    std::vector<ReferenceTruncation> truncation_reasons;
};

struct InspectedModule {
    std::string name;
    domain::Address base{};
    std::uint64_t rva{};
};

struct InspectedVtable {
    domain::Address address{};
    std::optional<InspectedModule> module;
};

struct InspectedCandidate {
    domain::Address object_address{};
    std::uint64_t field_offset{};
    InspectedVtable vtable;
    domain::DerivedConfidence confidence{};
    std::vector<domain::DerivedEvidence> evidence;
    std::vector<domain::ProvenanceKind> provenance;
};

struct InspectionAnalysisReport {
    std::uint64_t lookbehind_bytes_requested{};
    std::uint64_t lookbehind_bytes_read{};
    std::size_t vtable_probes_attempted{};
    std::size_t vtable_probes_complete{};
    bool complete{true};
    std::vector<domain::InspectionLimitation> limitations;
};

struct AddressInspection {
    domain::Address address{};
    domain::TargetPointerWidth pointer_width{};
    std::uint64_t sampled_at_ms{};
    std::optional<domain::MemoryRegion> region;
    std::optional<InspectedModule> module;
    InspectionAnalysisReport analysis;
    std::vector<InspectedCandidate> candidates;
    std::size_t candidates_total{};
    bool candidates_truncated{false};
    std::optional<ReferenceReport> references;
};

struct AddressInspectionRequest {
    domain::Address address{};
    domain::TargetPointerWidth pointer_width{domain::TargetPointerWidth::x64};
    domain::InspectionLimits limits;
    ReferenceQuery references;
};

// --- memory_debug_disassemble / find_code_references (ADR-0029) -------------

struct DisassembleRequest {
    domain::Address address{};
    domain::TargetPointerWidth pointer_width{domain::TargetPointerWidth::x64};
    std::size_t instruction_count{};
};

struct DisassembleResult {
    std::vector<domain::DecodedInstruction> instructions;
    // True when decoding stopped before instruction_count because the next bytes
    // could not be read or did not form a valid instruction -- so an empty or
    // short list is not mistaken for "the function is this short".
    bool stopped_early{false};
    std::uint64_t bytes_read{};
};

struct CodeReferenceRequest {
    domain::Address target{};
    // Matches a reference whose resolved target lies in [target, target+window].
    // Zero means an exact match, which is the common case for a single slot.
    std::uint64_t window{};
    domain::TargetPointerWidth pointer_width{domain::TargetPointerWidth::x64};
    // Optional ways to bound the sweep. A module name restricts it to that
    // module's image; an explicit [start,end) overrides. Absent means every
    // executable region.
    std::optional<std::string> module;
    std::optional<domain::Address> start_address;
    std::optional<domain::Address> end_address;
    std::uint64_t byte_budget{};
    std::size_t result_limit{};
};

struct CodeReferenceResult {
    std::vector<domain::CodeReferenceHit> hits;
    domain::ScanCoverage coverage;
};

// --- memory_debug_unreal_runtime_* -----------------------------------------

// Attached to every runtime-derived response, in success and in partial
// results. It never claims the PDB path's confidence, and it keeps the two
// sources comparable instead of merging them.
struct UnrealProvenance {
    std::string source{"unreal:runtime-reflection"};
    std::string profile_id;
    std::string process_fingerprint;
    domain::RootOrigin root_origin{domain::RootOrigin::explicit_address};
    domain::RuntimeConfidence confidence{domain::RuntimeConfidence::low};
    std::vector<domain::RuntimeEvidence> evidence;
    std::vector<domain::RuntimeInvariant> failed_invariants;
    domain::SnapshotStatus snapshot_status{domain::SnapshotStatus::stable};
};

struct UnrealDiscoverRequest {
    std::string module_name;
    std::string profile_id;
    domain::DiscoveryMode mode{domain::DiscoveryMode::explicit_roots};
    std::optional<std::uint64_t> gu_object_array_rva;
    std::optional<std::uint64_t> fname_pool_rva;
    std::optional<domain::Address> gu_object_array_address;
    std::optional<domain::Address> fname_pool_address;
};

struct UnrealDiscoverResult {
    std::string runtime_id;
    std::string module_name;
    domain::UnrealRuntimeRoots roots;
    UnrealProvenance provenance;
    std::size_t class_count{};
    bool classes_truncated{false};
    domain::UnrealRuntimeProgress progress;
    std::uint64_t expires_in_ms{};
};

struct UnrealClassPage {
    std::vector<domain::UnrealClassSummary> classes;
    std::size_t total_matched{};
    std::size_t offset{};
    std::optional<std::string> next_page_token;
    UnrealProvenance provenance;
};

struct UnrealTypeResult {
    domain::UnrealRuntimeType type;
    UnrealProvenance provenance;
};

struct UnrealObjectsPage {
    std::vector<domain::UnrealObjectSummary> objects;
    domain::UnrealRuntimeProgress progress;
    bool truncated{false};
    std::optional<std::string> next_page_token;
    UnrealProvenance provenance;
};

// Santa Monica/Kinetica reflection (Spec 0014). Every result describes a
// snapshot already admitted by the domain: no query parses a target again.
struct SantaMonicaDiscoverResult {
    std::string runtime_id;
    // Where the snapshot came from: a profiled build read natively, or the
    // controlled synthetic peer. Reported so a client never mistakes one for
    // the other.
    std::string source;
    std::string profile_id;
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t generation{};
    std::string consistency;
    bool coverage_complete{false};
    std::size_t type_count{};
    std::size_t field_count{};
    std::size_t enum_count{};
    std::size_t enum_value_count{};
    std::size_t function_count{};
    std::size_t retained_bytes{};
    std::uint64_t expires_in_ms{};
    // True when the build profile also locates the player's resource store.
    bool resources_published{false};
};

struct SantaMonicaTypePage {
    std::vector<domain::santamonica::TypeRecord> types;
    std::size_t total_matched{};
    std::size_t offset{};
    std::optional<std::string> next_page_token;
    std::uint64_t generation{};
};

struct SantaMonicaInventoryPage {
    std::vector<domain::santamonica::ResourceEntry> entries;
    std::uint64_t generation{};
    std::size_t total_matched{};
    std::size_t offset{};
    std::size_t resource_count{};
    std::optional<std::string> next_page_token;
};

// Outcome of a direct balance write. It never claims an engine transaction: the
// quantity slot was written and read back, and no game code ran.
struct SantaMonicaResourceWrite {
    domain::santamonica::ResourceEntry resource;  // As located, before the write.
    std::int32_t previous{};
    std::int32_t requested{};
    std::int32_t observed{};  // Quantity read back after the write.
    bool verified{false};
};

struct SantaMonicaTypeResult {
    domain::santamonica::TypeRecord type;
    std::vector<domain::santamonica::FieldRecord> fields;
    std::vector<domain::santamonica::TypeKey> inheritance;
    bool fields_truncated{false};
    std::uint64_t generation{};
};

struct SantaMonicaEnumEntry {
    domain::santamonica::EnumRecord declaration;
    std::vector<domain::santamonica::EnumValueRecord> values;
    bool values_truncated{false};
};

struct SantaMonicaEnumPage {
    std::vector<SantaMonicaEnumEntry> enums;
    std::size_t total_matched{};
    std::size_t offset{};
    std::optional<std::string> next_page_token;
    std::uint64_t generation{};
};

struct SantaMonicaFunctionPage {
    std::vector<domain::santamonica::SliFunctionRecord> functions;
    std::size_t total_matched{};
    std::size_t offset{};
    std::optional<std::string> next_page_token;
    std::uint64_t generation{};
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

    [[nodiscard]] domain::Result<domain::InjectedDebugBridge> inject_debug_bridge(
        const domain::SessionId& id,
        std::string_view bridge_path,
        bool authorized
    );

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

    // Read-only x86/x64 disassembly (ADR-0029): decode instruction_count
    // instructions from `address`, resolving relative branches and RIP-relative
    // operands to absolute targets. Does not write, hook or execute.
    [[nodiscard]] domain::Result<DisassembleResult> disassemble(
        const domain::SessionId& id,
        const DisassembleRequest& request,
        std::stop_token cancellation
    ) const;

    // Linear sweep over executable memory returning the instructions whose
    // resolved target lands in the requested window. Evidence of a reference,
    // not proof of a function boundary (ADR-0029).
    [[nodiscard]] domain::Result<CodeReferenceResult> find_code_references(
        const domain::SessionId& id,
        const CodeReferenceRequest& request,
        std::stop_token cancellation
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

    // Correlates one address with its region, module, probable object/vtable
    // shapes and -- only when asked, and only within an explicit budget --
    // references to it. Read-only, and every classification stays probable.
    [[nodiscard]] domain::Result<AddressInspection> inspect_address(
        const domain::SessionId& id,
        const AddressInspectionRequest& request,
        std::stop_token cancellation = {}
    ) const;

    // Validates the engine roots against an explicitly enabled layout profile
    // and publishes a runtime context plus its class catalog. Read-only: no
    // function in the target is ever called.
    [[nodiscard]] domain::Result<SantaMonicaDiscoverResult> santamonica_runtime_discover(
        const domain::SessionId& id,
        std::stop_token cancellation = {}
    );

    [[nodiscard]] domain::Result<SantaMonicaTypePage> santamonica_runtime_types(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::string_view name_contains,
        std::size_t limit,
        std::string_view page_token
    ) const;

    [[nodiscard]] domain::Result<SantaMonicaTypeResult> santamonica_runtime_type(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::uint64_t type_id,
        bool include_inherited,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<SantaMonicaEnumPage> santamonica_runtime_enums(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::string_view name_contains,
        std::size_t limit,
        std::size_t max_values,
        std::string_view page_token
    ) const;

    [[nodiscard]] domain::Result<SantaMonicaFunctionPage> santamonica_runtime_sli_functions(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::string_view name_contains,
        std::size_t limit,
        std::string_view page_token
    ) const;

    [[nodiscard]] domain::Result<void> santamonica_runtime_release(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id
    );

    // Pages through the player's resource balances. The snapshot is read on
    // first use or on refresh and cached per context; refresh restarts paging.
    [[nodiscard]] domain::Result<SantaMonicaInventoryPage> santamonica_runtime_resources(
        const domain::SessionId& id, const domain::RuntimeId& runtime_id,
        std::string_view name_contains, std::size_t limit, std::string_view page_token,
        bool acquired_only, bool refresh, std::stop_token cancellation = {});

    // Direct write of one acquired resource's quantity, gated like any memory
    // write. Not an engine grant: no game code runs.
    [[nodiscard]] domain::Result<SantaMonicaResourceWrite> santamonica_runtime_set_resource(
        const domain::SessionId& id, const domain::RuntimeId& runtime_id,
        std::string_view name, std::int64_t quantity, std::string_view confirmation,
        std::stop_token cancellation = {});

    [[nodiscard]] domain::Result<UnrealDiscoverResult> unreal_runtime_discover(
        const domain::SessionId& id,
        const UnrealDiscoverRequest& request,
        std::stop_token cancellation = {}
    );

    [[nodiscard]] domain::Result<UnrealClassPage> unreal_runtime_classes(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::string_view name_contains,
        std::size_t limit,
        std::string_view page_token
    ) const;

    [[nodiscard]] domain::Result<UnrealTypeResult> unreal_runtime_type(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::optional<domain::Address> class_address,
        std::string_view class_name,
        bool include_inherited,
        std::size_t max_properties,
        std::size_t max_super_depth,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<UnrealObjectsPage> unreal_runtime_objects(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id,
        std::string_view class_name,
        bool include_derived,
        std::size_t max_objects,
        std::string_view page_token,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<void> unreal_runtime_release(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id
    );

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

    [[nodiscard]] domain::Result<ReferenceReport> scan_references(
        const domain::SessionId& id,
        const domain::ProcessSession& session,
        std::span<const domain::MemoryRegion> sorted_regions,
        domain::Address target,
        domain::TargetPointerWidth width,
        const ReferenceQuery& query,
        std::stop_token cancellation
    ) const;

    // Shared by every Unreal runtime query: opens the context, checks that the
    // owning session still points at the same process, and builds a reader over
    // a fresh address-space snapshot.
    struct RuntimeQueryScope {
        std::shared_ptr<domain::ProcessSession> session;
        std::shared_ptr<const UnrealRuntimeContext> context;
        std::shared_ptr<SessionRuntimeMemoryView> view;
        std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot> snapshot;
        const domain::UnrealRuntimeProfile* profile{};
    };

    [[nodiscard]] domain::Result<RuntimeQueryScope> open_runtime_scope(
        const domain::SessionId& id,
        const domain::RuntimeId& runtime_id
    ) const;

    [[nodiscard]] domain::RuntimeLimits runtime_limits() const;
    [[nodiscard]] UnrealProvenance provenance_of(const UnrealRuntimeContext& context) const;

    std::unique_ptr<domain::ProcessMemoryProvider> provider_;
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider_;
    security::SecurityPolicy policy_;
    SessionManager sessions_;
    mutable ScanSessionManager scan_sessions_;
    mutable UnrealRuntimeManager unreal_contexts_;
    mutable SantaMonicaRuntimeManager santamonica_contexts_;
    // Per-process key for resume tokens. It never leaves the server, so a token
    // cannot be forged or replayed against a different query, and it dies with
    // the process -- a restarted server rejects stale continuations instead of
    // resuming a sweep over an address space that no longer exists.
    std::uint64_t resume_key_{};
    // Constructed last so it observes fully-initialized sessions_/scan_sessions_/
    // policy_ before any worker thread can touch them (workers only run once a
    // job is submitted, strictly after this constructor returns).
    std::unique_ptr<AnalysisJobManager> analysis_jobs_;
};

}  // namespace argos::application
