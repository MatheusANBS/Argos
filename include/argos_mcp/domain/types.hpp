#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace argos::domain {

using Address = std::uint64_t;
using ProcessId = std::uint32_t;

class SessionId final {
public:
    static std::expected<SessionId, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const SessionId&) const = default;

private:
    explicit SessionId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

class ScanSessionId final {
public:
    static std::expected<ScanSessionId, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const ScanSessionId&) const = default;

private:
    explicit ScanSessionId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

// Opaque handle for a background analysis job (Spec 0008). Owned by exactly
// one SessionId and never valid across server instances or after release.
class AnalysisJobId final {
public:
    static std::expected<AnalysisJobId, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const AnalysisJobId&) const = default;

private:
    explicit AnalysisJobId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

// Opaque continuation cursor (Spec 0008). Reserved for a follow-up pass: this
// version does not issue resume tokens (see AnalysisJobTermination), but the
// type exists so the wire contract and error taxonomy (`stale_resume_token`,
// `unsupported`) are already in place for that extension.
class ScanResumeToken final {
public:
    static std::expected<ScanResumeToken, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const ScanResumeToken&) const = default;

private:
    explicit ScanResumeToken(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

enum class AccessMode {
    read_only,
    read_write,
};

enum class ScanValueType {
    u8, u16, u32, u64,
    i8, i16, i32, i64,
    f32, f64,
};

enum class ScanComparison {
    exact,
    unknown,
    in_range,
    changed,
    unchanged,
    increased,
    decreased,
    increased_by,
    decreased_by,
};

enum class DebugErrorCode {
    invalid_argument,
    unauthorized,
    not_found,
    access_denied,
    unsupported,
    io_error,
    limit_exceeded,
    invalid_state,
    cancelled,
    parse_error,
};

struct DebugError {
    DebugErrorCode code{};
    std::string safe_message;
    // Closed, machine-readable refinement of `code` (e.g. "analysis_job_active",
    // "results_expired", "job_queue_full"). Empty when the code alone is
    // specific enough. Never free text -- see Spec 0008 "Erros de API".
    std::string reason;
};

template <typename T>
using Result = std::expected<T, DebugError>;

struct ProcessInfo {
    ProcessId pid{};
    std::string name;
    std::optional<std::string> executable;
    bool same_user{false};
};

struct MemoryRegion {
    Address start{};
    Address end{};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool private_mapping{false};
    std::string name;

    [[nodiscard]] std::uint64_t size() const noexcept { return end >= start ? end - start : 0U; }
};

struct ModuleInfo {
    std::string name;
    std::string path;
    Address base{};
    std::uint64_t size{};
};

struct ScanMatch {
    Address address{};
};

struct SessionInfo {
    SessionId id;
    ProcessId pid{};
    std::string process_name;
    AccessMode access{AccessMode::read_only};
};

struct ScanSessionInfo {
    ScanSessionId id;
    SessionId owner;
    ScanValueType value_type{};
    std::size_t candidate_count{};
    std::uint32_t generation{};
};

// Telemetry for a single sweep over the address space. Scoped to one scan
// operation, not to the scan session state: it answers "how much of the target
// did this call actually look at", which distinguishes an empty result meaning
// "the value is not present" from one meaning "the budget ran out first".
struct ScanCoverage {
    std::uint64_t bytes_scanned{};
    std::uint64_t bytes_eligible{};
    std::size_t regions_scanned{};
    std::size_t regions_eligible{};
    bool truncated_by_budget{false};
    bool truncated_by_result_limit{false};

    // 1.0 means the whole eligible range was swept. An empty candidate set is
    // only conclusive when this reaches 1.0.
    [[nodiscard]] double coverage_ratio() const noexcept {
        if (bytes_eligible == 0U) return 1.0;
        const auto swept = bytes_scanned < bytes_eligible ? bytes_scanned : bytes_eligible;
        return static_cast<double>(swept) / static_cast<double>(bytes_eligible);
    }

    // "Swept everything eligible and was not cut short." Deliberately derived
    // from bytes rather than from the flags alone: a region that failed to read
    // also leaves the sweep incomplete, and the caller must not read an empty
    // candidate set as conclusive in that case either.
    [[nodiscard]] bool complete() const noexcept {
        return !truncated_by_budget && !truncated_by_result_limit && bytes_scanned >= bytes_eligible;
    }
};

// ---------------------------------------------------------------------------
// Spec 0008 -- async scan operations (AnalysisJobManager wire vocabulary).
//
// Only `AnalysisJobKind::scan` is produced by this version. `pointer_index`
// and `unreal_runtime` are reserved so the envelope below does not need to
// change shape when Specs 0010/0012 add those job kinds; nothing in this
// codebase constructs them yet.
// ---------------------------------------------------------------------------

// The six scan-engine operations Spec 0008 accepts as async jobs. Every
// value has an existing synchronous tool of the same name; scan_start
// validates and converts a JSON `operation` into exactly one of these before
// the domain ever sees it.
enum class AsyncScanOperation {
    scan_exact,
    strings,
    scan_pointers_to,
    scan_pointer_chains,
    scan_first,
    scan_next,
};

enum class AnalysisJobKind {
    scan,
    pointer_index,   // reserved for Spec 0010; not constructible yet.
    unreal_runtime,  // reserved for Spec 0012; not constructible yet.
};

enum class AnalysisJobState {
    queued,
    running,
    completed,
    cancelled,
    failed,
};

enum class AnalysisStopReason {
    operation_completed,
    range_exhausted,
    byte_budget,
    result_limit,
    deadline,
    max_depth,
    max_fanout,
    client_cancelled,
    session_detached,
    server_shutdown,
    target_exited,
    read_error,
    stale_snapshot,     // reserved for pointer_index/unreal_runtime jobs.
    unstable_snapshot,  // reserved for pointer_index/unreal_runtime jobs.
    internal_error,
};

enum class AnalysisTruncationReason {
    byte_budget,
    result_limit,
    deadline,
    max_depth,
    max_fanout,
    // The scan itself may have finished cleanly (coverage_complete can still
    // be true), but AnalysisJobManager could not retain every match within
    // SecurityPolicy::max_async_results_retained_bytes -- a global cap summed
    // across every retained job, not a per-job one. Independent of the other
    // reasons above: a sweep can be untruncated by byte_budget/result_limit
    // and still lose trailing matches here purely because other jobs already
    // hold most of the retained-bytes budget.
    retained_bytes_budget,
};

// A job never produces a stop reason outside the closed subset its own
// operation can reach: scan operations never emit `stale_snapshot` or
// `unstable_snapshot` (those describe pointer-index/Unreal snapshots), and
// only scan_pointer_chains emits `max_depth`/`max_fanout`. The serializer and
// the job worker both consult this so an impossible combination fails a
// build-time-cheap assertion in tests rather than reaching the wire.
[[nodiscard]] bool is_stop_reason_valid_for_operation(
    AsyncScanOperation operation,
    AnalysisStopReason reason
) noexcept;

// Monotonic, bounded telemetry for one job. `sequence` increases on every
// published snapshot; every other counter is non-decreasing within a job.
// Deliberately free of bytes/addresses/patterns -- only counts and sizes are
// safe to hand back to the client and to log (see Spec 0008 "Observabilidade").
struct ScanProgress {
    std::uint64_t sequence{};
    std::size_t bytes_scanned{};
    std::size_t bytes_eligible{};
    std::size_t bytes_skipped{};
    std::size_t regions_scanned{};
    std::size_t regions_eligible{};
    std::size_t regions_skipped{};
    std::size_t matches_found{};
    std::size_t matches_retained{};

    [[nodiscard]] double coverage_ratio() const noexcept {
        if (bytes_eligible == 0U) return 1.0;
        const auto swept = bytes_scanned < bytes_eligible ? bytes_scanned : bytes_eligible;
        return static_cast<double>(swept) / static_cast<double>(bytes_eligible);
    }
};

// Terminal explanation for a job. `coverage_complete` and `results_complete`
// are independent: a job can sweep every eligible byte (coverage_complete)
// while still discarding matches past a retained-result cap
// (results_complete == false), and vice versa is never true by construction.
struct AnalysisJobTermination {
    AnalysisStopReason reason{};
    bool coverage_complete{false};
    bool results_complete{false};
    bool truncated{false};
    std::vector<AnalysisTruncationReason> truncation_reasons;
    std::size_t read_error_count{};
    // Diagnostic only -- never sufficient to resume correctly (see Spec 0008
    // "Retomada correta"). Populated only when the worker can name a clean,
    // alignment-safe boundary cheaply; absent otherwise.
    std::optional<Address> next_start_address;
    // Always empty in this version: resume_token issuance/redemption is a
    // deferred extension point (region fingerprinting, CAS admission, and
    // per-operation overlap state are not implemented yet). The field exists
    // so the wire shape already matches the spec for a follow-up pass.
    std::optional<ScanResumeToken> resume_token;

    [[nodiscard]] bool complete() const noexcept { return coverage_complete && results_complete; }
};

// Envelope shared by every job kind (only `scan` today). `operation` is not
// part of the C++ contract snippet in Spec 0008's AnalysisJobInfo, but every
// wire example in that spec includes it and a client cannot otherwise tell
// scan_exact from scan_pointers_to; it is added here deliberately (see
// implementation report for this ambiguity call).
struct AnalysisJobInfo {
    AnalysisJobId id;
    SessionId owner;
    AnalysisJobKind kind{AnalysisJobKind::scan};
    AsyncScanOperation operation{};
    AnalysisJobState state{};
    bool cancel_requested{false};
    bool results_available{false};
    bool results_expired{false};
    ScanProgress progress;
    std::optional<AnalysisJobTermination> termination;
};

[[nodiscard]] std::string_view to_string(AsyncScanOperation operation) noexcept;
[[nodiscard]] std::string_view to_string(AnalysisJobKind kind) noexcept;
[[nodiscard]] std::string_view to_string(AnalysisJobState state) noexcept;
[[nodiscard]] std::string_view to_string(AnalysisStopReason reason) noexcept;
[[nodiscard]] std::string_view to_string(AnalysisTruncationReason reason) noexcept;
[[nodiscard]] std::optional<AsyncScanOperation> async_scan_operation_from_string(std::string_view text) noexcept;

// Server-side selection over the region list. Without it a real target forces
// the client to download every region just to answer "how much is writable".
struct RegionFilter {
    std::optional<bool> readable;
    std::optional<bool> writable;
    std::optional<bool> executable;
    std::optional<bool> private_mapping;
    std::optional<Address> start_address;
    std::optional<Address> end_address;
    std::uint64_t min_size{0U};
    std::optional<std::uint64_t> max_size;
    std::string name_contains;

    [[nodiscard]] bool matches(const MemoryRegion& region) const noexcept;
};

struct RegionPage {
    std::vector<MemoryRegion> regions;
    std::size_t total_matched{};
    std::size_t offset{};
    bool truncated{false};
};

// Aggregate shape of the address space, sized to fit in a single response for
// any target. Answers "how much is there to scan" without listing regions.
struct AddressSpaceSummary {
    std::size_t region_count{};
    std::uint64_t total_bytes{};
    std::size_t readable_count{};
    std::uint64_t readable_bytes{};
    std::size_t writable_count{};
    std::uint64_t writable_bytes{};
    std::size_t executable_count{};
    std::uint64_t executable_bytes{};
    std::size_t private_count{};
    std::uint64_t private_bytes{};
    // Bytes a scan would actually sweep: readable, and readable+writable.
    std::uint64_t scannable_bytes{};
    std::uint64_t scannable_writable_bytes{};
    std::uint64_t largest_region_bytes{};
    Address lowest_address{};
    Address highest_address{};
};

[[nodiscard]] std::string_view to_string(AccessMode mode) noexcept;
[[nodiscard]] std::string_view to_string(DebugErrorCode code) noexcept;
[[nodiscard]] std::string_view to_string(ScanValueType type) noexcept;
[[nodiscard]] std::size_t scan_value_size(ScanValueType type) noexcept;
[[nodiscard]] std::optional<ScanValueType> scan_value_type_from_string(std::string_view text) noexcept;
[[nodiscard]] std::optional<ScanComparison> scan_comparison_from_string(std::string_view text) noexcept;

// Encodes a decimal literal into little-endian bytes of exactly the width of
// `type`. Rejects overflow, sign mismatch and fractional input for integral
// types instead of silently truncating -- the caller is an agent that would
// otherwise hand-roll the conversion and get it wrong quietly.
[[nodiscard]] std::expected<std::vector<std::byte>, std::string> encode_scan_value(
    ScanValueType type,
    std::string_view decimal
);

// Pure aggregations over a region list; no process I/O, no OS handles.
[[nodiscard]] AddressSpaceSummary summarize_address_space(std::span<const MemoryRegion> regions) noexcept;

[[nodiscard]] RegionPage filter_regions(
    std::span<const MemoryRegion> regions,
    const RegionFilter& filter,
    std::size_t offset,
    std::size_t limit
);

// Bytes a sweep would touch given the same eligibility rules the scan engine
// applies. Used to make ScanCoverage::coverage_ratio meaningful.
[[nodiscard]] std::pair<std::uint64_t, std::size_t> eligible_scan_bytes(
    std::span<const MemoryRegion> regions,
    bool writable_only,
    std::optional<Address> start_address,
    std::optional<Address> end_address
) noexcept;

}  // namespace argos::domain
