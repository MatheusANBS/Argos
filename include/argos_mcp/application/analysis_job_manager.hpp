#pragma once

#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/types.hpp"
#include "argos_mcp/security/policy.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace argos::application {

// Spec 0008 -- async scan operations.
//
// AnalysisJobManager runs the six long scan operations (scan_exact, strings,
// scan_pointers_to, scan_pointer_chains, scan_first, scan_next) in a bounded
// background worker pool instead of on the MCP request thread. It reuses the
// exact same scan engine as the synchronous tools by calling the
// corresponding MemoryDebugService method from a worker, passing the job's
// own std::stop_token through to the existing chunk-level cancellation
// checks and a progress callback through the additive ScanProgressSink
// parameter those methods already accept. Sync and async paths therefore
// never diverge in what counts as a match.
//
// Deferred extension point: resume_token issuance/redemption is NOT
// implemented in this version (see AnalysisJobTermination in
// domain/types.hpp). scan_start's resume_token-only continuation form is
// accepted by the schema but always answers `unsupported`
// (reason: "resume_not_supported"). A follow-up pass can add it without
// changing this class's public shape.
class AnalysisJobManager final {
public:
    // Discriminated request payloads, one per Spec-0008-eligible operation.
    // These mirror the parameters of the matching MemoryDebugService method
    // exactly (minus session id / cancellation / progress, which the
    // manager supplies); the protocol layer is responsible for validating
    // and converting untyped JSON into one of these before submit() ever
    // sees it -- scan_start never forwards a raw JSON object to the domain.
    struct ExactScanRequest {
        std::vector<std::byte> pattern;
        std::size_t alignment{1U};
        std::size_t result_limit{};
        bool writable_only{false};
        std::optional<domain::Address> start_address;
        std::optional<domain::Address> end_address;
    };

    struct StringScanRequest {
        std::size_t min_length{4U};
        std::string encoding{"ascii"};
        std::size_t result_limit{};
        bool writable_only{false};
        std::optional<domain::Address> start_address;
        std::optional<domain::Address> end_address;
    };

    struct PointerScanRequest {
        domain::Address target{};
        std::size_t pointer_size{8U};
        std::size_t result_limit{};
        bool writable_only{false};
        std::optional<domain::Address> start_address;
        std::optional<domain::Address> end_address;
    };

    struct PointerChainScanRequest {
        domain::Address target{};
        std::size_t pointer_size{8U};
        std::size_t max_depth{1U};
        std::size_t max_fanout{1U};
        std::size_t result_limit{};
        bool writable_only{false};
        std::optional<domain::Address> start_address;
        std::optional<domain::Address> end_address;
    };

    struct FirstScanRequest {
        domain::ScanValueType value_type{};
        domain::ScanComparison comparison{};
        std::optional<std::vector<std::byte>> value;
        std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range;
        std::size_t result_limit{};
        bool writable_only{false};
        std::optional<domain::Address> start_address;
        std::optional<domain::Address> end_address;
    };

    struct NextScanRequest {
        domain::ScanSessionId scan_id;
        domain::ScanComparison comparison{};
        std::optional<std::vector<std::byte>> value;
        std::optional<std::vector<std::byte>> delta;
    };

    using Request = std::variant<
        ExactScanRequest, StringScanRequest, PointerScanRequest,
        PointerChainScanRequest, FirstScanRequest, NextScanRequest>;

    // Requested execution limits, already validated/clamped against
    // SecurityPolicy by the time submit() runs. result_limit lives inside
    // each Request alternative because it is operation-specific in the sync
    // API this reuses; only byte_budget/deadline are generic.
    struct ExecutionLimits {
        std::size_t byte_budget{};
        std::size_t deadline_ms{};
    };

    // Discriminated, immutable result snapshot published once a job reaches
    // a terminal state. Exactly one field is populated, selected by the
    // job's operation. A tagged struct is used instead of a
    // std::variant<...> of five near-identical shapes to keep pagination and
    // JSON presentation simple; see the implementation report for this
    // simplification relative to the spec's illustrative AnalysisJobResult.
    struct Items {
        std::vector<domain::ScanMatch> address_matches;     // scan_exact, scan_pointers_to
        std::vector<StringMatch> string_matches;             // strings
        std::vector<PointerChainCandidate> pointer_chains;   // scan_pointer_chains
        std::vector<domain::ScanMatch> value_matches;        // scan_first, scan_next (diagnostic or final)
        // Only set for scan_first/scan_next, and only once the job reached
        // range_exhausted with coverage_complete && results_complete -- a
        // truncated, cancelled or failed job never publishes a scan session
        // (Spec 0008 "scan_first mantém candidatos num draft transacional").
        std::optional<domain::ScanSessionInfo> published_session;
    };

    struct ResultsPage {
        domain::AnalysisJobInfo info;
        std::vector<domain::ScanMatch> address_matches;
        std::vector<StringMatch> string_matches;
        std::vector<PointerChainCandidate> pointer_chains;
        std::vector<domain::ScanMatch> value_matches;
        std::optional<domain::ScanSessionInfo> published_session;
        std::size_t offset{};
        std::size_t total{};
        bool has_more{false};
    };

    using Clock = std::chrono::steady_clock;
    using ClockFn = std::function<Clock::time_point()>;

    // `clock` defaults to the real steady_clock and is production behavior;
    // tests that need to cross a TTL deterministically (without a real sleep)
    // inject a fake one instead. Never exposed through MemoryDebugService's
    // constructor -- only test code reaches for the third argument.
    explicit AnalysisJobManager(
        MemoryDebugService& service,
        const security::SecurityPolicy& policy,
        ClockFn clock = nullptr
    );
    ~AnalysisJobManager();

    AnalysisJobManager(const AnalysisJobManager&) = delete;
    AnalysisJobManager& operator=(const AnalysisJobManager&) = delete;

    [[nodiscard]] domain::Result<domain::AnalysisJobInfo> submit(
        const domain::SessionId& owner,
        domain::AsyncScanOperation operation,
        Request request,
        ExecutionLimits limits
    );

    // Always fails with `unsupported`/"resume_not_supported": resume tokens
    // are never issued by this version (see the class comment above).
    [[nodiscard]] domain::Result<domain::AnalysisJobInfo> submit_resume(
        const domain::SessionId& owner,
        const domain::ScanResumeToken& token,
        ExecutionLimits limits
    );

    [[nodiscard]] domain::Result<domain::AnalysisJobInfo> status(
        const domain::SessionId& owner,
        const domain::AnalysisJobId& id
    ) const;

    [[nodiscard]] domain::Result<ResultsPage> results(
        const domain::SessionId& owner,
        const domain::AnalysisJobId& id,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<domain::AnalysisJobInfo> cancel(
        const domain::SessionId& owner,
        const domain::AnalysisJobId& id
    );

    [[nodiscard]] domain::Result<void> release(
        const domain::SessionId& owner,
        const domain::AnalysisJobId& id
    );

    // True when `owner` currently has a job in the `running` state. Consulted
    // by MemoryDebugService's synchronous scan_* methods to enforce "at most
    // one long scan running per session" (Spec 0008, "Ownership, RAII e
    // concorrência"); a queued job does not count.
    [[nodiscard]] bool has_running_job(const domain::SessionId& owner) const;

    // Cancels every queued/running job owned by `owner` with
    // `session_detached`, waits (outside any registry lock) for workers to
    // release the session, then erases every record -- queued, running,
    // terminal or tombstoned -- belonging to it. Called by
    // MemoryDebugService::detach() before the session itself is torn down.
    void detach_session(const domain::SessionId& owner);

    // Opaque worker-side record; the full definition lives in
    // analysis_job_manager.cpp. Forward-declared as a public (but otherwise
    // unnamed-outside-this-translation-unit) type so the free helper
    // functions that operate on it there do not need to be members.
    struct JobRecord;

private:
    void worker_loop(std::stop_token worker_token);
    void run_job(const std::shared_ptr<JobRecord>& job);
    void reap_expired_locked() const;
    [[nodiscard]] std::string generate_id();

    MemoryDebugService& service_;
    const security::SecurityPolicy& policy_;
    ClockFn clock_;

    mutable std::mutex mutex_;
    mutable std::condition_variable_any wake_workers_;
    mutable std::condition_variable_any session_drained_;
    // mutable: status()/results() are logically const (polling must not
    // require exclusive access) but opportunistically reap tombstones past
    // their TTL, which erases from the registry -- a cache-eviction side
    // effect, not an observable state change to any caller.
    mutable std::unordered_map<std::string, std::shared_ptr<JobRecord>> jobs_;
    std::vector<std::string> pending_;              // FIFO of queued job ids
    std::unordered_set<std::string> running_owners_;  // session ids with a running job
    std::unordered_set<std::string> closing_owners_;  // sessions mid-detach: reject new submissions
    std::mt19937_64 rng_;
    std::mutex rng_mutex_;

    // Declared last so its destructor (request_stop + join on every worker)
    // runs first during ~AnalysisJobManager, before any other member is torn
    // down -- see the explicit destructor body for the shutdown sequence.
    std::vector<std::jthread> workers_;
};

}  // namespace argos::application
