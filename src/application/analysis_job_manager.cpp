#include "argos_mcp/application/analysis_job_manager.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <iterator>
#include <type_traits>
#include <utility>

namespace argos::application {
namespace {

using Clock = std::chrono::steady_clock;

[[nodiscard]] domain::DebugError error(
    const domain::DebugErrorCode code,
    std::string message,
    std::string reason = {}
) {
    return domain::DebugError{code, std::move(message), std::move(reason)};
}

// Why a job's cooperative stop was requested. The underlying scan engine only
// ever reports a generic `cancelled` DebugError once std::stop_token fires;
// this is how the worker recovers which terminal state/reason that maps to
// (deadline is `completed`, everything else is `cancelled` -- Spec 0008
// "Motivo de tÃ©rmino e cobertura").
enum class StopTrigger { none, client, deadline, session_detached, server_shutdown };

// The existing sync scan engines report only a single aggregate `truncated`
// flag, not which cap bound first. Reconstructing byte_budget vs
// result_limit from the numbers the job already tracked is best-effort but
// accurate for the common (single binding constraint) case; see the
// implementation report for the rare ambiguous case (e.g. both caps hit on
// the very same chunk).
[[nodiscard]] domain::AnalysisStopReason infer_sweep_reason(
    const bool truncated,
    const std::size_t bytes_scanned,
    const std::size_t byte_budget,
    const std::size_t matches_count,
    const std::size_t result_limit
) noexcept {
    if (!truncated) return domain::AnalysisStopReason::range_exhausted;
    if (bytes_scanned >= byte_budget) return domain::AnalysisStopReason::byte_budget;
    if (matches_count >= result_limit) return domain::AnalysisStopReason::result_limit;
    return domain::AnalysisStopReason::result_limit;
}

struct CancelledOutcome {
    domain::AnalysisJobState state{};
    domain::AnalysisStopReason reason{};
};

[[nodiscard]] CancelledOutcome classify_cancelled(const StopTrigger trigger) noexcept {
    switch (trigger) {
        case StopTrigger::deadline:
            return {domain::AnalysisJobState::completed, domain::AnalysisStopReason::deadline};
        case StopTrigger::session_detached:
            return {domain::AnalysisJobState::cancelled, domain::AnalysisStopReason::session_detached};
        case StopTrigger::server_shutdown:
            return {domain::AnalysisJobState::cancelled, domain::AnalysisStopReason::server_shutdown};
        case StopTrigger::client:
        case StopTrigger::none:
            break;
    }
    return {domain::AnalysisJobState::cancelled, domain::AnalysisStopReason::client_cancelled};
}

// Native/backend failures are already translated to safe DebugErrorCodes by
// the engine; this only picks the closer-fitting AnalysisStopReason label.
[[nodiscard]] domain::AnalysisStopReason classify_failure(const domain::DebugErrorCode code) noexcept {
    if (code == domain::DebugErrorCode::io_error) return domain::AnalysisStopReason::read_error;
    return domain::AnalysisStopReason::internal_error;
}

// ---------------------------------------------------------------------------
// Retained-results byte accounting (fixes ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES
// being declared/clamped by SecurityPolicy but never applied). size() *
// sizeof(T) alone would undercount: StringMatch's `text`/`encoding` and
// PointerChainCandidate's `hop_offsets`/`module_name` own separate heap
// allocations the outer vector's own storage does not include. capacity()
// (not size()) is used throughout so the count reflects bytes actually
// reserved; callers shrink_to_fit() first so capacity() == size() for
// anything that survives, keeping the accounted total honest about real
// process memory rather than just "logical" content.
// ---------------------------------------------------------------------------

[[nodiscard]] std::size_t element_heap_bytes(const domain::ScanMatch&) noexcept { return 0U; }

[[nodiscard]] std::size_t element_heap_bytes(const StringMatch& match) noexcept {
    return match.text.capacity() + match.encoding.capacity();
}

[[nodiscard]] std::size_t element_heap_bytes(const PointerChainCandidate& candidate) noexcept {
    return candidate.module_name.capacity() + candidate.hop_offsets.capacity() * sizeof(std::int64_t);
}

[[nodiscard]] std::size_t session_info_bytes(const domain::ScanSessionInfo& info) noexcept {
    return sizeof(domain::ScanSessionInfo) + info.id.value().capacity() + info.owner.value().capacity();
}

template <class T>
[[nodiscard]] std::size_t vector_retained_bytes(const std::vector<T>& values) noexcept {
    std::size_t total = values.capacity() * sizeof(T);
    for (const auto& value : values) {
        total += element_heap_bytes(value);
    }
    return total;
}

[[nodiscard]] std::size_t items_retained_bytes(const AnalysisJobManager::Items& items) noexcept {
    std::size_t total = vector_retained_bytes(items.address_matches) + vector_retained_bytes(items.string_matches) +
        vector_retained_bytes(items.pointer_chains) + vector_retained_bytes(items.value_matches);
    if (items.published_session) {
        total += session_info_bytes(*items.published_session);
    }
    return total;
}

// Drops each vector's unused reserved capacity so vector_retained_bytes'
// capacity()-based count matches what the process actually holds onto --
// without this, a vector grown by repeated push_back during the sweep could
// retain more memory than the accounting believes it does.
void shrink_items(AnalysisJobManager::Items& items) {
    items.address_matches.shrink_to_fit();
    items.string_matches.shrink_to_fit();
    items.pointer_chains.shrink_to_fit();
    items.value_matches.shrink_to_fit();
}

// Trims `values` to the longest prefix whose accounted bytes (each kept
// element's own storage plus its heap content) fit inside `budget`,
// returning exactly how many bytes that prefix accounts for. Only ever
// called on the one vector a given operation actually populates -- see
// Items' comment ("Exactly one field is populated, selected by the job's
// operation").
template <class T>
[[nodiscard]] std::size_t truncate_to_budget(std::vector<T>& values, const std::size_t budget) {
    std::size_t kept_bytes = 0U;
    std::size_t kept_count = 0U;
    for (; kept_count < values.size(); ++kept_count) {
        const std::size_t next = kept_bytes + sizeof(T) + element_heap_bytes(values[kept_count]);
        if (next > budget) break;
        kept_bytes = next;
    }
    if (kept_count < values.size()) {
        std::vector<T> trimmed(
            std::make_move_iterator(values.begin()),
            std::make_move_iterator(values.begin() + static_cast<std::ptrdiff_t>(kept_count))
        );
        values = std::move(trimmed);
    }
    values.shrink_to_fit();
    return kept_bytes;
}

}  // namespace

struct AnalysisJobManager::JobRecord {
    domain::AnalysisJobId id;
    domain::SessionId owner;
    domain::AsyncScanOperation operation;
    Request request;
    ExecutionLimits limits;
    std::stop_source stop_source;

    // Guards every field below. Never held during process I/O, worker
    // execution or condition_variable waits on the registry lock.
    mutable std::mutex mutex;
    domain::AnalysisJobState state{domain::AnalysisJobState::queued};
    bool cancel_requested{false};
    StopTrigger stop_trigger{StopTrigger::none};
    domain::ScanProgress progress{};
    std::optional<domain::AnalysisJobTermination> termination;
    std::shared_ptr<const AnalysisJobManager::Items> result;
    bool results_expired{false};
    Clock::time_point created_at{};
    std::optional<Clock::time_point> terminal_at;
    // This job's current share of AnalysisJobManager::retained_bytes_ (0
    // until a terminal state publishes `result`). Recorded per job so
    // whichever code path frees the job -- TTL expiry, release(), or
    // detach_session() -- can give back exactly what it reserved, never more
    // or less. Written under `mutex` together with `retained_bytes_`, which
    // is always taken first (registry lock outer, job lock inner).
    std::size_t retained_bytes{0U};
};

namespace {

// First writer wins: a client cancel racing a deadline or a detach must not
// overwrite whichever trigger already requested the stop (Spec 0008
// "Uma transiÃ§Ã£o terminal Ã© linearizada uma Ãºnica vez").
void request_stop_once(AnalysisJobManager::JobRecord& job, const StopTrigger trigger) {
    std::scoped_lock lock(job.mutex);
    if (job.stop_trigger == StopTrigger::none) {
        job.stop_trigger = trigger;
    }
    job.cancel_requested = true;
    job.stop_source.request_stop();
}

[[nodiscard]] domain::AnalysisJobInfo snapshot_locked(const AnalysisJobManager::JobRecord& job) {
    domain::AnalysisJobInfo info{job.id, job.owner};
    info.kind = domain::AnalysisJobKind::scan;
    info.operation = job.operation;
    info.state = job.state;
    info.cancel_requested = job.cancel_requested;
    info.progress = job.progress;
    info.termination = job.termination;
    info.results_available = job.result != nullptr && !job.results_expired;
    info.results_expired = job.results_expired;
    return info;
}

[[nodiscard]] domain::AnalysisJobInfo snapshot(const std::shared_ptr<AnalysisJobManager::JobRecord>& job) {
    std::scoped_lock lock(job->mutex);
    return snapshot_locked(*job);
}

}  // namespace

AnalysisJobManager::AnalysisJobManager(
    MemoryDebugService& service,
    const security::SecurityPolicy& policy,
    ClockFn clock
) : service_(service), policy_(policy), rng_(std::random_device{}()),
    clock_(clock ? std::move(clock) : ClockFn{[] { return Clock::now(); }}) {
    const auto worker_count = std::max<std::size_t>(1U, policy_.max_async_workers);
    workers_.reserve(worker_count);
    for (std::size_t index = 0; index < worker_count; ++index) {
        workers_.emplace_back([this](std::stop_token token) { worker_loop(token); });
    }
}

AnalysisJobManager::~AnalysisJobManager() {
    // Shutdown sequence (Spec 0008 "Shutdown"): stop accepting new jobs,
    // cancel the queue with server_shutdown, request stop on every running
    // job, then let the (reverse-declared-last) workers_ vector join --
    // in-flight sync calls already unwind promptly because their own
    // stop_source is requested here, not just the worker's implicit token.
    std::vector<std::shared_ptr<JobRecord>> queued_to_finalize;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& id : pending_) {
            const auto it = jobs_.find(id);
            if (it != jobs_.end()) {
                queued_to_finalize.push_back(it->second);
            }
        }
        pending_.clear();
        for (auto& [id, job] : jobs_) {
            (void)id;
            std::scoped_lock job_lock(job->mutex);
            if (job->state == domain::AnalysisJobState::running) {
                if (job->stop_trigger == StopTrigger::none) {
                    job->stop_trigger = StopTrigger::server_shutdown;
                }
                job->cancel_requested = true;
                job->stop_source.request_stop();
            }
        }
    }
    for (auto& job : queued_to_finalize) {
        std::scoped_lock job_lock(job->mutex);
        if (job->state != domain::AnalysisJobState::queued) continue;
        job->state = domain::AnalysisJobState::cancelled;
        domain::AnalysisJobTermination termination{};
        termination.reason = domain::AnalysisStopReason::server_shutdown;
        job->termination = termination;
        job->terminal_at = clock_();
    }
    wake_workers_.notify_all();
    // workers_ destructs next (reverse declaration order): request_stop on
    // each worker's own token, then join. No response is written after this.
}

std::string AnalysisJobManager::generate_id() {
    std::array<std::uint64_t, 2> words{};
    {
        std::scoped_lock lock(rng_mutex_);
        words[0] = rng_();
        words[1] = rng_();
    }
    std::array<char, 33> buffer{};
    buffer[32] = '\0';
    auto [ptr0, ec0] = std::to_chars(buffer.data(), buffer.data() + 16, words[0], 16);
    if (ec0 != std::errc{}) return generate_id();
    const auto written0 = static_cast<std::size_t>(ptr0 - buffer.data());
    if (written0 < 16U) {
        std::copy_backward(buffer.data(), buffer.data() + written0, buffer.data() + 16);
        std::fill(buffer.data(), buffer.data() + (16U - written0), '0');
    }
    auto [ptr1, ec1] = std::to_chars(buffer.data() + 16, buffer.data() + 32, words[1], 16);
    if (ec1 != std::errc{}) return generate_id();
    const auto written1 = static_cast<std::size_t>(ptr1 - (buffer.data() + 16));
    if (written1 < 16U) {
        std::copy_backward(buffer.data() + 16, buffer.data() + 16 + written1, buffer.data() + 32);
        std::fill(buffer.data() + 16, buffer.data() + 16 + (16U - written1), '0');
    }
    return std::string(buffer.data(), 32);
}

domain::Result<domain::AnalysisJobInfo> AnalysisJobManager::submit(
    const domain::SessionId& owner,
    const domain::AsyncScanOperation operation,
    Request request,
    const ExecutionLimits limits
) {
    std::shared_ptr<JobRecord> job;
    {
        std::scoped_lock lock(mutex_);
        if (closing_owners_.contains(owner.value())) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_state, "session is detaching; no new jobs are accepted", "session_closing"
            ));
        }
        if (jobs_.size() >= policy_.max_async_jobs_total) {
            return std::unexpected(error(
                domain::DebugErrorCode::limit_exceeded, "server-wide analysis job limit reached", "job_queue_full"
            ));
        }
        const auto owned_count = std::ranges::count_if(jobs_, [&owner](const auto& entry) {
            return entry.second->owner == owner;
        });
        if (static_cast<std::size_t>(owned_count) >= policy_.max_async_jobs_per_session) {
            return std::unexpected(error(
                domain::DebugErrorCode::limit_exceeded,
                "this session already has the maximum number of analysis jobs (queued, running or retained)",
                "job_queue_full"
            ));
        }
        if (pending_.size() >= policy_.max_async_queue_depth) {
            return std::unexpected(error(
                domain::DebugErrorCode::limit_exceeded, "analysis job queue is full", "job_queue_full"
            ));
        }

        std::optional<domain::AnalysisJobId> allocated_id;
        for (std::size_t attempt = 0; attempt < 8U; ++attempt) {
            auto id_result = domain::AnalysisJobId::create(generate_id());
            if (!id_result || jobs_.contains(id_result->value())) continue;
            allocated_id = *id_result;
            break;
        }
        if (!allocated_id) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_state, "unable to allocate analysis job id"));
        }
        // JobRecord has no default constructor (id/owner are opaque validated
        // types by design, matching SessionId elsewhere) -- id and owner are
        // supplied directly via C++20 aggregate paren-init; every other field
        // keeps its in-class default.
        job = std::make_shared<JobRecord>(*allocated_id, owner);
        job->created_at = clock_();
        job->operation = operation;
        job->request = std::move(request);
        job->limits = limits;
        jobs_.emplace(allocated_id->value(), job);
        pending_.push_back(allocated_id->value());
    }
    wake_workers_.notify_one();
    return snapshot(job);
}

domain::Result<domain::AnalysisJobInfo> AnalysisJobManager::submit_resume(
    const domain::SessionId&,
    const domain::ScanResumeToken&,
    const ExecutionLimits
) {
    // Deferred extension point -- see the class-level comment in
    // analysis_job_manager.hpp. No token is ever issued by this version, so
    // any resume_token presented here is definitionally unknown.
    return std::unexpected(error(
        domain::DebugErrorCode::unsupported,
        "resume_token continuation is not implemented in this version",
        "resume_not_supported"
    ));
}

domain::Result<domain::AnalysisJobInfo> AnalysisJobManager::status(
    const domain::SessionId& owner,
    const domain::AnalysisJobId& id
) const {
    std::shared_ptr<JobRecord> job;
    {
        std::scoped_lock lock(mutex_);
        const auto it = jobs_.find(id.value());
        if (it == jobs_.end() || it->second->owner != owner) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "analysis job not found"));
        }
        job = it->second;
    }
    reap_expired_locked();
    // Registry lock outer, job lock inner (see retained_bytes_'s declaration
    // comment): expiring results here gives back this job's share of the
    // global retained-bytes budget, so touching retained_bytes_ needs the
    // same nesting run_job()/release()/detach_session() use.
    std::scoped_lock lock(mutex_);
    std::scoped_lock job_lock(job->mutex);
    if (job->terminal_at && !job->results_expired) {
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(clock_() - *job->terminal_at).count();
        if (age >= static_cast<std::int64_t>(policy_.async_results_ttl_ms)) {
            job->results_expired = true;
            job->result.reset();
            retained_bytes_ -= job->retained_bytes;
            job->retained_bytes = 0U;
        }
    }
    return snapshot_locked(*job);
}

domain::Result<AnalysisJobManager::ResultsPage> AnalysisJobManager::results(
    const domain::SessionId& owner,
    const domain::AnalysisJobId& id,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || limit > policy_.max_async_job_result_items) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "limit is out of range"));
    }
    std::shared_ptr<JobRecord> job;
    {
        std::scoped_lock lock(mutex_);
        const auto it = jobs_.find(id.value());
        if (it == jobs_.end() || it->second->owner != owner) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "analysis job not found"));
        }
        job = it->second;
    }

    std::optional<domain::AnalysisJobInfo> info;
    std::shared_ptr<const Items> items;
    bool expired = false;
    {
        // Registry lock outer, job lock inner (see retained_bytes_'s
        // declaration comment): expiring results here gives back this job's
        // share of the global retained-bytes budget.
        std::scoped_lock lock(mutex_);
        std::scoped_lock job_lock(job->mutex);
        if (job->state == domain::AnalysisJobState::queued || job->state == domain::AnalysisJobState::running) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_state, "job has not reached a terminal state yet", "job_not_terminal"
            ));
        }
        if (job->terminal_at && !job->results_expired) {
            const auto age =
                std::chrono::duration_cast<std::chrono::milliseconds>(clock_() - *job->terminal_at).count();
            if (age >= static_cast<std::int64_t>(policy_.async_results_ttl_ms)) {
                job->results_expired = true;
                job->result.reset();
                retained_bytes_ -= job->retained_bytes;
                job->retained_bytes = 0U;
            }
        }
        expired = job->results_expired;
        items = job->result;
        info = snapshot_locked(*job);
    }
    if (expired || !items) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "job results have expired", "results_expired"));
    }

    // Exactly one vector is meaningful for a given operation; the others are
    // always empty, so summing sizes is equivalent to a switch on operation.
    const std::size_t total = items->address_matches.size() + items->string_matches.size() +
        items->pointer_chains.size() + items->value_matches.size();

    ResultsPage page{*info};
    page.offset = offset;
    page.total = total;
    page.published_session = items->published_session;

    const auto slice = [&](const auto& source, auto& destination) {
        if (offset >= source.size()) return;
        const auto count = std::min(limit, source.size() - offset);
        destination.assign(source.begin() + static_cast<std::ptrdiff_t>(offset),
                            source.begin() + static_cast<std::ptrdiff_t>(offset + count));
    };
    slice(items->address_matches, page.address_matches);
    slice(items->string_matches, page.string_matches);
    slice(items->pointer_chains, page.pointer_chains);
    slice(items->value_matches, page.value_matches);

    const auto returned = page.address_matches.size() + page.string_matches.size() +
        page.pointer_chains.size() + page.value_matches.size();
    page.has_more = offset + returned < total;
    return page;
}

domain::Result<domain::AnalysisJobInfo> AnalysisJobManager::cancel(
    const domain::SessionId& owner,
    const domain::AnalysisJobId& id
) {
    std::shared_ptr<JobRecord> job;
    bool was_queued = false;
    {
        std::scoped_lock lock(mutex_);
        const auto it = jobs_.find(id.value());
        if (it == jobs_.end() || it->second->owner != owner) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "analysis job not found"));
        }
        job = it->second;
        const auto pending_it = std::ranges::find(pending_, id.value());
        if (pending_it != pending_.end()) {
            pending_.erase(pending_it);
            was_queued = true;
        }
    }
    if (was_queued) {
        std::scoped_lock job_lock(job->mutex);
        if (job->state == domain::AnalysisJobState::queued) {
            job->state = domain::AnalysisJobState::cancelled;
            job->cancel_requested = true;
            domain::AnalysisJobTermination termination{};
            termination.reason = domain::AnalysisStopReason::client_cancelled;
            job->termination = termination;
            job->terminal_at = clock_();
        }
        return snapshot_locked(*job);
    }
    // Already running or terminal: idempotent either way -- request stop if
    // running, otherwise just report the winning terminal state unchanged.
    request_stop_once(*job, StopTrigger::client);
    return snapshot(job);
}

domain::Result<void> AnalysisJobManager::release(
    const domain::SessionId& owner,
    const domain::AnalysisJobId& id
) {
    std::scoped_lock lock(mutex_);
    const auto it = jobs_.find(id.value());
    if (it == jobs_.end() || it->second->owner != owner) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "analysis job not found"));
    }
    {
        std::scoped_lock job_lock(it->second->mutex);
        if (it->second->state == domain::AnalysisJobState::queued ||
            it->second->state == domain::AnalysisJobState::running) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_state,
                "job must be cancelled and reach a terminal state before it can be released",
                "job_not_terminal"
            ));
        }
        // Give back this job's share of the global retained-bytes budget --
        // a no-op if results already expired (TTL expiry already zeroed it).
        retained_bytes_ -= it->second->retained_bytes;
        it->second->retained_bytes = 0U;
    }
    jobs_.erase(it);
    return {};
}

bool AnalysisJobManager::has_running_job(const domain::SessionId& owner) const {
    std::scoped_lock lock(mutex_);
    return running_owners_.contains(owner.value());
}

void AnalysisJobManager::detach_session(const domain::SessionId& owner) {
    std::vector<std::shared_ptr<JobRecord>> queued_to_finalize;
    {
        std::scoped_lock lock(mutex_);
        closing_owners_.insert(owner.value());
        for (auto it = pending_.begin(); it != pending_.end();) {
            const auto job_it = jobs_.find(*it);
            if (job_it != jobs_.end() && job_it->second->owner == owner) {
                queued_to_finalize.push_back(job_it->second);
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto& [id, job] : jobs_) {
            (void)id;
            if (job->owner != owner) continue;
            std::scoped_lock job_lock(job->mutex);
            if (job->state == domain::AnalysisJobState::running) {
                if (job->stop_trigger == StopTrigger::none) {
                    job->stop_trigger = StopTrigger::session_detached;
                }
                job->cancel_requested = true;
                job->stop_source.request_stop();
            }
        }
    }
    for (auto& job : queued_to_finalize) {
        std::scoped_lock job_lock(job->mutex);
        if (job->state != domain::AnalysisJobState::queued) continue;
        job->state = domain::AnalysisJobState::cancelled;
        domain::AnalysisJobTermination termination{};
        termination.reason = domain::AnalysisStopReason::session_detached;
        job->termination = termination;
        job->terminal_at = clock_();
    }
    wake_workers_.notify_all();

    std::unique_lock lock(mutex_);
    session_drained_.wait(lock, [&] {
        for (auto& [id, job] : jobs_) {
            (void)id;
            if (job->owner != owner) continue;
            std::scoped_lock job_lock(job->mutex);
            if (job->state == domain::AnalysisJobState::running) return false;
        }
        return true;
    });
    for (auto it = jobs_.begin(); it != jobs_.end();) {
        if (it->second->owner == owner) {
            // Give back this job's share of the global retained-bytes
            // budget -- a no-op if results already expired.
            {
                std::scoped_lock job_lock(it->second->mutex);
                retained_bytes_ -= it->second->retained_bytes;
                it->second->retained_bytes = 0U;
            }
            it = jobs_.erase(it);
        } else {
            ++it;
        }
    }
    running_owners_.erase(owner.value());
    closing_owners_.erase(owner.value());
}

void AnalysisJobManager::reap_expired_locked() const {
    // Tombstone GC: erase records whose results already expired and whose
    // terminal state has outlived the (shorter) tombstone TTL too. Run
    // opportunistically from status()/results() rather than a dedicated
    // thread -- there is no correctness requirement to reap sooner, only a
    // bounded-memory one, and every accessor already visits the registry.
    std::scoped_lock lock(mutex_);
    for (auto it = jobs_.begin(); it != jobs_.end();) {
        const auto& job = it->second;
        bool erase = false;
        {
            std::scoped_lock job_lock(job->mutex);
            if (job->terminal_at && job->results_expired) {
                const auto age =
                    std::chrono::duration_cast<std::chrono::milliseconds>(clock_() - *job->terminal_at).count();
                erase = age >= static_cast<std::int64_t>(policy_.async_results_ttl_ms + policy_.async_tombstone_ttl_ms);
            }
        }
        it = erase ? jobs_.erase(it) : std::next(it);
    }
}

void AnalysisJobManager::run_job(const std::shared_ptr<JobRecord>& job) {
    const domain::SessionId owner = job->owner;
    const std::stop_token cancellation = job->stop_source.get_token();
    const auto deadline = clock_() + std::chrono::milliseconds(job->limits.deadline_ms);
    const std::size_t byte_budget = job->limits.byte_budget;

    // Shared by every branch below: publishes progress under the job's own
    // lock (never the registry lock) and folds deadline enforcement into the
    // same periodic checkpoint the engine already visits every chunk -- no
    // extra thread is needed to make a deadline cooperative.
    const ScanProgressSink sink = [this, job, deadline](const domain::ScanProgress& snapshot) {
        {
            std::scoped_lock lock(job->mutex);
            job->progress = snapshot;
        }
        if (clock_() >= deadline) {
            request_stop_once(*job, StopTrigger::deadline);
        }
    };

    domain::AnalysisJobState state = domain::AnalysisJobState::completed;
    domain::AnalysisJobTermination termination{};
    auto items = std::make_shared<Items>();

    const auto finalize_domain_error = [&](const domain::DebugError& failure) {
        if (failure.code == domain::DebugErrorCode::cancelled) {
            const auto outcome = classify_cancelled(job->stop_trigger);
            state = outcome.state;
            termination.reason = outcome.reason;
            termination.truncated = outcome.reason == domain::AnalysisStopReason::deadline;
            if (termination.truncated) {
                termination.truncation_reasons.push_back(domain::AnalysisTruncationReason::deadline);
            }
            termination.coverage_complete = false;
            termination.results_complete = false;
        } else {
            state = domain::AnalysisJobState::failed;
            termination.reason = classify_failure(failure.code);
            termination.coverage_complete = false;
            termination.results_complete = false;
        }
    };

    std::visit([&](auto&& request) {
        using T = std::decay_t<decltype(request)>;

        if constexpr (std::is_same_v<T, ExactScanRequest>) {
            auto result = service_.scan_exact(
                owner, request.pattern, request.alignment, byte_budget, request.result_limit,
                request.writable_only, request.start_address, request.end_address, cancellation, sink, true
            );
            if (!result) { finalize_domain_error(result.error()); return; }
            items->address_matches = std::move(result->matches);
            termination.reason = infer_sweep_reason(
                result->truncated, result->bytes_scanned, byte_budget, items->address_matches.size(), request.result_limit
            );
            termination.truncated = result->truncated;
            termination.coverage_complete = !result->truncated;
            termination.results_complete = !result->truncated;
            if (result->truncated) {
                termination.truncation_reasons.push_back(
                    termination.reason == domain::AnalysisStopReason::byte_budget
                        ? domain::AnalysisTruncationReason::byte_budget
                        : domain::AnalysisTruncationReason::result_limit
                );
                termination.next_start_address = result->stopped_at;
            }
        } else if constexpr (std::is_same_v<T, PointerScanRequest>) {
            auto result = service_.scan_pointers_to(
                owner, request.target, request.pointer_size, byte_budget, request.result_limit,
                request.writable_only, request.start_address, request.end_address, cancellation, sink, true
            );
            if (!result) { finalize_domain_error(result.error()); return; }
            items->address_matches = std::move(result->matches);
            termination.reason = infer_sweep_reason(
                result->truncated, result->bytes_scanned, byte_budget, items->address_matches.size(), request.result_limit
            );
            termination.truncated = result->truncated;
            termination.coverage_complete = !result->truncated;
            termination.results_complete = !result->truncated;
            if (result->truncated) {
                termination.truncation_reasons.push_back(
                    termination.reason == domain::AnalysisStopReason::byte_budget
                        ? domain::AnalysisTruncationReason::byte_budget
                        : domain::AnalysisTruncationReason::result_limit
                );
                termination.next_start_address = result->stopped_at;
            }
        } else if constexpr (std::is_same_v<T, StringScanRequest>) {
            auto result = service_.extract_strings(
                owner, request.min_length, request.encoding, byte_budget, request.result_limit,
                request.writable_only, request.start_address, request.end_address, cancellation, sink, true
            );
            if (!result) { finalize_domain_error(result.error()); return; }
            items->string_matches = std::move(result->matches);
            termination.reason = infer_sweep_reason(
                result->truncated, result->bytes_scanned, byte_budget, items->string_matches.size(), request.result_limit
            );
            termination.truncated = result->truncated;
            termination.coverage_complete = !result->truncated;
            termination.results_complete = !result->truncated;
            if (result->truncated) {
                termination.truncation_reasons.push_back(
                    termination.reason == domain::AnalysisStopReason::byte_budget
                        ? domain::AnalysisTruncationReason::byte_budget
                        : domain::AnalysisTruncationReason::result_limit
                );
                termination.next_start_address = result->stopped_at;
            }
        } else if constexpr (std::is_same_v<T, PointerChainScanRequest>) {
            auto result = service_.scan_pointer_chains(
                owner, request.target, request.pointer_size, request.max_depth, request.max_fanout,
                byte_budget, request.result_limit, request.writable_only, request.start_address,
                request.end_address, cancellation, sink, true
            );
            if (!result) { finalize_domain_error(result.error()); return; }
            items->pointer_chains = std::move(result->candidates);
            termination.reason = infer_sweep_reason(
                result->truncated, result->bytes_scanned, byte_budget, items->pointer_chains.size(), request.result_limit
            );
            termination.truncated = result->truncated;
            termination.coverage_complete = !result->truncated;
            termination.results_complete = !result->truncated;
            if (result->truncated) {
                // The BFS engine does not expose which specific cap (byte,
                // result, fanout or depth) bound first; byte/result are the
                // only two this wrapper can confirm numerically, so those map
                // directly and anything else falls back to result_limit.
                termination.truncation_reasons.push_back(
                    termination.reason == domain::AnalysisStopReason::byte_budget
                        ? domain::AnalysisTruncationReason::byte_budget
                        : domain::AnalysisTruncationReason::result_limit
                );
            }
        } else if constexpr (std::is_same_v<T, FirstScanRequest>) {
            auto result = service_.scan_first(
                owner, request.value_type, request.comparison, request.value, request.range,
                byte_budget, request.result_limit, request.writable_only, request.start_address,
                request.end_address, cancellation, sink, true
            );
            if (!result) { finalize_domain_error(result.error()); return; }
            const bool complete = result->coverage.complete();
            termination.coverage_complete = complete;
            termination.results_complete = complete;
            termination.truncated = !complete;
            if (!complete) {
                termination.reason = result->coverage.truncated_by_budget
                    ? domain::AnalysisStopReason::byte_budget
                    : domain::AnalysisStopReason::result_limit;
                termination.truncation_reasons.push_back(
                    result->coverage.truncated_by_budget
                        ? domain::AnalysisTruncationReason::byte_budget
                        : domain::AnalysisTruncationReason::result_limit
                );
            } else {
                termination.reason = domain::AnalysisStopReason::range_exhausted;
            }
            // Fetch the candidate addresses while the draft is still intact,
            // then discard the session itself unless the job fully completed
            // -- scan_first only ever publishes a scan_id backed by complete
            // coverage AND complete results (Spec 0008 "scan_first mantÃ©m
            // candidatos num draft transacional"). The underlying sync engine
            // always creates a session; a not-fully-complete job resets it to
            // empty rather than leaving retained candidates behind. See the
            // implementation report for the known limitation this leaves (the
            // now-empty session still occupies one scan-session quota slot
            // until the owning debug session detaches).
            auto page = service_.scan_results_page(
                result->info.id, 0U, std::min<std::size_t>(request.result_limit, policy_.max_async_job_result_items)
            );
            if (page) {
                items->value_matches = std::move(page->matches);
            }
            if (complete) {
                items->published_session = result->info;
            } else {
                (void)service_.scan_reset(result->info.id);
            }
        } else if constexpr (std::is_same_v<T, NextScanRequest>) {
            auto result = service_.scan_next(request.scan_id, request.comparison, request.value, request.delta, cancellation, sink, true);
            if (!result) { finalize_domain_error(result.error()); return; }
            // scan_next always processes every candidate in one pass (no
            // byte_budget/coverage concept applies); reaching this point
            // without a cancelled error means it committed the new
            // generation already (Spec 0008 "scan_next mantÃ©m a geraÃ§Ã£o
            // original intacta... e sÃ³ faz o replace... quando completo").
            termination.reason = domain::AnalysisStopReason::operation_completed;
            termination.coverage_complete = true;
            termination.results_complete = true;
            termination.truncated = false;
            items->published_session = *result;
            auto page = service_.scan_results_page(
                result->id, 0U, std::min<std::size_t>(result->candidate_count + 1U, policy_.max_async_job_result_items)
            );
            if (page) {
                items->value_matches = std::move(page->matches);
            }
        }
    }, job->request);

    shrink_items(*items);
    const std::size_t requested_bytes = items_retained_bytes(*items);
    const auto now = clock_();

    // Registry lock outer, job lock inner -- the same nesting order
    // detach_session()/release()/the destructor already use, never reversed
    // (see retained_bytes_'s declaration comment in the header). Needed here
    // because reserving from the global retained-bytes budget has to be
    // atomic with publishing this job's own result.
    std::scoped_lock lock(mutex_);
    std::scoped_lock job_lock(job->mutex);

    std::size_t reserved_bytes = requested_bytes;
    const std::size_t available = retained_bytes_ < policy_.max_async_results_retained_bytes
        ? policy_.max_async_results_retained_bytes - retained_bytes_
        : 0U;
    if (requested_bytes > available) {
        // The global cap (summed across every retained job, not per job --
        // see SecurityPolicy::max_async_results_retained_bytes) does not have
        // room for everything this job found. Keep as large a prefix as
        // fits and mark the loss the same way any other partial retention is
        // marked, reusing AnalysisJobTermination's existing truncated /
        // truncation_reasons vocabulary rather than inventing a separate
        // rejection state. published_session's own small, fixed cost is
        // reserved first and never trimmed away -- dropping it would orphan
        // an already-created scan session that scan_next could otherwise
        // still reach, so in the extreme case where even that fixed cost
        // does not fit, the budget is allowed a bounded, sizeof(ScanSessionInfo)
        // -- not scan-size-dependent -- overshoot rather than losing the
        // session's continuation handle.
        const std::size_t session_cost =
            items->published_session ? session_info_bytes(*items->published_session) : 0U;
        const std::size_t budget_for_matches = available > session_cost ? available - session_cost : 0U;
        std::size_t matches_bytes = 0U;
        if (!items->address_matches.empty()) {
            matches_bytes = truncate_to_budget(items->address_matches, budget_for_matches);
        } else if (!items->string_matches.empty()) {
            matches_bytes = truncate_to_budget(items->string_matches, budget_for_matches);
        } else if (!items->pointer_chains.empty()) {
            matches_bytes = truncate_to_budget(items->pointer_chains, budget_for_matches);
        } else if (!items->value_matches.empty()) {
            matches_bytes = truncate_to_budget(items->value_matches, budget_for_matches);
        }
        reserved_bytes = matches_bytes + session_cost;
        termination.truncated = true;
        termination.results_complete = false;
        termination.truncation_reasons.push_back(domain::AnalysisTruncationReason::retained_bytes_budget);
    }

    retained_bytes_ += reserved_bytes;
    job->retained_bytes = reserved_bytes;
    job->state = state;
    job->termination = termination;
    job->result = std::move(items);
    job->terminal_at = now;
}

void AnalysisJobManager::worker_loop(std::stop_token worker_token) {
    while (true) {
        std::shared_ptr<JobRecord> job;
        {
            std::unique_lock lock(mutex_);
            wake_workers_.wait(lock, worker_token, [&] { return !pending_.empty(); });
            if (worker_token.stop_requested() && pending_.empty()) {
                return;
            }
            // Pick the first queued job whose owner has no job running yet --
            // a global FIFO with a per-session concurrency cap of one, so one
            // busy session cannot head-of-line-block every other session's
            // queued work (Spec 0008 "no mÃ¡ximo um scan longo running por
            // sessÃ£o").
            auto pick = pending_.end();
            for (auto it = pending_.begin(); it != pending_.end(); ++it) {
                const auto job_it = jobs_.find(*it);
                if (job_it == jobs_.end()) continue;
                if (!running_owners_.contains(job_it->second->owner.value())) {
                    pick = it;
                    break;
                }
            }
            if (pick == pending_.end()) {
                // Every queued job's session is already running one. Wait for
                // a state change instead of busy-spinning.
                session_drained_.wait_for(lock, std::chrono::milliseconds(50));
                continue;
            }
            const auto job_it = jobs_.find(*pick);
            job = job_it->second;
            pending_.erase(pick);
            running_owners_.insert(job->owner.value());
        }
        {
            std::scoped_lock job_lock(job->mutex);
            job->state = domain::AnalysisJobState::running;
        }
        run_job(job);
        {
            std::scoped_lock lock(mutex_);
            running_owners_.erase(job->owner.value());
        }
        session_drained_.notify_all();
        wake_workers_.notify_one();
    }
}

}  // namespace argos::application
