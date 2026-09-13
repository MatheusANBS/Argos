#pragma once

#include "argos_mcp/domain/santa_monica_invoke.hpp"
#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// The dispatcher core (Spec 0014 §"Execução no processo"): the thread-discipline
// and bookkeeping that let one engine call cross from the server/IPC thread onto
// the game's main thread and back, without ever calling the engine off that
// thread. It is deliberately pure -- it owns no OS handle, hook or transport and
// resolves/executes a function only through an injected EngineFunctionTable
// port. The real bridge backs that port with native SLI pointers; a test backs
// it with an in-process struct. `submit` is called from the IPC thread and
// `tick` from the main thread, so a mutex guards the shared registry.
namespace argos::domain::santamonica {

// A completed or in-flight operation. `result` is present exactly when `state`
// is `completed`; `error` is present for `failed`. `outcome_unknown` carries
// neither -- an effect may have happened and cannot be confirmed here.
struct EngineOperationRecord {
    std::string operation_id;
    std::string idempotency_key;
    EngineOperationState state{EngineOperationState::queued};
    std::optional<EngineInvokeResult> result;
    std::optional<DebugError> error;
};

// Port: resolves an allowlisted function and runs it ON THE CALLING THREAD. The
// dispatcher calls `invoke` only from `tick`, so an implementation may touch the
// engine directly. Returning an error whose reason is "effect_started" tells the
// dispatcher the call began a mutation it could not confirm, which becomes
// `outcome_unknown`; any other error is a clean `failed` with no effect.
class EngineFunctionTable {
public:
    virtual ~EngineFunctionTable() = default;
    // nullopt means "not allowlisted for invocation"; the request is refused.
    [[nodiscard]] virtual std::optional<SliFunctionRecord> lookup(FunctionKey id) const = 0;
    [[nodiscard]] virtual Result<EngineInvokeResult> invoke(
        const EngineInvokePlan& plan, std::span<const EngineArgument> arguments) = 0;
};

// A concrete table built by registering allowlisted functions before use. The
// real bridge registers native thunks that call SLI pointers on the main thread;
// a test registers plain lambdas. Registration must complete before the first
// submit/tick, after which lookups and invokes are read-only and thread-safe.
class RegisteredFunctionTable final : public EngineFunctionTable {
public:
    using Callable =
        std::function<Result<EngineInvokeResult>(const EngineInvokePlan&, std::span<const EngineArgument>)>;

    // Registering the same id twice replaces the earlier entry. The record's id
    // must equal `record.id`; the signature is what `plan_engine_invoke` matches.
    void register_function(SliFunctionRecord record, Callable callable);

    [[nodiscard]] std::optional<SliFunctionRecord> lookup(FunctionKey id) const override;
    [[nodiscard]] Result<EngineInvokeResult> invoke(
        const EngineInvokePlan& plan, std::span<const EngineArgument> arguments) override;

    [[nodiscard]] std::size_t size() const noexcept { return functions_.size(); }

private:
    struct Entry {
        SliFunctionRecord record;
        Callable callable;
    };
    std::unordered_map<std::uint64_t, Entry> functions_;
};

struct EngineDispatcherLimits {
    std::size_t max_queue{16};        // Pending + at most one active.
    std::size_t max_tombstones{64};   // Terminal records kept for dedup/status.
};

class EngineDispatcher final {
public:
    explicit EngineDispatcher(EngineFunctionTable& table, EngineDispatcherLimits limits = {});
    EngineDispatcher(const EngineDispatcher&) = delete;
    EngineDispatcher& operator=(const EngineDispatcher&) = delete;

    // IPC thread. Validates the request against the allowlisted signature and
    // admits it. A repeated (key, content) returns the same operation id; a key
    // reused with different content is `idempotency_conflict`; a second distinct
    // operation while one is still in flight is `invalid_state`/"busy".
    [[nodiscard]] Result<std::string> submit(const EngineInvokeRequest& request);

    // Main thread. Runs at most one queued operation to a terminal state and
    // returns true iff it did work. Never blocks on I/O.
    bool tick();

    [[nodiscard]] Result<EngineOperationRecord> status(std::string_view operation_id) const;
    [[nodiscard]] std::optional<EngineOperationRecord> status_by_key(std::string_view key) const;

    // Cancels a still-queued operation (never one whose effect may have started).
    [[nodiscard]] Result<void> cancel(std::string_view operation_id);

    [[nodiscard]] std::size_t pending() const;

private:
    struct Entry {
        EngineOperationRecord record;
        EngineInvokePlan plan;
        std::vector<EngineArgument> arguments;
        std::string content_signature;
    };

    [[nodiscard]] bool has_active_locked() const;
    void retire_locked(const std::string& key);

    EngineFunctionTable& table_;
    EngineDispatcherLimits limits_;
    mutable std::mutex mutex_;
    std::uint64_t next_id_{1};
    std::unordered_map<std::string, Entry> entries_;      // by operation_id
    std::unordered_map<std::string, std::string> by_key_; // idempotency_key -> operation_id
    std::deque<std::string> queue_;                       // operation_ids, FIFO
    std::deque<std::string> tombstones_;                  // terminal keys, FIFO for eviction
};

// Stable content signature for idempotency-conflict detection: the function id
// and every argument's kind and value, independent of map ordering or padding.
[[nodiscard]] std::string engine_invoke_signature(const EngineInvokeRequest& request);

}  // namespace argos::domain::santamonica
