#include "argos_mcp/domain/santa_monica_dispatcher.hpp"

#include <bit>
#include <utility>

namespace argos::domain::santamonica {
namespace {

void append_u64(std::string& out, const std::uint64_t value) {
    for (std::size_t index = 0; index < 8U; ++index) {
        out.push_back(static_cast<char>(static_cast<unsigned char>((value >> (8U * index)) & 0xFFU)));
    }
}

}  // namespace

std::string engine_invoke_signature(const EngineInvokeRequest& request) {
    std::string signature;
    append_u64(signature, request.function_id.value);
    append_u64(signature, request.arguments.size());
    for (const EngineArgument& argument : request.arguments) {
        signature.push_back(static_cast<char>(static_cast<unsigned char>(to_string(argument.kind).front())));
        switch (argument.kind) {
            case EngineValueKind::integer:
                append_u64(signature, static_cast<std::uint64_t>(argument.integer));
                break;
            case EngineValueKind::floating:
                append_u64(signature, std::bit_cast<std::uint64_t>(argument.floating));
                break;
            case EngineValueKind::boolean:
                signature.push_back(argument.boolean ? '1' : '0');
                break;
            case EngineValueKind::text:
                append_u64(signature, argument.text.size());
                signature.append(argument.text);
                break;
        }
    }
    return signature;
}

void RegisteredFunctionTable::register_function(SliFunctionRecord record, Callable callable) {
    const std::uint64_t id = record.id.value;
    functions_.insert_or_assign(id, Entry{std::move(record), std::move(callable)});
}

std::optional<SliFunctionRecord> RegisteredFunctionTable::lookup(const FunctionKey id) const {
    const auto it = functions_.find(id.value);
    if (it == functions_.end()) return std::nullopt;
    return it->second.record;
}

Result<EngineInvokeResult> RegisteredFunctionTable::invoke(
    const EngineInvokePlan& plan, const std::span<const EngineArgument> arguments) {
    const auto it = functions_.find(plan.function_id.value);
    if (it == functions_.end() || !it->second.callable) {
        return std::unexpected(DebugError{
            DebugErrorCode::not_found, "function is not registered", "not_registered"});
    }
    return it->second.callable(plan, arguments);
}

EngineDispatcher::EngineDispatcher(EngineFunctionTable& table, const EngineDispatcherLimits limits)
    : table_(table), limits_(limits) {}

bool EngineDispatcher::has_active_locked() const {
    for (const std::string& id : queue_) {
        const auto it = entries_.find(id);
        if (it != entries_.end() && !is_terminal(it->second.record.state)) return true;
    }
    return false;
}

void EngineDispatcher::retire_locked(const std::string& key) {
    tombstones_.push_back(key);
    while (tombstones_.size() > limits_.max_tombstones) {
        const std::string oldest = std::move(tombstones_.front());
        tombstones_.pop_front();
        if (const auto mapped = by_key_.find(oldest); mapped != by_key_.end()) {
            entries_.erase(mapped->second);
            by_key_.erase(mapped);
        }
    }
}

Result<std::string> EngineDispatcher::submit(const EngineInvokeRequest& request) {
    const auto function = table_.lookup(request.function_id);
    if (!function) {
        return std::unexpected(DebugError{
            DebugErrorCode::access_denied, "function is not allowlisted", "not_allowlisted"});
    }
    auto plan = plan_engine_invoke(*function, request);
    if (!plan) return std::unexpected(plan.error());

    const std::string signature = engine_invoke_signature(request);

    const std::lock_guard lock{mutex_};

    if (const auto existing = by_key_.find(request.idempotency_key); existing != by_key_.end()) {
        const auto entry = entries_.find(existing->second);
        if (entry == entries_.end()) {
            return std::unexpected(DebugError{
                DebugErrorCode::invalid_state, "operation record expired", "results_expired"});
        }
        if (entry->second.content_signature != signature) {
            return std::unexpected(DebugError{
                DebugErrorCode::invalid_argument, "idempotency key reused with new content",
                "idempotency_conflict"});
        }
        return entry->second.record.operation_id;  // Faithful dedup: same op.
    }

    if (has_active_locked()) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_state, "another operation is in flight", "busy"});
    }
    if (queue_.size() >= limits_.max_queue) {
        return std::unexpected(DebugError{
            DebugErrorCode::limit_exceeded, "operation queue is full", "queue_full"});
    }

    std::string operation_id = "op-" + std::to_string(next_id_++);
    Entry entry;
    entry.record.operation_id = operation_id;
    entry.record.idempotency_key = request.idempotency_key;
    entry.record.state = EngineOperationState::queued;
    entry.plan = *plan;
    entry.arguments = request.arguments;
    entry.content_signature = signature;

    by_key_.emplace(request.idempotency_key, operation_id);
    queue_.push_back(operation_id);
    entries_.emplace(operation_id, std::move(entry));
    return operation_id;
}

bool EngineDispatcher::tick() {
    std::string operation_id;
    {
        const std::lock_guard lock{mutex_};
        while (!queue_.empty()) {
            const std::string& front = queue_.front();
            const auto it = entries_.find(front);
            if (it == entries_.end()) {
                queue_.pop_front();  // Cancelled and erased.
                continue;
            }
            if (it->second.record.state == EngineOperationState::cancelled) {
                queue_.pop_front();
                continue;
            }
            // A non-queued front means another tick is mid-flight. tick() is
            // single-threaded by contract (one main-thread owner), so this only
            // guards against accidental re-entry and never double-runs a call.
            if (it->second.record.state != EngineOperationState::queued) return false;
            operation_id = front;
            it->second.record.state = EngineOperationState::running;
            break;
        }
        if (operation_id.empty()) return false;
    }

    // Snapshot the work under the lock, then run the native call unlocked so a
    // slow engine callback never blocks submit/status. The op is pinned in
    // `running` and cannot be popped or cancelled while it runs.
    EngineInvokePlan plan;
    std::vector<EngineArgument> arguments;
    {
        const std::lock_guard lock{mutex_};
        const auto it = entries_.find(operation_id);
        if (it == entries_.end()) return true;  // Vanished; nothing to do.
        plan = it->second.plan;
        arguments = it->second.arguments;
        it->second.record.state = EngineOperationState::commit_in_progress;
    }

    Result<EngineInvokeResult> outcome = table_.invoke(plan, arguments);

    const std::lock_guard lock{mutex_};
    const auto it = entries_.find(operation_id);
    if (it == entries_.end()) return true;
    if (outcome) {
        it->second.record.state = EngineOperationState::completed;
        it->second.record.result = std::move(*outcome);
    } else if (outcome.error().reason == "effect_started") {
        it->second.record.state = EngineOperationState::outcome_unknown;
    } else {
        it->second.record.state = EngineOperationState::failed;
        it->second.record.error = outcome.error();
    }
    if (!queue_.empty() && queue_.front() == operation_id) queue_.pop_front();
    retire_locked(it->second.record.idempotency_key);
    return true;
}

Result<EngineOperationRecord> EngineDispatcher::status(const std::string_view operation_id) const {
    const std::lock_guard lock{mutex_};
    const auto it = entries_.find(std::string{operation_id});
    if (it == entries_.end()) {
        return std::unexpected(DebugError{DebugErrorCode::not_found, "no such operation", "not_found"});
    }
    return it->second.record;
}

std::optional<EngineOperationRecord> EngineDispatcher::status_by_key(const std::string_view key) const {
    const std::lock_guard lock{mutex_};
    const auto mapped = by_key_.find(std::string{key});
    if (mapped == by_key_.end()) return std::nullopt;
    const auto it = entries_.find(mapped->second);
    if (it == entries_.end()) return std::nullopt;
    return it->second.record;
}

Result<void> EngineDispatcher::cancel(const std::string_view operation_id) {
    const std::lock_guard lock{mutex_};
    const auto it = entries_.find(std::string{operation_id});
    if (it == entries_.end()) {
        return std::unexpected(DebugError{DebugErrorCode::not_found, "no such operation", "not_found"});
    }
    if (it->second.record.state != EngineOperationState::queued) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_state, "operation already started", "not_cancellable"});
    }
    it->second.record.state = EngineOperationState::cancelled;
    retire_locked(it->second.record.idempotency_key);
    return {};
}

std::size_t EngineDispatcher::pending() const {
    const std::lock_guard lock{mutex_};
    std::size_t count = 0;
    for (const std::string& id : queue_) {
        const auto it = entries_.find(id);
        if (it != entries_.end() && !is_terminal(it->second.record.state)) ++count;
    }
    return count;
}

}  // namespace argos::domain::santamonica
