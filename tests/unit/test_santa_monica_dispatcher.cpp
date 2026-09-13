#include "argos_mcp/domain/santa_monica_dispatcher.hpp"

#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// A fake engine: an allowlisted "AddResource(i,i)->i" that mutates an in-process
// counter, plus a "Fail()->i" and a "PartialCommit()->i" to exercise the
// failed / outcome_unknown paths. Anything else is not allowlisted.
class FakeTable final : public EngineFunctionTable {
public:
    std::int64_t balance{0};
    int calls{0};

    [[nodiscard]] std::optional<SliFunctionRecord> lookup(const FunctionKey id) const override {
        switch (id.value) {
            case 1: return SliFunctionRecord{id, "AddResource", "i_ii"};
            case 2: return SliFunctionRecord{id, "Fail", "i"};
            case 3: return SliFunctionRecord{id, "PartialCommit", "i"};
            default: return std::nullopt;
        }
    }

    [[nodiscard]] Result<EngineInvokeResult> invoke(
        const EngineInvokePlan& plan, const std::span<const EngineArgument> arguments) override {
        ++calls;
        if (plan.function_id.value == 2) {
            return std::unexpected(DebugError{DebugErrorCode::io_error, "native failure", "engine_error"});
        }
        if (plan.function_id.value == 3) {
            return std::unexpected(DebugError{DebugErrorCode::invalid_state, "half done", "effect_started"});
        }
        balance += arguments[0].integer + arguments[1].integer;
        return EngineInvokeResult{EngineOperationState::completed, EngineValueKind::integer, balance,
                                  0.0, false, {}, 5};
    }
};

EngineArgument arg_i(const std::int64_t value) {
    return EngineArgument{EngineValueKind::integer, value, 0.0, false, {}};
}

EngineInvokeRequest add_request(std::string key, const std::int64_t a, const std::int64_t b) {
    return EngineInvokeRequest{FunctionKey{1}, {arg_i(a), arg_i(b)}, std::move(key)};
}

void test_happy_path() {
    FakeTable table;
    EngineDispatcher dispatcher{table};

    const auto op = dispatcher.submit(add_request("k1", 40, 60));
    check(op.has_value(), "a valid request is admitted");
    check(dispatcher.pending() == 1, "one operation pending before the tick");

    const auto before = dispatcher.status(*op);
    check(before && before->state == EngineOperationState::queued, "operation starts queued");

    check(dispatcher.tick(), "tick runs the queued operation");
    check(!dispatcher.tick(), "a second tick has nothing to do");
    check(table.calls == 1, "the native function ran exactly once");

    const auto after = dispatcher.status(*op);
    check(after && after->state == EngineOperationState::completed, "operation completed");
    check(after && after->result && after->result->integer == 100, "result carries the new balance");
    check(table.balance == 100, "the effect was applied once");
}

void test_idempotency() {
    FakeTable table;
    EngineDispatcher dispatcher{table};

    const auto first = dispatcher.submit(add_request("dup", 1, 2));
    const auto second = dispatcher.submit(add_request("dup", 1, 2));
    check(first && second && *first == *second, "same key and content dedups to one operation");
    check(dispatcher.pending() == 1, "the duplicate did not enqueue a second operation");

    const auto conflict = dispatcher.submit(add_request("dup", 9, 9));
    check(!conflict && conflict.error().reason == "idempotency_conflict",
          "same key with new content is a conflict");

    dispatcher.tick();
    check(table.balance == 3, "only the first content ran");

    // After completion the key still dedups to the terminal record.
    const auto replay = dispatcher.submit(add_request("dup", 1, 2));
    check(replay && *replay == *first, "a replay after completion returns the terminal operation");
    check(table.calls == 1, "the replay did not run the function again");
}

void test_busy_and_queue() {
    FakeTable table;
    EngineDispatcher dispatcher{table};
    const auto first = dispatcher.submit(add_request("a", 1, 1));
    check(first.has_value(), "first admitted");
    const auto second = dispatcher.submit(add_request("b", 2, 2));
    check(!second && second.error().reason == "busy", "a distinct op while one is in flight is busy");
    dispatcher.tick();
    const auto third = dispatcher.submit(add_request("c", 3, 3));
    check(third.has_value(), "after the first completes, a new op is admitted");
}

void test_failure_and_unknown() {
    FakeTable table;
    EngineDispatcher dispatcher{table};

    const auto fail_op = dispatcher.submit(EngineInvokeRequest{FunctionKey{2}, {}, "f"});
    check(fail_op.has_value(), "fail op admitted");
    dispatcher.tick();
    const auto fail_status = dispatcher.status(*fail_op);
    check(fail_status && fail_status->state == EngineOperationState::failed, "clean failure is failed");
    check(fail_status && fail_status->error && fail_status->error->reason == "engine_error",
          "failure carries the typed reason");

    const auto unknown_op = dispatcher.submit(EngineInvokeRequest{FunctionKey{3}, {}, "u"});
    check(unknown_op.has_value(), "partial op admitted");
    dispatcher.tick();
    const auto unknown_status = dispatcher.status(*unknown_op);
    check(unknown_status && unknown_status->state == EngineOperationState::outcome_unknown,
          "a started-but-unconfirmed effect is outcome_unknown");
}

void test_rejections_and_cancel() {
    FakeTable table;
    EngineDispatcher dispatcher{table};

    const auto denied = dispatcher.submit(EngineInvokeRequest{FunctionKey{99}, {}, "x"});
    check(!denied && denied.error().reason == "not_allowlisted",
          "a function outside the allowlist is denied");

    const auto bad_args = dispatcher.submit(EngineInvokeRequest{FunctionKey{1}, {arg_i(1)}, "y"});
    check(!bad_args && bad_args.error().reason == "signature_mismatch",
          "wrong arity is rejected against the allowlisted signature");

    const auto op = dispatcher.submit(add_request("z", 1, 1));
    check(op.has_value(), "op admitted for cancel");
    check(dispatcher.cancel(*op).has_value(), "a queued op cancels");
    check(!dispatcher.tick(), "a cancelled op is not run");
    check(table.calls == 0, "the cancelled function never executed");
    const auto cancelled = dispatcher.status(*op);
    check(cancelled && cancelled->state == EngineOperationState::cancelled, "state is cancelled");
}

}  // namespace

int main() {
    test_happy_path();
    test_idempotency();
    test_busy_and_queue();
    test_failure_and_unknown();
    test_rejections_and_cancel();
    if (failures != 0) std::cerr << failures << " Santa Monica dispatcher test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
