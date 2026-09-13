#include "argos_mcp/domain/santa_monica_dispatcher.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_service.hpp"
#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// Stand-in for the game state the native bridge would mutate on the main thread.
struct FakeGame {
    std::int64_t resource{0};
};

// Builds a table the way the real bridge would: one allowlisted AddResource
// bound to a native effect. Here the "native" effect is a struct write.
RegisteredFunctionTable make_table(FakeGame& game) {
    RegisteredFunctionTable table;
    table.register_function(
        SliFunctionRecord{FunctionKey{1}, "AddResource", "i_i"},
        [&game](const EngineInvokePlan&, std::span<const EngineArgument> args)
            -> Result<EngineInvokeResult> {
            game.resource += args[0].integer;
            return EngineInvokeResult{EngineOperationState::completed, EngineValueKind::integer,
                                      game.resource, 0.0, false, {}, 3};
        });
    return table;
}

EngineArgument arg_i(const std::int64_t value) {
    return EngineArgument{EngineValueKind::integer, value, 0.0, false, {}};
}

void test_end_to_end() {
    FakeGame game;
    auto table = make_table(game);
    infra::EngineBridgeService service{table};

    // Server side: encode a command frame.
    EngineInvokeRequest request{FunctionKey{1}, {arg_i(50)}, "grant-1"};
    const auto command = infra::encode_invoke_command(request, 100, 1);
    check(command.has_value(), "server encodes the command frame");
    if (!command) return;

    // Bridge side: decode, dispatch on this thread, encode the result frame.
    const auto result_frame = service.run(*command, 100, 1);
    check(result_frame.has_value(), "bridge produces a result frame");
    if (!result_frame) return;
    check(game.resource == 50, "the native effect ran exactly once");

    // Server side: decode the result frame.
    const auto result = infra::decode_invoke_result(*result_frame, 100, 1);
    check(result.has_value(), "server decodes the result frame");
    check(result && result->state == EngineOperationState::completed, "result state is completed");
    check(result && result->return_kind == EngineValueKind::integer && result->integer == 50,
          "result carries the new balance");
    check(result && result->duration_us == 3, "result carries the reported duration");
}

void test_replay_is_idempotent() {
    FakeGame game;
    auto table = make_table(game);
    infra::EngineBridgeService service{table};

    EngineInvokeRequest request{FunctionKey{1}, {arg_i(7)}, "grant-once"};
    const auto command = infra::encode_invoke_command(request, 5, 1);
    check(command.has_value(), "command encodes");
    if (!command) return;

    const auto first = service.run(*command, 5, 1);
    const auto second = service.run(*command, 5, 1);  // Retried delivery, same op.
    check(first && second, "both deliveries produce a result frame");
    check(game.resource == 7, "the effect ran only once despite the replay");
}

void test_not_allowlisted_frame() {
    FakeGame game;
    auto table = make_table(game);
    infra::EngineBridgeService service{table};

    EngineInvokeRequest request{FunctionKey{42}, {}, "nope"};
    const auto command = infra::encode_invoke_command(request, 9, 1);
    check(command.has_value(), "a syntactically valid command for an unknown function encodes");
    if (!command) return;

    const auto result = service.run(*command, 9, 1);
    check(!result && result.error().reason == "not_allowlisted",
          "the bridge refuses a function outside the allowlist");
    check(game.resource == 0, "nothing ran");
}

void test_bad_sequence_frame() {
    FakeGame game;
    auto table = make_table(game);
    infra::EngineBridgeService service{table};

    EngineInvokeRequest request{FunctionKey{1}, {arg_i(1)}, "k"};
    const auto command = infra::encode_invoke_command(request, 3, 1);
    if (!command) {
        check(false, "command encodes");
        return;
    }
    const auto result = service.run(*command, 3, 2);  // Expected sequence 2, frame carries 1.
    check(!result, "a frame whose sequence does not match is rejected before dispatch");
    check(game.resource == 0, "a rejected frame runs nothing");
}

}  // namespace

int main() {
    test_end_to_end();
    test_replay_is_idempotent();
    test_not_allowlisted_frame();
    test_bad_sequence_frame();
    if (failures != 0) std::cerr << failures << " Santa Monica bridge service test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
