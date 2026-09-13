#include "argos_mcp/infrastructure/santa_monica_bridge_service.hpp"

#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;

// One command is one op; a single tick runs it. A small bound tolerates a
// cancelled/vanished front ahead of it without ever spinning unbounded.
constexpr int max_ticks = 8;

}  // namespace

EngineBridgeService::EngineBridgeService(
    sm::EngineFunctionTable& table, const sm::EngineDispatcherLimits limits)
    : dispatcher_(table, limits) {}

domain::Result<std::vector<std::byte>> EngineBridgeService::run(
    const std::span<const std::byte> command_frame, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    auto request = decode_invoke_command(command_frame, request_id, sequence);
    if (!request) return std::unexpected(request.error());

    auto operation_id = dispatcher_.submit(*request);
    if (!operation_id) return std::unexpected(operation_id.error());

    for (int attempt = 0; attempt < max_ticks; ++attempt) {
        const auto record = dispatcher_.status(*operation_id);
        if (record && sm::is_terminal(record->state)) break;
        if (!dispatcher_.tick()) break;
    }

    const auto record = dispatcher_.status(*operation_id);
    if (!record) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_state, "operation record vanished", "results_expired"});
    }
    if (!sm::is_terminal(record->state)) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_state, "operation did not reach a terminal state", "not_terminal"});
    }

    sm::EngineInvokeResult result;
    if (record->result) {
        result = *record->result;
    } else {
        // failed / outcome_unknown carry no value; report the state with an
        // integer placeholder so the frame is well-formed.
        result.state = record->state;
        result.return_kind = sm::EngineValueKind::integer;
    }
    result.state = record->state;
    return encode_invoke_result(result, request_id, sequence);
}

}  // namespace argos::infrastructure::santamonica
