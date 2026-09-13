#pragma once

#include "argos_mcp/domain/santa_monica_dispatcher.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// The bridge-side command service (Spec 0014 stage 4): the exact logic the
// injected DLL runs to turn one command frame into one result frame. It owns an
// EngineDispatcher over a native EngineFunctionTable and drives the codec; it
// installs no hook and speaks no transport itself, so it is fully testable over
// byte buffers. The real DLL wraps this with a named-pipe read/write loop
// (LocalBridgeChannel) after the handshake and calls `run` from the IPC thread
// while the game's main thread pumps the dispatcher's tick.
namespace argos::infrastructure::santamonica {

namespace sm = domain::santamonica;

class EngineBridgeService {
public:
    explicit EngineBridgeService(
        sm::EngineFunctionTable& table, sm::EngineDispatcherLimits limits = {});

    // Decode one command frame (bound to request_id/sequence), admit it, run it
    // to a terminal state on the calling thread, and return the encoded result
    // frame carrying the same request_id/sequence. A completed, failed or
    // outcome_unknown run all produce a result frame; only a malformed frame or
    // a refused admission (not allowlisted, signature mismatch, busy, conflict)
    // returns a typed error for the transport to surface.
    [[nodiscard]] domain::Result<std::vector<std::byte>> run(
        std::span<const std::byte> command_frame, std::uint64_t request_id, std::uint64_t sequence);

    // Direct access for a transport that separates admission from execution
    // (IPC thread submits, main thread ticks). `run` is the synchronous
    // convenience used in tests and simple loops.
    [[nodiscard]] sm::EngineDispatcher& dispatcher() noexcept { return dispatcher_; }

private:
    sm::EngineDispatcher dispatcher_;
};

}  // namespace argos::infrastructure::santamonica
