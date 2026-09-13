// Loads the built argos_debug_bridge.dll the way an injection does (LoadLibrary
// is exactly what a CreateRemoteThread+LoadLibrary injector triggers in the
// target) and drives its C ABI: submit on the IPC side, tick on the main side,
// poll the effect, and run a raw codec-built command frame end to end. This
// validates the injected-module code path without a second process.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <span>
#include <vector>

#ifndef ARGOS_DEBUG_BRIDGE_DLL
#error "ARGOS_DEBUG_BRIDGE_DLL path must be defined by the build"
#endif

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

using StartupFn = int (*)();
using ShutdownFn = void (*)();
using SubmitAddFn = int (*)(long long, char*, unsigned);
using TickFn = int (*)();
using PollFn = long long (*)();
using RunFn = int (*)(const unsigned char*, unsigned, unsigned long long, unsigned long long,
                      unsigned char*, unsigned*);

}  // namespace

int main() {
    const HMODULE module = LoadLibraryA(ARGOS_DEBUG_BRIDGE_DLL);
    if (module == nullptr) {
        std::cerr << "FAIL: could not load " << ARGOS_DEBUG_BRIDGE_DLL << " (err "
                  << GetLastError() << ")\n";
        return 1;
    }

    auto startup = reinterpret_cast<StartupFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgeStartup")));
    auto shutdown = reinterpret_cast<ShutdownFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgeShutdown")));
    auto submit_add = reinterpret_cast<SubmitAddFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgeSubmitAdd")));
    auto tick = reinterpret_cast<TickFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgeTick")));
    auto poll = reinterpret_cast<PollFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgePollBalance")));
    auto run = reinterpret_cast<RunFn>(
        reinterpret_cast<void*>(GetProcAddress(module, "Argos_BridgeRun")));

    check(startup && shutdown && submit_add && tick && poll && run, "all bridge exports resolve");
    if (!(startup && shutdown && submit_add && tick && poll && run)) {
        FreeLibrary(module);
        return 1;
    }

    check(startup() == 0, "startup succeeds");

    // IPC side submits; main side ticks. The effect must apply exactly once.
    std::array<char, 64> op{};
    check(submit_add(50, op.data(), static_cast<unsigned>(op.size())) == 0, "AddResource(50) admitted");
    check(op[0] != '\0', "an operation id was returned");
    check(tick() == 1, "the tick runs the queued operation");
    check(tick() == 0, "a second tick has nothing to do");
    check(poll() == 50, "the demo effect ran once on the tick thread");

    // Raw per-command entrypoint: a codec-built command frame in, result out.
    EngineInvokeRequest request{FunctionKey{1}, {EngineArgument{EngineValueKind::integer, 25, 0.0, false, {}}},
                                "run-key"};
    const auto frame = infra::encode_invoke_command(request, 1, 1);
    check(frame.has_value(), "server encodes a raw command frame");
    if (frame) {
        std::vector<unsigned char> out(256);
        unsigned out_len = static_cast<unsigned>(out.size());
        const int rc = run(reinterpret_cast<const unsigned char*>(frame->data()),
                           static_cast<unsigned>(frame->size()), 1, 1, out.data(), &out_len);
        check(rc == 0, "raw command runs");
        if (rc == 0) {
            const std::span<const std::byte> result_frame{
                reinterpret_cast<const std::byte*>(out.data()), out_len};
            const auto result = infra::decode_invoke_result(result_frame, 1, 1);
            check(result && result->state == EngineOperationState::completed, "raw result completed");
            check(result && result->integer == 75, "raw command applied on top of the prior balance");
        }
        check(poll() == 75, "the raw command's effect is visible");
    }

    shutdown();
    FreeLibrary(module);
    if (failures != 0) std::cerr << failures << " debug bridge load test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
