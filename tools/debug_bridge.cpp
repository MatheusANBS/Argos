// Argos debug bridge (ADR-0021 injection lifecycle, Spec 0014 stage 4).
//
// DllMain still does no work: loading the module must be inert. Everything runs
// through an explicit C ABI the host drives after the module is present. This
// build wraps the tested EngineBridgeService (decode command -> dispatch on the
// main thread -> encode result) with a small demo function table so the loaded
// module can be exercised end to end against the controlled target
// `argos_debug_target_game`. It is NOT the production bridge: it installs no
// hook, speaks no authenticated transport, and its allowlist is a demo
// AddResource over an internal counter, not real SLI thunks. The named-pipe
// channel, handshake and secret bootstrap into an injected module remain a
// separate, security-reviewed deliverable.
//
// Thread model mirrors the real bridge: `Argos_BridgeSubmit*` is the IPC side
// and `Argos_BridgeTick` is the main-thread side, so the host pumps the tick
// from the same thread that owns the game.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "argos_mcp/domain/santa_monica_dispatcher.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_service.hpp"
#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

namespace {

using argos::domain::santamonica::EngineArgument;
using argos::domain::santamonica::EngineInvokePlan;
using argos::domain::santamonica::EngineInvokeRequest;
using argos::domain::santamonica::EngineInvokeResult;
using argos::domain::santamonica::EngineOperationState;
using argos::domain::santamonica::EngineValueKind;
using argos::domain::santamonica::FunctionKey;
using argos::domain::santamonica::RegisteredFunctionTable;
using argos::domain::santamonica::SliFunctionRecord;
using argos::infrastructure::santamonica::EngineBridgeService;

// All mutable module state lives behind one function-local singleton so there is
// no namespace-scope mutable global. `balance` is atomic because the demo effect
// runs on the tick (main) thread while a poll may read from the IPC thread.
struct BridgeState {
    std::mutex mutex;
    std::atomic<std::int64_t> balance{0};
    std::atomic<std::uint64_t> counter{0};
    std::atomic<bool> serve_stop{false};
    std::unique_ptr<RegisteredFunctionTable> table;
    std::unique_ptr<EngineBridgeService> service;
    bool started{false};
};

[[nodiscard]] BridgeState& state() {
    static BridgeState instance;
    return instance;
}

// Demo allowlist: one AddResource(i)->i that adds to the internal counter, the
// stand-in for a native SLI effect. The real table is supplied by a build
// profile in a later milestone.
constexpr std::uint64_t demo_add_function = 1;

[[nodiscard]] bool copy_out(
    const std::vector<std::byte>& source, unsigned char* out, std::uint32_t* out_len) {
    if (out == nullptr || out_len == nullptr) return false;
    const std::uint32_t capacity = *out_len;
    *out_len = static_cast<std::uint32_t>(source.size());
    if (source.size() > capacity) return false;
    std::memcpy(out, source.data(), source.size());
    return true;
}

[[nodiscard]] std::uint32_t read_le32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8U) |
           (static_cast<std::uint32_t>(p[2]) << 16U) | (static_cast<std::uint32_t>(p[3]) << 24U);
}

[[nodiscard]] std::uint64_t read_le64(const unsigned char* p) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8U; ++index) {
        value |= static_cast<std::uint64_t>(p[index]) << (8U * index);
    }
    return value;
}

[[nodiscard]] bool read_full(HANDLE pipe, unsigned char* buffer, std::size_t count) {
    std::size_t filled = 0;
    while (filled < count) {
        DWORD got = 0;
        if (ReadFile(pipe, buffer + filled, static_cast<DWORD>(count - filled), &got, nullptr) == 0 ||
            got == 0) {
            return false;
        }
        filled += got;
    }
    return true;
}

[[nodiscard]] bool write_full(HANDLE pipe, const unsigned char* buffer, std::size_t count) {
    std::size_t written = 0;
    while (written < count) {
        DWORD put = 0;
        if (WriteFile(pipe, buffer + written, static_cast<DWORD>(count - written), &put, nullptr) == 0 ||
            put == 0) {
            return false;
        }
        written += put;
    }
    return true;
}

// Handles one connected client until it disconnects or sends a malformed frame.
void serve_client(HANDLE pipe, EngineBridgeService& service) {
    namespace infra = argos::infrastructure::santamonica;
    for (;;) {
        std::array<unsigned char, infra::invoke_header_bytes> header{};
        if (!read_full(pipe, header.data(), header.size())) return;
        const std::uint32_t payload_len = read_le32(header.data() + 12);
        const std::uint64_t request_id = read_le64(header.data() + 16);
        const std::uint64_t sequence = read_le64(header.data() + 24);
        if (payload_len > infra::max_invoke_payload_bytes) return;

        std::vector<unsigned char> frame(header.begin(), header.end());
        frame.resize(infra::invoke_header_bytes + payload_len);
        if (payload_len > 0 &&
            !read_full(pipe, frame.data() + infra::invoke_header_bytes, payload_len)) {
            return;
        }

        const std::span<const std::byte> command{
            reinterpret_cast<const std::byte*>(frame.data()), frame.size()};
        auto result = service.run(command, request_id, sequence);
        if (!result) return;  // Protocol/admission failure closes the connection.
        if (!write_full(pipe, reinterpret_cast<const unsigned char*>(result->data()), result->size())) {
            return;
        }
    }
}

}  // namespace

extern "C" {

// Prepares the dispatcher and registers the demo allowlist. Idempotent.
__declspec(dllexport) int Argos_BridgeStartup() {
    BridgeState& self = state();
    const std::lock_guard lock{self.mutex};
    if (self.started) return 0;
    self.balance.store(0);
    self.counter.store(0);
    self.table = std::make_unique<RegisteredFunctionTable>();
    self.table->register_function(
        SliFunctionRecord{FunctionKey{demo_add_function}, "AddResource", "i_i"},
        [](const EngineInvokePlan&, std::span<const EngineArgument> arguments)
            -> argos::domain::Result<EngineInvokeResult> {
            const std::int64_t updated =
                state().balance.fetch_add(arguments[0].integer) + arguments[0].integer;
            return EngineInvokeResult{EngineOperationState::completed, EngineValueKind::integer,
                                      updated, 0.0, false, {}, 0};
        });
    self.service = std::make_unique<EngineBridgeService>(*self.table);
    self.started = true;
    return 0;
}

__declspec(dllexport) void Argos_BridgeShutdown() {
    BridgeState& self = state();
    const std::lock_guard lock{self.mutex};
    self.service.reset();
    self.table.reset();
    self.started = false;
}

// IPC side: admit an AddResource command and return its operation id. Returns 0
// on success, a negative code on refusal.
__declspec(dllexport) int Argos_BridgeSubmitAdd(
    long long amount, char* operation_id, unsigned operation_id_capacity) {
    BridgeState& self = state();
    EngineBridgeService* service = nullptr;
    {
        const std::lock_guard lock{self.mutex};
        service = self.service.get();
    }
    if (service == nullptr) return -1;
    EngineInvokeRequest request;
    request.function_id = FunctionKey{demo_add_function};
    request.arguments.push_back(
        EngineArgument{EngineValueKind::integer, static_cast<std::int64_t>(amount), 0.0, false, {}});
    request.idempotency_key = "demo-" + std::to_string(self.counter.fetch_add(1));
    auto submitted = service->dispatcher().submit(request);
    if (!submitted) return -2;
    if (operation_id != nullptr && operation_id_capacity > 0) {
        const std::size_t length = submitted->size() < operation_id_capacity - 1U
                                       ? submitted->size()
                                       : operation_id_capacity - 1U;
        std::memcpy(operation_id, submitted->data(), length);
        operation_id[length] = '\0';
    }
    return 0;
}

// Main-thread side: run at most one queued operation. Returns 1 if it did work.
__declspec(dllexport) int Argos_BridgeTick() {
    BridgeState& self = state();
    EngineBridgeService* service = nullptr;
    {
        const std::lock_guard lock{self.mutex};
        service = self.service.get();
    }
    if (service == nullptr) return 0;
    return service->dispatcher().tick() ? 1 : 0;
}

__declspec(dllexport) long long Argos_BridgePollBalance() {
    return static_cast<long long>(state().balance.load());
}

// Raw per-command entrypoint the future authenticated transport calls: decode a
// command frame, run it to a terminal state on this thread, and write the result
// frame into `out`. Returns 0 on success; -1 no service, -2 dispatch/protocol
// error, -3 output buffer too small (with *out_len set to the required size).
__declspec(dllexport) int Argos_BridgeRun(
    const unsigned char* frame, unsigned frame_len, unsigned long long request_id,
    unsigned long long sequence, unsigned char* out, unsigned* out_len) {
    BridgeState& self = state();
    EngineBridgeService* service = nullptr;
    {
        const std::lock_guard lock{self.mutex};
        service = self.service.get();
    }
    if (service == nullptr || frame == nullptr) return -1;
    const std::span<const std::byte> command{reinterpret_cast<const std::byte*>(frame), frame_len};
    auto result = service->run(command, request_id, sequence);
    if (!result) return -2;
    std::uint32_t capacity = out_len != nullptr ? *out_len : 0U;
    if (!copy_out(*result, out, &capacity)) {
        if (out_len != nullptr) *out_len = capacity;
        return -3;
    }
    if (out_len != nullptr) *out_len = capacity;
    return 0;
}

// Blocking named-pipe server: hosts the bridge for a client driver over the
// approved local pipe (no authenticated handshake in this demo build). Accepts
// clients in turn until `Argos_BridgeStopServe` is called or the process exits.
// Returns 0 when stopped cleanly, negative on a setup failure. The demo runs the
// dispatcher on this serving thread; a real game would submit here and tick from
// its own main thread.
__declspec(dllexport) int Argos_BridgeServe(const char* pipe_name) {
    if (pipe_name == nullptr) return -1;
    if (Argos_BridgeStartup() != 0) return -2;

    BridgeState& self = state();
    EngineBridgeService* service = nullptr;
    {
        const std::lock_guard lock{self.mutex};
        service = self.service.get();
    }
    if (service == nullptr) return -2;

    const HANDLE pipe = CreateNamedPipeA(
        pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
        64U * 1024U, 64U * 1024U, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return -3;

    self.serve_stop.store(false);
    while (!self.serve_stop.load()) {
        const BOOL connected =
            ConnectNamedPipe(pipe, nullptr) != 0 || GetLastError() == ERROR_PIPE_CONNECTED;
        if (self.serve_stop.load()) break;
        if (connected != 0) {
            serve_client(pipe, *service);
        }
        DisconnectNamedPipe(pipe);
    }
    CloseHandle(pipe);
    return 0;
}

__declspec(dllexport) void Argos_BridgeStopServe() { state().serve_stop.store(true); }

}  // extern "C"

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
