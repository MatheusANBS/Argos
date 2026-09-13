// Client driver for the debug bridge's named-pipe server (demo, approved local
// pipe, no authenticated handshake). Connects to the pipe the target hosts,
// sends one AddResource(amount) command frame, reads the result frame and prints
// the new balance. This is the "run it and see the invoke happen" tool.
//
//   argos_bridge_invoke --pipe \\.\pipe\argos-bridge-demo --add 500

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "argos_mcp/domain/santa_monica_invoke.hpp"
#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

struct Options {
    std::string pipe{R"(\\.\pipe\argos-bridge-demo)"};
    std::int64_t amount{0};
    bool has_amount{false};
    std::uint64_t request_id{1};
    std::uint64_t sequence{1};
};

[[nodiscard]] bool parse_i64(const std::string_view text, std::int64_t& out) {
    const auto* first = text.data();
    const auto* last = first + text.size();
    const auto result = std::from_chars(first, last, out);
    return result.ec == std::errc{} && result.ptr == last;
}

[[nodiscard]] bool parse(const int argc, char** argv, Options& options) {
    for (int index = 1; index + 1 < argc; index += 2) {
        const std::string_view key{argv[index]};
        const std::string_view value{argv[index + 1]};
        if (key == "--pipe") {
            options.pipe = value;
        } else if (key == "--add") {
            if (!parse_i64(value, options.amount)) return false;
            options.has_amount = true;
        } else if (key == "--request") {
            std::int64_t v{};
            if (!parse_i64(value, v) || v <= 0) return false;
            options.request_id = static_cast<std::uint64_t>(v);
        } else if (key == "--seq") {
            std::int64_t v{};
            if (!parse_i64(value, v) || v <= 0) return false;
            options.sequence = static_cast<std::uint64_t>(v);
        } else {
            return false;
        }
    }
    return options.has_amount;
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

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse(argc, argv, options)) {
        std::cerr << "usage: argos_bridge_invoke --add <amount> [--pipe <name>] "
                     "[--request <id>] [--seq <n>]\n";
        return 2;
    }

    EngineInvokeRequest request;
    request.function_id = FunctionKey{1};  // Demo AddResource.
    request.arguments.push_back(EngineArgument{EngineValueKind::integer, options.amount, 0.0, false, {}});
    request.idempotency_key = "cli-" + std::to_string(options.request_id) + "-" +
                              std::to_string(options.sequence);
    const auto command = infra::encode_invoke_command(request, options.request_id, options.sequence);
    if (!command) {
        std::cerr << "failed to encode command (" << command.error().reason << ")\n";
        return 1;
    }

    HANDLE pipe = CreateFileA(options.pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        if (WaitNamedPipeA(options.pipe.c_str(), 5000) != 0) {
            pipe = CreateFileA(options.pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        }
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        std::cerr << "could not open pipe " << options.pipe << " (err " << GetLastError()
                  << "); is the target hosting the bridge?\n";
        return 1;
    }

    DWORD written = 0;
    if (WriteFile(pipe, command->data(), static_cast<DWORD>(command->size()), &written, nullptr) == 0) {
        std::cerr << "write failed (err " << GetLastError() << ")\n";
        CloseHandle(pipe);
        return 1;
    }

    std::vector<unsigned char> header(infra::invoke_header_bytes);
    if (!read_full(pipe, header.data(), header.size())) {
        std::cerr << "no result frame from the bridge\n";
        CloseHandle(pipe);
        return 1;
    }
    std::uint32_t payload_len = 0;
    for (std::size_t index = 0; index < 4U; ++index) {
        payload_len |= static_cast<std::uint32_t>(header[12 + index]) << (8U * index);
    }
    std::vector<unsigned char> frame = header;
    frame.resize(infra::invoke_header_bytes + payload_len);
    if (payload_len > 0 && !read_full(pipe, frame.data() + infra::invoke_header_bytes, payload_len)) {
        std::cerr << "truncated result frame\n";
        CloseHandle(pipe);
        return 1;
    }
    CloseHandle(pipe);

    const std::span<const std::byte> result_frame{
        reinterpret_cast<const std::byte*>(frame.data()), frame.size()};
    const auto result = infra::decode_invoke_result(result_frame, options.request_id, options.sequence);
    if (!result) {
        std::cerr << "failed to decode result (" << result.error().reason << ")\n";
        return 1;
    }

    std::cout << "state=" << to_string(result->state) << " balance=" << result->integer << "\n";
    return result->state == EngineOperationState::completed ? 0 : 1;
}
