#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain {

struct LaunchSpec {
    std::string executable;
    std::vector<std::string> arguments;
    std::optional<std::string> working_directory;
    bool capture_output{true};
};

struct OutputChunk {
    std::string stdout_text;
    std::string stderr_text;
    std::uint64_t cursor{};
    bool process_alive{true};
};

// Describes an operator-approved Argos debug bridge. It intentionally carries
// only a DLL path: arbitrary exports, arguments and code bytes are not a part
// of the domain contract.
struct DebugBridgeSpec {
    std::string path;
};

struct InjectedDebugBridge {
    ProcessId pid{};
    std::string name;
    Address module_base{};
};

class ProcessSession {
public:
    virtual ~ProcessSession() = default;

    [[nodiscard]] virtual ProcessId pid() const noexcept = 0;
    [[nodiscard]] virtual std::string_view process_name() const noexcept = 0;
    [[nodiscard]] virtual AccessMode access_mode() const noexcept = 0;

    [[nodiscard]] virtual Result<std::size_t> read(
        Address address,
        std::span<std::byte> output
    ) const = 0;

    [[nodiscard]] virtual Result<std::size_t> write(
        Address address,
        std::span<const std::byte> input
    ) = 0;

    [[nodiscard]] virtual Result<std::vector<MemoryRegion>> regions() const = 0;
    [[nodiscard]] virtual Result<std::vector<ModuleInfo>> modules() const = 0;

    // Platforms and synthetic test sessions that do not implement the
    // explicitly-gated bridge return unsupported. This keeps a Win32 remote
    // loading mechanism out of the domain and avoids making injection an
    // implicit capability of every ProcessSession implementation.
    [[nodiscard]] virtual Result<InjectedDebugBridge> inject_debug_bridge(
        const DebugBridgeSpec&
    ) {
        return std::unexpected(DebugError{
            DebugErrorCode::unsupported, "debug bridge injection is not supported on this platform"
        });
    }
};

// A ProcessSession for a process the MCP itself started with launch(). In
// addition to the read-only/read-write memory access every ProcessSession
// offers, an owned session can be polled for captured stdout/stderr and can
// be terminated by the server -- capabilities attach() sessions never gain.
class LaunchedProcessSession : public ProcessSession {
public:
    [[nodiscard]] virtual Result<OutputChunk> read_output(
        std::uint64_t since_cursor,
        std::size_t max_bytes
    ) = 0;

    [[nodiscard]] virtual Result<void> terminate() = 0;

    [[nodiscard]] virtual bool owned() const noexcept = 0;
};

class ProcessMemoryProvider {
public:
    virtual ~ProcessMemoryProvider() = default;

    [[nodiscard]] virtual Result<std::vector<ProcessInfo>> list_processes(
        std::string_view filter,
        std::size_t limit
    ) const = 0;

    [[nodiscard]] virtual Result<std::unique_ptr<ProcessSession>> attach(
        ProcessId pid,
        AccessMode access
    ) const = 0;

    [[nodiscard]] virtual Result<std::unique_ptr<LaunchedProcessSession>> launch(
        const LaunchSpec& spec,
        AccessMode access
    ) const = 0;
};

}  // namespace argos::domain
