#pragma once

#include "argos_mcp/domain/types.hpp"

#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace argos::domain {

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
};

}  // namespace argos::domain
