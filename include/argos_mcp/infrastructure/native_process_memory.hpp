#pragma once

#include "argos_mcp/domain/process_memory.hpp"

#include <cstddef>

namespace argos::infrastructure {

class NativeProcessMemoryProvider final : public domain::ProcessMemoryProvider {
public:
    explicit NativeProcessMemoryProvider(
        bool allow_foreign_user = false,
        std::size_t max_captured_output_bytes = 1U * 1024U * 1024U
    ) noexcept
        : allow_foreign_user_(allow_foreign_user), max_captured_output_bytes_(max_captured_output_bytes) {}

    [[nodiscard]] domain::Result<std::vector<domain::ProcessInfo>> list_processes(
        std::string_view filter,
        std::size_t limit
    ) const override;

    [[nodiscard]] domain::Result<std::unique_ptr<domain::ProcessSession>> attach(
        domain::ProcessId pid,
        domain::AccessMode access
    ) const override;

    [[nodiscard]] domain::Result<std::unique_ptr<domain::LaunchedProcessSession>> launch(
        const domain::LaunchSpec& spec,
        domain::AccessMode access
    ) const override;

private:
    bool allow_foreign_user_{false};
    std::size_t max_captured_output_bytes_{1U * 1024U * 1024U};
};

}  // namespace argos::infrastructure
