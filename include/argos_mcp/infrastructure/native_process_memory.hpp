#pragma once

#include "argos_mcp/domain/process_memory.hpp"

namespace argos::infrastructure {

class NativeProcessMemoryProvider final : public domain::ProcessMemoryProvider {
public:
    explicit NativeProcessMemoryProvider(bool allow_foreign_user = false) noexcept
        : allow_foreign_user_(allow_foreign_user) {}

    [[nodiscard]] domain::Result<std::vector<domain::ProcessInfo>> list_processes(
        std::string_view filter,
        std::size_t limit
    ) const override;

    [[nodiscard]] domain::Result<std::unique_ptr<domain::ProcessSession>> attach(
        domain::ProcessId pid,
        domain::AccessMode access
    ) const override;

private:
    bool allow_foreign_user_{false};
};

}  // namespace argos::infrastructure
