#pragma once

#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/types.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

namespace argos::application {

class SessionManager final {
public:
    SessionManager();

    [[nodiscard]] domain::Result<domain::SessionInfo> add(
        std::unique_ptr<domain::ProcessSession> session
    );

    [[nodiscard]] domain::Result<std::shared_ptr<domain::ProcessSession>> get(
        const domain::SessionId& id
    ) const;

    [[nodiscard]] domain::Result<void> remove(const domain::SessionId& id);
    [[nodiscard]] std::vector<domain::SessionInfo> list() const;

    [[nodiscard]] std::size_t count_if(
        const std::function<bool(const domain::ProcessSession&)>& predicate
    ) const;

private:
    [[nodiscard]] std::string generate_id();

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<domain::ProcessSession>> sessions_;
    mutable std::mutex rng_mutex_;
    std::mt19937_64 rng_;
};

}  // namespace argos::application
