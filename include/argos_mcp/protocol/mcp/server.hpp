#pragma once

#include "argos_mcp/observability/logger.hpp"
#include "argos_mcp/protocol/json/value.hpp"
#include "argos_mcp/protocol/mcp/tools.hpp"

#include <cstdint>
#include <istream>
#include <optional>
#include <ostream>
#include <stop_token>
#include <string>

namespace argos::protocol::mcp {

class Server final {
public:
    Server(ToolCatalog& tools, const observability::Logger& logger) noexcept
        : tools_(tools), logger_(logger) {}

    int run(std::istream& input, std::ostream& output);

    [[nodiscard]] std::optional<json::Value> handle(const json::Value& message);

private:
    [[nodiscard]] std::optional<json::Value> handle_with_token(
        const json::Value& message,
        std::stop_token cancellation
    );

    [[nodiscard]] static json::Value rpc_result(const json::Value& id, json::Value result);
    [[nodiscard]] static json::Value rpc_error(
        const json::Value& id,
        std::int64_t code,
        std::string message
    );

    ToolCatalog& tools_;
    const observability::Logger& logger_;
};

}  // namespace argos::protocol::mcp
