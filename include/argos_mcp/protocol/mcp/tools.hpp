#pragma once

#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/observability/logger.hpp"
#include "argos_mcp/protocol/json/value.hpp"

#include <string>
#include <string_view>
#include <stop_token>
#include <optional>
#include <vector>

namespace argos::protocol::mcp {

struct ToolDefinition {
    std::string name;
    std::string description;
    json::Value input_schema;
    json::Value annotations;
};

struct ToolCallResult {
    json::Value structured;
    bool is_error{false};
};

class ToolCatalog final {
public:
    ToolCatalog(
        application::MemoryDebugService& service,
        const observability::Logger& logger
    );

    [[nodiscard]] const std::vector<ToolDefinition>& definitions() const noexcept {
        return definitions_;
    }

    [[nodiscard]] std::optional<ToolCallResult> invoke(
        std::string_view name,
        const json::Value& arguments,
        std::stop_token cancellation = {}
    );

private:
    [[nodiscard]] std::vector<ToolDefinition> build_definitions() const;

    application::MemoryDebugService& service_;
    const observability::Logger& logger_;
    std::vector<ToolDefinition> definitions_;
};

}  // namespace argos::protocol::mcp
