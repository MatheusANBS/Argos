#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/infrastructure/native_process_memory.hpp"
#include "argos_mcp/observability/logger.hpp"
#include "argos_mcp/protocol/json/value.hpp"
#include "argos_mcp/protocol/mcp/server.hpp"
#include "argos_mcp/protocol/mcp/tools.hpp"
#include "argos_mcp/security/policy.hpp"

#include <iostream>
#include <memory>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

}  // namespace

int main() {
    argos::security::SecurityPolicy policy;
    auto provider = std::make_unique<argos::infrastructure::NativeProcessMemoryProvider>(false);
    argos::application::MemoryDebugService service{std::move(provider), policy};
    argos::observability::Logger logger{argos::observability::LogLevel::error};
    argos::protocol::mcp::ToolCatalog catalog{service, logger};
    argos::protocol::mcp::Server server{catalog, logger};

    const auto initialize = argos::protocol::json::Value::object({
        {"jsonrpc", "2.0"},
        {"id", 1},
        {"method", "initialize"},
        {"params", argos::protocol::json::Value::object({
            {"protocolVersion", "2025-11-25"},
            {"capabilities", argos::protocol::json::Value::object({})},
            {"clientInfo", argos::protocol::json::Value::object({{"name", "test"}, {"version", "1"}})}
        })}
    });
    auto init_response = server.handle(initialize);
    check(init_response.has_value(), "initialize receives a response");
    if (init_response) {
        const auto& result = init_response->at("result");
        check(result.at("protocolVersion").as_string() == "2025-11-25", "stable protocol version is negotiated");
    }

    const auto list = argos::protocol::json::Value::object({
        {"jsonrpc", "2.0"}, {"id", 2}, {"method", "tools/list"},
        {"params", argos::protocol::json::Value::object({})}
    });
    auto list_response = server.handle(list);
    check(list_response.has_value(), "tools/list receives a response");
    if (list_response) {
        const auto& tools = list_response->at("result").at("tools").as_array();
        check(tools.size() >= 25U, "tool catalog exposes the runtime debugging tools");
        bool has_pdb_type = false;
        bool has_unity_type = false;
        bool has_unreal_type = false;
        bool has_unreal_reflection = false;
        bool has_strings = false;
        bool has_scan_pointers_to = false;
        bool has_pdb_list_types = false;
        bool has_scan_first = false;
        bool has_scan_next = false;
        bool has_scan_results = false;
        bool has_scan_reset = false;
        bool has_launch = false;
        bool has_read_output = false;
        for (const auto& tool : tools) {
            const auto name = tool.at("name").as_string();
            has_pdb_type = has_pdb_type || name == "memory_debug.pdb_type";
            has_unity_type = has_unity_type || name == "memory_debug.unity_type";
            has_unreal_type = has_unreal_type || name == "memory_debug.unreal_type";
            has_unreal_reflection = has_unreal_reflection || name == "memory_debug.unreal_reflection";
            has_strings = has_strings || name == "memory_debug.strings";
            has_scan_pointers_to = has_scan_pointers_to || name == "memory_debug.scan_pointers_to";
            has_pdb_list_types = has_pdb_list_types || name == "memory_debug.pdb_list_types";
            has_scan_first = has_scan_first || name == "memory_debug.scan_first";
            has_scan_next = has_scan_next || name == "memory_debug.scan_next";
            has_scan_results = has_scan_results || name == "memory_debug.scan_results";
            has_scan_reset = has_scan_reset || name == "memory_debug.scan_reset";
            has_launch = has_launch || name == "memory_debug.launch";
            has_read_output = has_read_output || name == "memory_debug.read_output";
        }
        check(has_pdb_type, "tool catalog exposes PDB type metadata");
        check(has_unity_type, "tool catalog exposes Unity metadata");
        check(has_unreal_type, "tool catalog exposes Unreal type metadata");
        check(has_unreal_reflection, "tool catalog exposes Unreal reflection metadata");
        check(has_strings, "tool catalog exposes memory_debug.strings");
        check(has_scan_pointers_to, "tool catalog exposes memory_debug.scan_pointers_to");
        check(has_pdb_list_types, "tool catalog exposes memory_debug.pdb_list_types");
        check(has_scan_first, "tool catalog exposes memory_debug.scan_first");
        check(has_scan_next, "tool catalog exposes memory_debug.scan_next");
        check(has_scan_results, "tool catalog exposes memory_debug.scan_results");
        check(has_scan_reset, "tool catalog exposes memory_debug.scan_reset");
        check(has_launch, "tool catalog exposes memory_debug.launch");
        check(has_read_output, "tool catalog exposes memory_debug.read_output");
    }

    const auto notification = argos::protocol::json::Value::object({
        {"jsonrpc", "2.0"}, {"method", "notifications/initialized"}
    });
    check(!server.handle(notification).has_value(), "notification produces no response");

    if (failures == 0) {
        std::cout << "All MCP contract tests passed\n";
        return 0;
    }
    return 1;
}
