#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/observability/logger.hpp"
#include "argos_mcp/protocol/json/value.hpp"
#include "argos_mcp/protocol/mcp/server.hpp"
#include "argos_mcp/protocol/mcp/tools.hpp"
#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

[[nodiscard]] argos::domain::DebugError debug_error(
    const argos::domain::DebugErrorCode code,
    std::string message
) {
    return argos::domain::DebugError{code, std::move(message)};
}

class ContractSession final : public argos::domain::ProcessSession {
public:
    explicit ContractSession(const argos::domain::AccessMode access) : access_(access) {
        memory_[4] = std::byte{0x2A};  // i32 42 at 0x1004, little-endian.
    }

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 4242U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "contract-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override { return access_; }

    [[nodiscard]] argos::domain::Result<std::size_t> read(
        const argos::domain::Address address,
        const std::span<std::byte> output
    ) const override {
        constexpr argos::domain::Address base = 0x1000U;
        if (address < base || address - base > memory_.size()) {
            return std::unexpected(debug_error(
                argos::domain::DebugErrorCode::io_error, "address is outside contract memory"
            ));
        }
        const auto offset = static_cast<std::size_t>(address - base);
        if (output.size() > memory_.size() - offset) {
            return std::unexpected(debug_error(
                argos::domain::DebugErrorCode::io_error, "read is outside contract memory"
            ));
        }
        std::copy_n(memory_.begin() + static_cast<std::ptrdiff_t>(offset), output.size(), output.begin());
        return output.size();
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(debug_error(
            argos::domain::DebugErrorCode::access_denied, "contract target is read-only"
        ));
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{
            {0x1000U, 0x1010U, true, true, false, true, "heap-main"},
            {0x2000U, 0x2020U, true, false, true, false, "image.text"},
            {0x3000U, 0x3008U, false, false, false, true, "guard"}
        };
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{};
    }

private:
    argos::domain::AccessMode access_;
    std::array<std::byte, 16> memory_{};
};

class ContractProvider final : public argos::domain::ProcessMemoryProvider {
public:
    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<argos::domain::ProcessInfo>{
            {4242U, "contract-target", std::nullopt, true}
        };
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::ProcessSession>> attach(
        const argos::domain::ProcessId pid,
        const argos::domain::AccessMode access
    ) const override {
        if (pid != 4242U) {
            return std::unexpected(debug_error(argos::domain::DebugErrorCode::not_found, "process not found"));
        }
        std::unique_ptr<argos::domain::ProcessSession> session = std::make_unique<ContractSession>(access);
        return session;
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::LaunchedProcessSession>> launch(
        const argos::domain::LaunchSpec&,
        argos::domain::AccessMode
    ) const override {
        return std::unexpected(debug_error(
            argos::domain::DebugErrorCode::unsupported, "launch is unavailable in contract tests"
        ));
    }
};

class SlowContractSession final : public argos::domain::ProcessSession {
public:
    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 4343U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "slow-contract-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override {
        return argos::domain::AccessMode::read_only;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> read(
        argos::domain::Address,
        const std::span<std::byte> output
    ) const override {
        std::this_thread::sleep_for(std::chrono::milliseconds{40});
        std::ranges::fill(output, std::byte{0});
        return output.size();
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(debug_error(
            argos::domain::DebugErrorCode::access_denied, "slow contract target is read-only"
        ));
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{
            {0x1000U, 0x11000U, true, false, false, true, "slow-memory"}
        };
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{};
    }
};

class SlowContractProvider final : public argos::domain::ProcessMemoryProvider {
public:
    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<argos::domain::ProcessInfo>{{4343U, "slow-contract-target", std::nullopt, true}};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::ProcessSession>> attach(
        argos::domain::ProcessId,
        argos::domain::AccessMode
    ) const override {
        std::unique_ptr<argos::domain::ProcessSession> session = std::make_unique<SlowContractSession>();
        return session;
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::LaunchedProcessSession>> launch(
        const argos::domain::LaunchSpec&,
        argos::domain::AccessMode
    ) const override {
        return std::unexpected(debug_error(
            argos::domain::DebugErrorCode::unsupported, "launch is unavailable in cancellation tests"
        ));
    }
};

using JsonValue = argos::protocol::json::Value;

[[nodiscard]] std::optional<JsonValue> call_tool(
    argos::protocol::mcp::Server& server,
    const std::int64_t id,
    std::string name,
    JsonValue arguments
) {
    return server.handle(JsonValue::object({
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", "tools/call"},
        {"params", JsonValue::object({
            {"name", std::move(name)},
            {"arguments", std::move(arguments)}
        })}
    }));
}

[[nodiscard]] JsonValue modern_request_meta(
    std::string protocol_version = "2026-07-28",
    const bool include_client_capabilities = true
) {
    JsonValue meta = JsonValue::object({
        {"io.modelcontextprotocol/protocolVersion", std::move(protocol_version)},
        {"io.modelcontextprotocol/clientInfo", JsonValue::object({
            {"name", "contract-modern-client"}, {"version", "1.0.0"}
        })}
    });
    if (include_client_capabilities) {
        meta["io.modelcontextprotocol/clientCapabilities"] = JsonValue::object({});
    }
    return meta;
}

[[nodiscard]] std::optional<JsonValue> call_modern_request(
    argos::protocol::mcp::Server& server,
    const std::int64_t id,
    std::string method,
    JsonValue params,
    std::string protocol_version = "2026-07-28",
    const bool include_client_capabilities = true
) {
    params["_meta"] = modern_request_meta(std::move(protocol_version), include_client_capabilities);
    return server.handle(JsonValue::object({
        {"jsonrpc", "2.0"},
        {"id", id},
        {"method", std::move(method)},
        {"params", std::move(params)}
    }));
}

[[nodiscard]] std::optional<JsonValue> call_modern_tool(
    argos::protocol::mcp::Server& server,
    const std::int64_t id,
    std::string name,
    JsonValue arguments
) {
    return call_modern_request(server, id, "tools/call", JsonValue::object({
        {"name", std::move(name)}, {"arguments", std::move(arguments)}
    }));
}

[[nodiscard]] const JsonValue* successful_tool_data(const std::optional<JsonValue>& response) {
    if (!response) {
        check(false, "tool call receives a response");
        return nullptr;
    }
    const auto& result = response->at("result");
    if (result.at("isError").as_bool()) {
        check(false, "tool call succeeds");
        return nullptr;
    }
    const auto& structured = result.at("structuredContent");
    if (!structured.at("ok").as_bool()) {
        check(false, "successful tool response contains ok=true");
        return nullptr;
    }
    return &structured.at("data");
}

[[nodiscard]] bool is_invalid_arguments(const std::optional<JsonValue>& response) {
    if (!response) return false;
    const auto& result = response->at("result");
    if (!result.at("isError").as_bool()) return false;
    const auto& structured = result.at("structuredContent");
    return !structured.at("ok").as_bool() &&
           structured.at("error").at("code").as_string() == "invalid_arguments";
}

}  // namespace

int main() {
    argos::security::SecurityPolicy policy;
    auto provider = std::make_unique<ContractProvider>();
    argos::application::MemoryDebugService service{std::move(provider), policy};
    argos::observability::Logger logger{argos::observability::LogLevel::error};
    argos::protocol::mcp::ToolCatalog catalog{service, logger};
    argos::protocol::mcp::Server server{catalog, logger};

    {
        std::string framed_input(argos::protocol::json::max_parse_input_bytes + 1U, ' ');
        framed_input += "\n{\"jsonrpc\":\"2.0\",\"id\":902,\"method\":\"ping\"}\n";
        std::istringstream input{std::move(framed_input)};
        std::ostringstream output;
        check(server.run(input, output) == 0, "stdio server drains an oversized frame and exits cleanly");

        const auto response_text = output.str();
        const auto first_newline = response_text.find('\n');
        const auto second_newline = first_newline == std::string::npos
            ? std::string::npos
            : response_text.find('\n', first_newline + 1U);
        check(first_newline != std::string::npos && second_newline != std::string::npos,
              "oversized frame and following valid request each receive a response");
        if (first_newline != std::string::npos && second_newline != std::string::npos) {
            const auto oversized_response = argos::protocol::json::parse(
                std::string_view{response_text}.substr(0U, first_newline)
            );
            const auto ping_response = argos::protocol::json::parse(
                std::string_view{response_text}.substr(first_newline + 1U, second_newline - first_newline - 1U)
            );
            check(oversized_response.has_value() && oversized_response->at("error").at("code").as_integer() == -32700,
                  "oversized stdio frame is rejected as a parse error");
            check(ping_response.has_value() && ping_response->at("id").as_integer() == 902 &&
                      ping_response->contains("result"),
                  "server resynchronizes at newline after an oversized frame");
        }
    }

    const auto legacy_unknown = call_tool(server, 903, "memory_debug.no_such_tool", JsonValue::object({}));
    check(legacy_unknown.has_value() && legacy_unknown->contains("error") &&
              legacy_unknown->at("error").at("code").as_integer() == -32602 &&
              !legacy_unknown->contains("result"),
          "legacy unknown tool is a JSON-RPC invalid-params error");
    const auto modern_unknown = call_modern_tool(
        server, 904, "memory_debug.no_such_tool", JsonValue::object({})
    );
    check(modern_unknown.has_value() && modern_unknown->contains("error") &&
              modern_unknown->at("error").at("code").as_integer() == -32602 &&
              !modern_unknown->contains("result"),
          "modern unknown tool is a JSON-RPC invalid-params error");

    {
        argos::security::SecurityPolicy slow_policy;
        argos::application::MemoryDebugService slow_service{
            std::make_unique<SlowContractProvider>(), slow_policy
        };
        auto attached = slow_service.attach(4343U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "cancellation transport fixture attaches");
        if (attached) {
            argos::observability::Logger slow_logger{argos::observability::LogLevel::error};
            argos::protocol::mcp::ToolCatalog slow_catalog{slow_service, slow_logger};
            argos::protocol::mcp::Server slow_server{slow_catalog, slow_logger};
            const auto tool_call = JsonValue::object({
                {"jsonrpc", "2.0"}, {"id", 905}, {"method", "tools/call"},
                {"params", JsonValue::object({
                    {"name", "memory_debug.scan_exact"},
                    {"arguments", JsonValue::object({
                        {"session_id", attached->id.value()}, {"pattern_hex", "ff"},
                        {"byte_budget", 64 * 1024}, {"result_limit", 16}
                    })}
                })}
            });
            const auto cancelled = JsonValue::object({
                {"jsonrpc", "2.0"}, {"method", "notifications/cancelled"},
                {"params", JsonValue::object({{"requestId", 905}, {"reason", "contract test"}})}
            });
            std::istringstream input{tool_call.dump() + '\n' + cancelled.dump() + '\n'};
            std::ostringstream output;
            check(slow_server.run(input, output) == 0, "cancelled stdio request shuts down cleanly");
            check(output.str().empty(), "cancelled stdio request emits no response with the cancelled id");
        }
    }

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
        check(result.at("serverInfo").at("version").as_string() == "0.2.0",
              "initialize advertises the release version");
    }

    const auto legacy_2025_06 = argos::protocol::json::Value::object({
        {"jsonrpc", "2.0"},
        {"id", 90},
        {"method", "initialize"},
        {"params", argos::protocol::json::Value::object({
            {"protocolVersion", "2025-06-18"},
            {"capabilities", argos::protocol::json::Value::object({})},
            {"clientInfo", argos::protocol::json::Value::object({{"name", "old-test"}, {"version", "1"}})}
        })}
    });
    auto legacy_2025_06_response = server.handle(legacy_2025_06);
    check(legacy_2025_06_response.has_value(), "2025-06-18 initialize remains supported");
    if (legacy_2025_06_response) {
        const auto& result = legacy_2025_06_response->at("result");
        check(result.at("protocolVersion").as_string() == "2025-06-18",
              "legacy initialize preserves the requested supported version");
        check(result.find("resultType") == nullptr, "legacy initialize does not acquire the modern result envelope");
        check(result.find("serverInfo") != nullptr, "legacy initialize keeps serverInfo in the result body");
    }

    auto legacy_ping = server.handle(JsonValue::object({
        {"jsonrpc", "2.0"}, {"id", 91}, {"method", "ping"},
        {"params", JsonValue::object({})}
    }));
    check(legacy_ping.has_value(), "legacy ping remains available");
    if (legacy_ping) {
        const auto& result = legacy_ping->at("result");
        check(result.is_object() && result.as_object().empty(),
              "legacy ping keeps its empty-result format");
    }

    auto legacy_discover = server.handle(JsonValue::object({
        {"jsonrpc", "2.0"}, {"id", 92}, {"method", "server/discover"},
        {"params", JsonValue::object({})}
    }));
    check(legacy_discover.has_value(), "legacy discovery probe receives a fallback response");
    if (legacy_discover) {
        check(legacy_discover->at("error").at("code").as_integer() == -32601,
              "server/discover without modern metadata enables legacy fallback");
    }

    const auto list = argos::protocol::json::Value::object({
        {"jsonrpc", "2.0"}, {"id", 2}, {"method", "tools/list"},
        {"params", argos::protocol::json::Value::object({})}
    });
    auto list_response = server.handle(list);
    check(list_response.has_value(), "tools/list receives a response");
    if (list_response) {
        const auto& list_result = list_response->at("result");
        check(list_result.find("resultType") == nullptr, "legacy tools/list keeps its original envelope");
        check(list_result.find("ttlMs") == nullptr, "legacy tools/list does not add modern cache hints");
        check(list_result.find("cacheScope") == nullptr, "legacy tools/list does not add modern cache scope");
        const auto& tools = list_result.at("tools").as_array();
        check(tools.size() >= 25U, "tool catalog exposes the runtime debugging tools");
        bool has_pdb_type = false;
        bool has_unity_type = false;
        bool has_unreal_type = false;
        bool has_unreal_reflection = false;
        bool has_strings = false;
        bool has_scan_pointers_to = false;
        bool has_scan_pointer_chains = false;
        bool has_pdb_list_types = false;
        bool has_scan_first = false;
        bool has_scan_next = false;
        bool has_scan_results = false;
        bool has_scan_reset = false;
        bool has_launch = false;
        bool has_read_output = false;
        bool has_address_space_summary = false;
        bool regions_supports_filtering = false;
        bool scan_first_accepts_decimal = false;
        bool scan_next_accepts_decimal = false;
        bool all_tools_have_output_schema = true;
        bool detach_is_destructive = false;
        for (const auto& tool : tools) {
            const auto name = tool.at("name").as_string();
            all_tools_have_output_schema = all_tools_have_output_schema &&
                tool.contains("outputSchema") && tool.at("outputSchema").is_object();
            if (name == "memory_debug.detach") {
                detach_is_destructive = tool.at("annotations").at("destructiveHint").as_bool();
            }
            if (name == "memory_debug.regions") {
                const auto& properties = tool.at("inputSchema").at("properties");
                regions_supports_filtering = properties.find("writable") != nullptr &&
                    properties.find("offset") != nullptr && properties.find("limit") != nullptr;
            }
            if (name == "memory_debug.scan_first") {
                const auto& properties = tool.at("inputSchema").at("properties");
                scan_first_accepts_decimal = properties.find("value_decimal") != nullptr;
            }
            if (name == "memory_debug.scan_next") {
                const auto& properties = tool.at("inputSchema").at("properties");
                scan_next_accepts_decimal = properties.find("value_decimal") != nullptr &&
                    properties.find("delta_decimal") != nullptr;
            }
            has_address_space_summary =
                has_address_space_summary || name == "memory_debug.address_space_summary";
            has_pdb_type = has_pdb_type || name == "memory_debug.pdb_type";
            has_unity_type = has_unity_type || name == "memory_debug.unity_type";
            has_unreal_type = has_unreal_type || name == "memory_debug.unreal_type";
            has_unreal_reflection = has_unreal_reflection || name == "memory_debug.unreal_reflection";
            has_strings = has_strings || name == "memory_debug.strings";
            has_scan_pointers_to = has_scan_pointers_to || name == "memory_debug.scan_pointers_to";
            has_scan_pointer_chains = has_scan_pointer_chains || name == "memory_debug.scan_pointer_chains";
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
        check(has_scan_pointer_chains, "tool catalog exposes memory_debug.scan_pointer_chains");
        check(has_pdb_list_types, "tool catalog exposes memory_debug.pdb_list_types");
        check(has_scan_first, "tool catalog exposes memory_debug.scan_first");
        check(has_scan_next, "tool catalog exposes memory_debug.scan_next");
        check(has_scan_results, "tool catalog exposes memory_debug.scan_results");
        check(has_scan_reset, "tool catalog exposes memory_debug.scan_reset");
        check(has_launch, "tool catalog exposes memory_debug.launch");
        check(has_read_output, "tool catalog exposes memory_debug.read_output");
        check(has_address_space_summary, "tool catalog exposes memory_debug.address_space_summary");
        check(regions_supports_filtering, "memory_debug.regions advertises filtering and paging");
        check(scan_first_accepts_decimal, "memory_debug.scan_first advertises value_decimal");
        check(scan_next_accepts_decimal, "memory_debug.scan_next advertises decimal value and delta");
        check(all_tools_have_output_schema, "every tool advertises its structured result schema");
        check(detach_is_destructive,
              "detach is conservatively destructive because terminate=true can stop a process");
    }

    // MCP 2026-07-28 is stateless: every request carries its protocol and
    // client-capability metadata, while legacy calls above remain unchanged.
    auto discover_response = call_modern_request(
        server, 100, "server/discover", JsonValue::object({})
    );
    check(discover_response.has_value(), "modern server/discover receives a response");
    if (discover_response) {
        const auto& result = discover_response->at("result");
        check(result.at("resultType").as_string() == "complete",
              "server/discover identifies a complete modern result");
        const auto& versions = result.at("supportedVersions").as_array();
        check(versions.size() == 3U, "server/discover advertises every supported protocol era");
        if (versions.size() == 3U) {
            check(versions[0].as_string() == "2026-07-28" &&
                      versions[1].as_string() == "2025-11-25" &&
                      versions[2].as_string() == "2025-06-18",
                  "supported protocol versions use the required preference order");
        }
        check(result.at("capabilities").at("tools").is_object(),
              "server/discover advertises the tools capability");
        check(!result.at("instructions").as_string().empty(),
              "server/discover supplies operating instructions");
        check(result.at("ttlMs").as_integer() > 0, "server/discover includes a finite cache lifetime");
        check(result.at("cacheScope").as_string() == "public",
              "server/discover marks instance-wide discovery data as public");
        check(result.find("serverInfo") == nullptr,
              "modern server info is not duplicated in the result body");
        const auto& server_info = result.at("_meta").at("io.modelcontextprotocol/serverInfo");
        check(server_info.at("name").as_string() == "argos-runtime-memory-mcp",
              "modern results identify the server through reserved metadata");
    }

    auto modern_list_response = call_modern_request(
        server, 101, "tools/list", JsonValue::object({})
    );
    check(modern_list_response.has_value(), "modern tools/list receives a response");
    if (modern_list_response) {
        const auto& result = modern_list_response->at("result");
        check(result.at("resultType").as_string() == "complete",
              "modern tools/list identifies a complete result");
        check(result.at("ttlMs").as_integer() > 0 && result.at("cacheScope").as_string() == "public",
              "modern tools/list provides cache hints");
        check(result.at("_meta").at("io.modelcontextprotocol/serverInfo").is_object(),
              "modern tools/list carries server identity metadata");

        const auto& tools = result.at("tools").as_array();
        bool deterministic_order = true;
        for (std::size_t index = 1; index < tools.size(); ++index) {
            deterministic_order = deterministic_order &&
                tools[index - 1].at("name").as_string() <= tools[index].at("name").as_string();
        }
        check(deterministic_order, "modern tools/list is ordered deterministically by tool name");
    }

    auto unsupported_version = call_modern_request(
        server, 102, "tools/list", JsonValue::object({}), "2099-01-01"
    );
    check(unsupported_version.has_value(), "an unsupported modern version receives an error");
    if (unsupported_version) {
        const auto& error = unsupported_version->at("error");
        check(error.at("code").as_integer() == -32022,
              "unsupported modern versions use the protocol-version error code");
        const auto& data = error.at("data");
        check(data.at("requested").as_string() == "2099-01-01",
              "the version error echoes the requested protocol");
        const auto& supported = data.at("supported").as_array();
        check(supported.size() == 3U && supported.front().as_string() == "2026-07-28",
              "the version error advertises the supported versions");
    }

    auto missing_capabilities = call_modern_request(
        server, 103, "tools/list", JsonValue::object({}), "2026-07-28", false
    );
    check(missing_capabilities.has_value(), "modern metadata without client capabilities receives an error");
    if (missing_capabilities) {
        check(missing_capabilities->at("error").at("code").as_integer() == -32602,
              "modern requests require a clientCapabilities object");
    }

    auto missing_client_info = server.handle(JsonValue::object({
        {"jsonrpc", "2.0"}, {"id", 105}, {"method", "tools/list"},
        {"params", JsonValue::object({
            {"_meta", JsonValue::object({
                {"io.modelcontextprotocol/protocolVersion", "2026-07-28"},
                {"io.modelcontextprotocol/clientCapabilities", JsonValue::object({})}
            })}
        })}
    }));
    check(missing_client_info.has_value() && missing_client_info->contains("result"),
          "modern clientInfo is optional when protocolVersion and clientCapabilities are present");

    auto incomplete_modern_meta = server.handle(JsonValue::object({
        {"jsonrpc", "2.0"}, {"id", 106}, {"method", "tools/list"},
        {"params", JsonValue::object({
            {"_meta", JsonValue::object({
                {"io.modelcontextprotocol/clientInfo", JsonValue::object({
                    {"name", "incomplete-client"}, {"version", "1"}
                })},
                {"io.modelcontextprotocol/clientCapabilities", JsonValue::object({})}
            })}
        })}
    }));
    check(incomplete_modern_meta.has_value() &&
              incomplete_modern_meta->at("error").at("code").as_integer() == -32602,
          "reserved modern metadata without protocolVersion is rejected instead of falling back to legacy");

    auto modern_ping = call_modern_request(server, 104, "ping", JsonValue::object({}));
    check(modern_ping.has_value(), "modern ping receives a method response");
    if (modern_ping) {
        check(modern_ping->at("error").at("code").as_integer() == -32601,
              "modern ping is not exposed as a legacy lifecycle method");
    }

    auto modern_tool_response = call_modern_tool(
        server, 105, "memory_debug.process_list", JsonValue::object({})
    );
    check(modern_tool_response.has_value(), "modern tools/call receives a response");
    if (modern_tool_response) {
        const auto& result = modern_tool_response->at("result");
        check(result.at("resultType").as_string() == "complete",
              "modern tools/call identifies a complete result");
        check(result.at("content").as_array().empty(),
              "modern tools/call does not duplicate structured JSON as TextContent");
        check(result.at("structuredContent").at("ok").as_bool(),
              "modern tools/call retains its structured payload");
        check(result.at("_meta").at("io.modelcontextprotocol/serverInfo").is_object(),
              "modern tools/call carries server identity metadata");
    }

    // End-to-end exercise of the scan-ergonomics surface. Advertising a schema
    // is not evidence the handler works, so each new capability is invoked.
    std::string session_id;
    {
        auto attached = call_tool(server, 3, "memory_debug.attach", JsonValue::object({
            {"pid", 4242}, {"authorized", true}, {"access", "read_only"}
        }));
        if (attached) {
            const auto& legacy_result = attached->at("result");
            const auto& content = legacy_result.at("content").as_array();
            check(legacy_result.find("resultType") == nullptr,
                  "legacy tools/call keeps its original result envelope");
            check(content.size() == 1U && content.front().at("type").as_string() == "text",
                  "legacy tools/call keeps its TextContent compatibility payload");
            if (content.size() == 1U) {
                check(content.front().at("text").as_string() ==
                          legacy_result.at("structuredContent").dump(),
                      "legacy TextContent remains the serialized structured payload");
            }
        }
        const auto* data = successful_tool_data(attached);
        check(data != nullptr, "attach succeeds in the contract flow");
        if (data != nullptr) session_id = data->at("session_id").as_string();
    }

    if (!session_id.empty()) {
        auto summary = call_tool(server, 4, "memory_debug.address_space_summary", JsonValue::object({
            {"session_id", session_id}
        }));
        const auto* data = successful_tool_data(summary);
        check(data != nullptr, "address_space_summary returns data");
        if (data != nullptr) {
            check(data->at("region_count").as_integer() == 3, "summary counts every region");
            // Readable: heap-main (0x10) + image.text (0x20). The guard page is
            // unreadable and must not be counted as scannable.
            check(data->at("scannable_bytes").as_integer() == 0x30,
                  "summary counts only readable bytes as scannable");
            check(data->at("scannable_writable_bytes").as_integer() == 0x10,
                  "summary separates readable+writable bytes");
        }

        auto filtered = call_tool(server, 5, "memory_debug.regions", JsonValue::object({
            {"session_id", session_id}, {"writable", true}
        }));
        data = successful_tool_data(filtered);
        check(data != nullptr, "filtered regions returns data");
        if (data != nullptr) {
            check(data->at("total_matched").as_integer() == 1, "regions filters by attribute server-side");
            const auto& matched = data->at("regions").as_array();
            check(matched.size() == 1U && matched.front().at("name").as_string() == "heap-main",
                  "regions returns the matching region");
        }

        auto paged = call_tool(server, 6, "memory_debug.regions", JsonValue::object({
            {"session_id", session_id}, {"offset", 1}, {"limit", 1}
        }));
        data = successful_tool_data(paged);
        check(data != nullptr, "paged regions returns data");
        if (data != nullptr) {
            check(data->at("total_matched").as_integer() == 3, "regions reports the full match count");
            check(data->at("returned").as_integer() == 1, "regions honours limit");
            check(data->at("truncated").as_bool(), "regions flags a partial page");
            const auto& page_rows = data->at("regions").as_array();
            check(page_rows.size() == 1U && page_rows.front().at("name").as_string() == "image.text",
                  "regions honours the requested offset");
        }

        auto by_name = call_tool(server, 7, "memory_debug.regions", JsonValue::object({
            {"session_id", session_id}, {"name_contains", "IMAGE"}
        }));
        data = successful_tool_data(by_name);
        check(data != nullptr, "name-filtered regions returns data");
        if (data != nullptr) {
            check(data->at("total_matched").as_integer() == 1, "regions matches name case-insensitively");
        }

        // The decimal form must find the same i32 the hex form would, without
        // the caller hand-encoding little-endian bytes.
        auto scan = call_tool(server, 8, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"},
            {"comparison", "exact"}, {"value_decimal", "42"}
        }));
        data = successful_tool_data(scan);
        check(data != nullptr, "scan_first accepts a decimal value");
        std::string decimal_scan_id;
        if (data != nullptr) {
            decimal_scan_id = data->at("scan_id").as_string();
            check(data->at("candidate_count").as_integer() == 1,
                  "scan_first(value_decimal) finds the value");
            const auto& coverage = data->at("coverage");
            check(coverage.at("bytes_eligible").as_integer() == 0x30,
                  "coverage reports the full eligible size");
            // image.text is outside the fixture's readable window, so the sweep
            // is genuinely partial -- and must say so rather than claim success.
            check(!coverage.at("complete").as_bool(),
                  "coverage marks a sweep shortened by an unreadable region as incomplete");
            check(!coverage.at("truncated_by_budget").as_bool(),
                  "a failed read is not misreported as budget truncation");
        }

        if (!decimal_scan_id.empty()) {
            auto decimal_next = call_tool(server, 14, "memory_debug.scan_next", JsonValue::object({
                {"scan_id", decimal_scan_id}, {"comparison", "exact"}, {"value_decimal", "42"}
            }));
            data = successful_tool_data(decimal_next);
            check(data != nullptr && data->at("candidate_count").as_integer() == 1,
                  "scan_next reuses the session type to encode value_decimal");

            auto conflicting_next = call_tool(server, 15, "memory_debug.scan_next", JsonValue::object({
                {"scan_id", decimal_scan_id}, {"comparison", "exact"},
                {"value", "2a000000"}, {"value_decimal", "42"}
            }));
            check(is_invalid_arguments(conflicting_next),
                  "scan_next rejects simultaneous hexadecimal and decimal values");

            auto results_page = call_tool(server, 16, "memory_debug.scan_results", JsonValue::object({
                {"scan_id", decimal_scan_id}, {"offset", 0}, {"limit", 1}
            }));
            data = successful_tool_data(results_page);
            check(data != nullptr && data->at("total").as_integer() == 1 &&
                      data->at("returned").as_integer() == 1 &&
                      data->at("offset").as_integer() == 0 &&
                      !data->at("truncated").as_bool() &&
                      data->at("matches").as_array().size() == 1U,
                  "scan_results returns atomic pagination and generation metadata with its matches");
        }

        auto conflicting = call_tool(server, 9, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "exact"},
            {"value", "2a000000"}, {"value_decimal", "42"}
        }));
        check(is_invalid_arguments(conflicting),
              "scan_first rejects value and value_decimal supplied together");

        auto overflowing = call_tool(server, 10, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "u8"}, {"comparison", "exact"},
            {"value_decimal", "300"}
        }));
        check(is_invalid_arguments(overflowing),
              "scan_first rejects a decimal value wider than value_type");

        auto decimal_range = call_tool(server, 11, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "in_range"},
            {"range_low_decimal", "41"}, {"range_high_decimal", "43"},
            {"start_address", "0x1000"}, {"end_address", "0x1010"},
            {"byte_budget", 16}, {"result_limit", 8}
        }));
        data = successful_tool_data(decimal_range);
        check(data != nullptr, "scan_first accepts a paired decimal range");
        if (data != nullptr) {
            check(data->at("candidate_count").as_integer() == 1,
                  "scan_first encodes both decimal range endpoints");
        }

        auto incomplete_range = call_tool(server, 12, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "in_range"},
            {"range_low_decimal", "41"}
        }));
        check(is_invalid_arguments(incomplete_range),
              "scan_first rejects a decimal range with only one endpoint");

        auto legacy_hex = call_tool(server, 13, "memory_debug.scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "exact"},
            {"value", "2a000000"},
            {"start_address", "0x1000"}, {"end_address", "0x1010"},
            {"byte_budget", 16}, {"result_limit", 8}
        }));
        data = successful_tool_data(legacy_hex);
        check(data != nullptr, "scan_first preserves hexadecimal input compatibility");
        if (data != nullptr) {
            check(data->at("candidate_count").as_integer() == 1,
                  "the existing hexadecimal form still finds the same value");
        }
    }

    if (!session_id.empty()) {
        auto inspected = call_tool(server, 20, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"lookbehind_bytes", 0}
        }));
        const auto* data = successful_tool_data(inspected);
        check(data != nullptr, "inspect_address returns data");
        if (data != nullptr) {
            check(data->at("pointer_size").as_string() == "8",
                  "inspect_address echoes the target pointer width as a string");
            check(data->at("region").at("name").as_string() == "heap-main",
                  "inspect_address reports the region containing the address");
            check(data->at("region").at("writable").as_bool(), "inspect_address reports protections");
            // The contract target loads no modules, so the honest answer is
            // null and an empty candidate list -- not a synthesized module.
            check(data->at("module").is_null(), "an address with no owning module serializes as null");
            check(data->at("object_candidates").as_array().empty(),
                  "no module means no probable vtable shape");
            check(data->at("object_candidates_total").as_integer() == 0,
                  "the candidate total stays zero");
            check(!data->at("object_candidates_truncated").as_bool(), "nothing was truncated");
            check(data->at("references").is_null(), "references are absent unless requested");
            check(data->at("analysis").at("complete").as_bool(),
                  "a fully readable window reports a complete analysis");
            check(data->at("analysis").at("limitations").as_array().empty(),
                  "a complete analysis lists no limitation");
            check(data->at("sampled_at_ms").as_integer() > 0,
                  "the response carries the sampling timestamp");
        }

        // A window the region cannot supply in full is a partial analysis, and
        // saying so is what keeps an absent candidate from reading as absence
        // of the thing itself.
        auto clamped = call_tool(server, 210, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"lookbehind_bytes", 4096}
        }));
        data = successful_tool_data(clamped);
        check(data != nullptr, "inspect_address answers when the lookbehind exceeds the region");
        if (data != nullptr) {
            check(!data->at("analysis").at("complete").as_bool(),
                  "a clamped lookbehind reports an incomplete analysis");
            const auto& limitations = data->at("analysis").at("limitations").as_array();
            check(!limitations.empty() &&
                      limitations.front().as_string() == "lookbehind_clamped_to_region",
                  "the limitation names the clamping");
            check(data->at("analysis").at("lookbehind_bytes_requested").as_integer() == 4096,
                  "the requested window is echoed");
            check(data->at("analysis").at("lookbehind_bytes_read").as_integer() < 4096,
                  "the window actually read is reported separately");
        }

        auto guarded = call_tool(server, 21, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x3004"}, {"pointer_size", "8"}
        }));
        data = successful_tool_data(guarded);
        check(data != nullptr, "inspect_address answers for an unreadable region");
        if (data != nullptr) {
            check(!data->at("region").at("readable").as_bool(),
                  "an unreadable region is described, not hidden");
            check(!data->at("analysis").at("complete").as_bool(),
                  "an unreadable region makes the analysis incomplete");
            const auto& limitations = data->at("analysis").at("limitations").as_array();
            check(!limitations.empty() && limitations.front().as_string() == "region_not_readable",
                  "the limitation names the unreadable region");
        }

        auto references = call_tool(server, 22, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"references", JsonValue::object({
                {"mode", "live_scan"}, {"byte_budget", 65536}, {"result_limit", 8},
                {"start_address", "0x1000"}, {"end_address", "0x1010"}
            })}
        }));
        data = successful_tool_data(references);
        check(data != nullptr, "inspect_address runs a budgeted live reference slice");
        if (data != nullptr) {
            const auto& report = data->at("references");
            check(report.at("mode").as_string() == "live_scan", "the reference mode is echoed");
            check(report.at("budget").at("byte_budget").as_integer() == 65536,
                  "the reference budget is reported back");
            check(report.at("matches").as_array().empty(), "no reference exists in the swept range");
            check(report.at("coverage").at("complete").as_bool(),
                  "a fully swept range reports complete coverage");
            check(report.at("resume_token").is_null(), "a complete sweep offers no continuation");
            check(report.at("next_start_address").is_null(), "the diagnostic address is null when done");
            check(report.at("next_cursor").is_null(), "the index cursor stays null in live_scan mode");
            check(report.at("truncation_reasons").as_array().empty(), "nothing truncated the slice");
        }

        // The same query over a range the backend cannot fully read must stay
        // distinguishable from the conclusive empty result above.
        auto partial_references = call_tool(server, 220, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"references", JsonValue::object({
                {"mode", "live_scan"}, {"byte_budget", 65536}, {"result_limit", 8}
            })}
        }));
        data = successful_tool_data(partial_references);
        check(data != nullptr, "inspect_address answers when a region cannot be read");
        if (data != nullptr) {
            const auto& report = data->at("references");
            check(report.at("matches").as_array().empty(), "no reference was found");
            check(!report.at("coverage").at("complete").as_bool(),
                  "an empty result over incomplete coverage is not conclusive");
            check(report.at("coverage").at("coverage_ratio").as_number() < 1.0,
                  "the coverage ratio shows how much was actually swept");
            const auto& reasons = report.at("truncation_reasons").as_array();
            check(!reasons.empty() && reasons.front().as_string() == "region_read_failed",
                  "the reason names the unreadable region");
        }

        check(is_invalid_arguments(call_tool(server, 23, "memory_debug.inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "6"}
              }))),
              "inspect_address rejects a pointer size that is not 4 or 8");

        check(is_invalid_arguments(call_tool(server, 24, "memory_debug.inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
                  {"references", JsonValue::object({
                      {"mode", "live_scan"}, {"byte_budget", 4096}, {"result_limit", 8},
                      {"index_id", "idx"}
                  })}
              }))),
              "index_id is rejected with reference mode live_scan");

        check(is_invalid_arguments(call_tool(server, 25, "memory_debug.inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
                  {"references", JsonValue::object({
                      {"mode", "index"}, {"index_id", "idx"}, {"byte_budget", 4096}
                  })}
              }))),
              "byte_budget is rejected with reference mode index");

        auto impossible = call_tool(server, 26, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"min_executable_entries", 9}, {"vtable_entries", 4}
        }));
        check(impossible.has_value() && impossible->at("result").at("isError").as_bool(),
              "a minimum larger than the vtable sample is rejected");

        auto unsupported_index = call_tool(server, 27, "memory_debug.inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"references", JsonValue::object({{"mode", "index"}, {"index_id", "idx"}})}
        }));
        check(unsupported_index.has_value() &&
                  unsupported_index->at("result").at("structuredContent").at("error")
                      .at("code").as_string() == "unsupported",
              "an unimplemented reference source reports unsupported instead of downgrading");
    }

    // The Unreal runtime surface must not exist at all under default policy,
    // and a request can never be what turns it on.
    {
        const auto& tools = catalog.definitions();
        const bool advertises_runtime = std::ranges::any_of(tools, [](const auto& tool) {
            return tool.name.starts_with("memory_debug.unreal_runtime_");
        });
        check(!advertises_runtime, "unreal runtime tools are absent while the feature gate is off");

        auto refused = call_tool(server, 30, "memory_debug.unreal_runtime_discover", JsonValue::object({
            {"session_id", session_id}, {"profile_id", "ue5-fproperty-x64"}
        }));
        // An unadvertised tool is not dispatchable at all, so this arrives as a
        // JSON-RPC error rather than as a tool result.
        const bool rejected = !refused.has_value() || refused->find("error") != nullptr ||
            refused->at("result").at("isError").as_bool();
        check(rejected, "calling a gated tool without the gate fails");

        argos::security::SecurityPolicy enabled;
        enabled.enable_unreal_runtime = true;
        enabled.unreal_profile_allowlist = {"ue5-fproperty-x64"};
        argos::application::MemoryDebugService enabled_service{
            std::make_unique<ContractProvider>(), enabled
        };
        argos::protocol::mcp::ToolCatalog enabled_catalog{enabled_service, logger};
        std::size_t runtime_tools = 0;
        const argos::protocol::mcp::ToolDefinition* discover = nullptr;
        for (const auto& tool : enabled_catalog.definitions()) {
            if (tool.name.starts_with("memory_debug.unreal_runtime_")) {
                ++runtime_tools;
                if (tool.name == "memory_debug.unreal_runtime_discover") discover = &tool;
            }
        }
        check(runtime_tools == 5U, "enabling the feature advertises the full runtime surface");
        if (discover != nullptr) {
            const auto& profiles = discover->input_schema.at("properties").at("profile_id")
                .at("enum").as_array();
            check(profiles.size() == 1U && profiles.front().as_string() == "ue5-fproperty-x64",
                  "only allowlisted profiles are offered to the client");
            const auto& roots = discover->input_schema.at("properties").at("roots");
            check(roots.at("oneOf").as_array().size() == 2U,
                  "root forms are declared as mutually exclusive alternatives");
        }
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
