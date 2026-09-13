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
    explicit ContractSession(const argos::domain::AccessMode access, const bool native = false)
        : access_(access), native_(native) {
        memory_[4] = std::byte{0x2A};  // i32 42 at 0x1004, little-endian.
        if (!native) return;
        memory_.assign(4096, std::byte{});
        const auto number = [this](const std::size_t rva, const std::uint64_t value, const std::size_t width) {
            for (std::size_t i = 0; i < width; ++i) memory_[rva + i] = static_cast<std::byte>((value >> (8U * i)) & 255U);
        };
        std::size_t next_name = 0x800;
        const auto name = [this, &next_name](const std::string_view text) {
            const auto pointer = 0x1000U + next_name;
            for (const char c : text) memory_[next_name++] = static_cast<std::byte>(c);
            memory_[next_name++] = std::byte{};
            return pointer;
        };
        number(0x100, name("tContract"), 8);
        number(0x110, 16, 8);
        number(0x118, 8, 8);
        number(0x124, 1, 4);
        number(0x128, 0xFFFF, 2);
        number(0x200, name("Mode"), 8);
        number(0x212, 4, 2);
        number(0x214, 4, 1);  // unsigned primitive with enum index 0
        number(0x218, 0xFFFF, 2);
        number(0x300, name("ContractMode"), 8);
        number(0x30C, 1, 4);
        number(0x310, 0x1500, 8);
        number(0x318, 0x1510, 8);
        number(0x500, name("Active"), 8);
        number(0x510, 7, 8);
        number(0x400, name("DescribeContract"), 8);
        number(0x408, 0x1600, 8);
        number(0x410, name("v"), 8);
        // Resource store (ADR-0028): root slot -> wallet set -> records, with
        // ResourcesPerm immediately before its definitions.
        number(0xB00, 0x1000U + 0xB08U, 8);
        number(0xB18, 0x1000U + 0xC00U, 8);
        number(0xB28, 2, 4);
        number(0xC28, 0x1000U + 0xD00U, 8);
        number(0xC30, 5, 4);
        number(0xC38, 3, 4);
        number(0xC68, 0x1000U + 0xD40U, 8);
        number(0xC70, 0xFFFFFFFFU, 4);
        number(0xC78, 2, 4);
        number(0xC88, 0x1000U + 0xD00U, 8);
        number(0xC90, 2, 4);
        number(0xD00, name("ContractOre"), 8);
        number(0xD08, 11, 4);
        number(0xD28, 0xFFFFFFFFU, 4);
        number(0xD3C, 1, 1);
        number(0xD40, name("ContractKey"), 8);
        number(0xD48, 12, 4);
        number(0xD68, 1, 4);
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
        const argos::domain::Address address,
        const std::span<const std::byte> bytes
    ) override {
        // Only the native image accepts writes, and only through a read_write
        // session, so resource writes can be exercised end to end.
        constexpr argos::domain::Address base = 0x1000U;
        if (!native_ || access_ != argos::domain::AccessMode::read_write) {
            return std::unexpected(debug_error(
                argos::domain::DebugErrorCode::access_denied, "contract target is read-only"
            ));
        }
        if (address < base || address - base > memory_.size() ||
            bytes.size() > memory_.size() - static_cast<std::size_t>(address - base)) {
            return std::unexpected(debug_error(
                argos::domain::DebugErrorCode::io_error, "write is outside contract memory"
            ));
        }
        std::copy(bytes.begin(), bytes.end(),
                  memory_.begin() + static_cast<std::ptrdiff_t>(address - base));
        return bytes.size();
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        if (native_) return std::vector<argos::domain::MemoryRegion>{{0x1000U, 0x2000U, true, false, false, false, "image"}};
        return std::vector<argos::domain::MemoryRegion>{
            {0x1000U, 0x1010U, true, true, false, true, "heap-main"},
            {0x2000U, 0x2020U, true, false, true, false, "image.text"},
            {0x3000U, 0x3008U, false, false, false, true, "guard"}
        };
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        if (native_) return std::vector<argos::domain::ModuleInfo>{{"Contract.exe", "C:/synthetic", 0x1000U, 4096U}};
        return std::vector<argos::domain::ModuleInfo>{};
    }

private:
    argos::domain::AccessMode access_;
    bool native_{};
    std::vector<std::byte> memory_ = std::vector<std::byte>(16);
};

class ContractProvider final : public argos::domain::ProcessMemoryProvider {
public:
    explicit ContractProvider(const bool native = false) : native_(native) {}
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
        std::unique_ptr<argos::domain::ProcessSession> session = std::make_unique<ContractSession>(access, native_);
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
private:
    bool native_{};
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

    const auto legacy_unknown = call_tool(server, 903, "memory_debug_no_such_tool", JsonValue::object({}));
    check(legacy_unknown.has_value() && legacy_unknown->contains("error") &&
              legacy_unknown->at("error").at("code").as_integer() == -32602 &&
              !legacy_unknown->contains("result"),
          "legacy unknown tool is a JSON-RPC invalid-params error");
    const auto modern_unknown = call_modern_tool(
        server, 904, "memory_debug_no_such_tool", JsonValue::object({})
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
                    {"name", "memory_debug_scan_exact"},
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
        check(tools.size() >= 30U, "tool catalog exposes the runtime debugging tools");
        for (const auto& tool : tools) {
            check(!tool.at("name").as_string().starts_with("memory_debug_santamonica_runtime_"),
                  "Santa Monica tools stay absent in legacy MCP while the gate is off");
        }
        bool has_scan_start = false;
        bool has_job_status = false;
        bool has_job_results = false;
        bool has_job_cancel = false;
        bool has_job_release = false;
        bool scan_start_offers_resume_variant = false;
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
        // Both of the checks below guard the same observed failure mode: a
        // client that validates the tool list rejects the whole array, so a
        // single malformed entry makes *every* tool disappear with no visible
        // error -- the server still reports as connected, just with nothing
        // callable. A bare oneOf inputSchema root and a name outside
        // ^[A-Za-z0-9_-]{1,128}$ have each caused exactly that.
        bool all_tools_have_object_input_schema = true;
        bool all_tool_names_are_client_safe = true;
        const auto name_is_client_safe = [](const std::string& value) {
            if (value.empty() || value.size() > 128U) return false;
            for (const char character : value) {
                const bool allowed = (character >= 'a' && character <= 'z') ||
                                     (character >= 'A' && character <= 'Z') ||
                                     (character >= '0' && character <= '9') ||
                                     character == '_' || character == '-';
                if (!allowed) return false;
            }
            return true;
        };
        bool detach_is_destructive = false;
        for (const auto& tool : tools) {
            const auto name = tool.at("name").as_string();
            all_tools_have_output_schema = all_tools_have_output_schema &&
                tool.contains("outputSchema") && tool.at("outputSchema").is_object();
            all_tools_have_object_input_schema = all_tools_have_object_input_schema &&
                tool.contains("inputSchema") && tool.at("inputSchema").is_object() &&
                tool.at("inputSchema").contains("type") &&
                tool.at("inputSchema").at("type").as_string() == "object";
            all_tool_names_are_client_safe =
                all_tool_names_are_client_safe && name_is_client_safe(name);
            if (name == "memory_debug_detach") {
                detach_is_destructive = tool.at("annotations").at("destructiveHint").as_bool();
            }
            if (name == "memory_debug_regions") {
                const auto& properties = tool.at("inputSchema").at("properties");
                regions_supports_filtering = properties.find("writable") != nullptr &&
                    properties.find("offset") != nullptr && properties.find("limit") != nullptr;
            }
            if (name == "memory_debug_scan_first") {
                const auto& properties = tool.at("inputSchema").at("properties");
                scan_first_accepts_decimal = properties.find("value_decimal") != nullptr;
            }
            if (name == "memory_debug_scan_next") {
                const auto& properties = tool.at("inputSchema").at("properties");
                scan_next_accepts_decimal = properties.find("value_decimal") != nullptr &&
                    properties.find("delta_decimal") != nullptr;
            }
            has_address_space_summary =
                has_address_space_summary || name == "memory_debug_address_space_summary";
            has_pdb_type = has_pdb_type || name == "memory_debug_pdb_type";
            has_unity_type = has_unity_type || name == "memory_debug_unity_type";
            has_unreal_type = has_unreal_type || name == "memory_debug_unreal_type";
            has_unreal_reflection = has_unreal_reflection || name == "memory_debug_unreal_reflection";
            has_strings = has_strings || name == "memory_debug_strings";
            has_scan_pointers_to = has_scan_pointers_to || name == "memory_debug_scan_pointers_to";
            has_scan_pointer_chains = has_scan_pointer_chains || name == "memory_debug_scan_pointer_chains";
            has_pdb_list_types = has_pdb_list_types || name == "memory_debug_pdb_list_types";
            has_scan_first = has_scan_first || name == "memory_debug_scan_first";
            has_scan_next = has_scan_next || name == "memory_debug_scan_next";
            has_scan_results = has_scan_results || name == "memory_debug_scan_results";
            has_scan_reset = has_scan_reset || name == "memory_debug_scan_reset";
            has_launch = has_launch || name == "memory_debug_launch";
            has_read_output = has_read_output || name == "memory_debug_read_output";
            has_scan_start = has_scan_start || name == "memory_debug_scan_start";
            has_job_status = has_job_status || name == "memory_debug_job_status";
            has_job_results = has_job_results || name == "memory_debug_job_results";
            has_job_cancel = has_job_cancel || name == "memory_debug_job_cancel";
            has_job_release = has_job_release || name == "memory_debug_job_release";
            if (name == "memory_debug_scan_start") {
                const auto& one_of = tool.at("inputSchema").at("oneOf").as_array();
                scan_start_offers_resume_variant = one_of.size() == 2U;
            }
        }
        check(all_tools_have_object_input_schema,
              "every tool advertises an object inputSchema; a bare oneOf root drops the whole catalog");
        check(all_tool_names_are_client_safe,
              "every tool name matches ^[A-Za-z0-9_-]{1,128}$ enforced by MCP clients");
        check(has_pdb_type, "tool catalog exposes PDB type metadata");
        check(has_unity_type, "tool catalog exposes Unity metadata");
        check(has_unreal_type, "tool catalog exposes Unreal type metadata");
        check(has_unreal_reflection, "tool catalog exposes Unreal reflection metadata");
        check(has_strings, "tool catalog exposes memory_debug_strings");
        check(has_scan_pointers_to, "tool catalog exposes memory_debug_scan_pointers_to");
        check(has_scan_pointer_chains, "tool catalog exposes memory_debug_scan_pointer_chains");
        check(has_pdb_list_types, "tool catalog exposes memory_debug_pdb_list_types");
        check(has_scan_first, "tool catalog exposes memory_debug_scan_first");
        check(has_scan_next, "tool catalog exposes memory_debug_scan_next");
        check(has_scan_results, "tool catalog exposes memory_debug_scan_results");
        check(has_scan_reset, "tool catalog exposes memory_debug_scan_reset");
        check(has_launch, "tool catalog exposes memory_debug_launch");
        check(has_read_output, "tool catalog exposes memory_debug_read_output");
        check(has_address_space_summary, "tool catalog exposes memory_debug_address_space_summary");
        check(regions_supports_filtering, "memory_debug_regions advertises filtering and paging");
        check(scan_first_accepts_decimal, "memory_debug_scan_first advertises value_decimal");
        check(scan_next_accepts_decimal, "memory_debug_scan_next advertises decimal value and delta");
        check(all_tools_have_output_schema, "every tool advertises its structured result schema");
        check(detach_is_destructive,
              "detach is conservatively destructive because terminate=true can stop a process");
        check(has_scan_start, "tool catalog exposes memory_debug_scan_start (Spec 0008)");
        check(has_job_status, "tool catalog exposes memory_debug_job_status (Spec 0008)");
        check(has_job_results, "tool catalog exposes memory_debug_job_results (Spec 0008)");
        check(has_job_cancel, "tool catalog exposes memory_debug_job_cancel (Spec 0008)");
        check(has_job_release, "tool catalog exposes memory_debug_job_release (Spec 0008)");
        check(scan_start_offers_resume_variant, "scan_start advertises both the fresh and resume_token input shapes");
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
        for (const auto& tool : tools) {
            check(!tool.at("name").as_string().starts_with("memory_debug_santamonica_runtime_"),
                  "Santa Monica tools stay absent in modern MCP while the gate is off");
        }
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
        server, 105, "memory_debug_process_list", JsonValue::object({})
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
        auto attached = call_tool(server, 3, "memory_debug_attach", JsonValue::object({
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
        auto summary = call_tool(server, 4, "memory_debug_address_space_summary", JsonValue::object({
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

        auto filtered = call_tool(server, 5, "memory_debug_regions", JsonValue::object({
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

        auto paged = call_tool(server, 6, "memory_debug_regions", JsonValue::object({
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

        auto by_name = call_tool(server, 7, "memory_debug_regions", JsonValue::object({
            {"session_id", session_id}, {"name_contains", "IMAGE"}
        }));
        data = successful_tool_data(by_name);
        check(data != nullptr, "name-filtered regions returns data");
        if (data != nullptr) {
            check(data->at("total_matched").as_integer() == 1, "regions matches name case-insensitively");
        }

        // The decimal form must find the same i32 the hex form would, without
        // the caller hand-encoding little-endian bytes.
        auto scan = call_tool(server, 8, "memory_debug_scan_first", JsonValue::object({
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
            auto decimal_next = call_tool(server, 14, "memory_debug_scan_next", JsonValue::object({
                {"scan_id", decimal_scan_id}, {"comparison", "exact"}, {"value_decimal", "42"}
            }));
            data = successful_tool_data(decimal_next);
            check(data != nullptr && data->at("candidate_count").as_integer() == 1,
                  "scan_next reuses the session type to encode value_decimal");

            auto conflicting_next = call_tool(server, 15, "memory_debug_scan_next", JsonValue::object({
                {"scan_id", decimal_scan_id}, {"comparison", "exact"},
                {"value", "2a000000"}, {"value_decimal", "42"}
            }));
            check(is_invalid_arguments(conflicting_next),
                  "scan_next rejects simultaneous hexadecimal and decimal values");

            auto results_page = call_tool(server, 16, "memory_debug_scan_results", JsonValue::object({
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

        auto conflicting = call_tool(server, 9, "memory_debug_scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "exact"},
            {"value", "2a000000"}, {"value_decimal", "42"}
        }));
        check(is_invalid_arguments(conflicting),
              "scan_first rejects value and value_decimal supplied together");

        auto overflowing = call_tool(server, 10, "memory_debug_scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "u8"}, {"comparison", "exact"},
            {"value_decimal", "300"}
        }));
        check(is_invalid_arguments(overflowing),
              "scan_first rejects a decimal value wider than value_type");

        auto decimal_range = call_tool(server, 11, "memory_debug_scan_first", JsonValue::object({
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

        auto incomplete_range = call_tool(server, 12, "memory_debug_scan_first", JsonValue::object({
            {"session_id", session_id}, {"value_type", "i32"}, {"comparison", "in_range"},
            {"range_low_decimal", "41"}
        }));
        check(is_invalid_arguments(incomplete_range),
              "scan_first rejects a decimal range with only one endpoint");

        auto legacy_hex = call_tool(server, 13, "memory_debug_scan_first", JsonValue::object({
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

    // Spec 0008 -- async scan operations. End-to-end start -> status ->
    // results -> cancel -> release across the JSON-RPC surface (the deep
    // engine behavior -- progress, concurrent cancellation, backpressure,
    // TTL -- is covered by the AnalysisJobManager unit tests).
    if (!session_id.empty()) {
        auto started = call_tool(server, 200, "memory_debug_scan_start", JsonValue::object({
            {"session_id", session_id},
            {"operation", "scan_exact"},
            {"request", JsonValue::object({
                {"pattern_hex", "2a000000"}, {"start_address", "0x1000"}, {"end_address", "0x1010"}
            })},
            {"execution", JsonValue::object({{"byte_budget", 64}, {"deadline_ms", 5000}})}
        }));
        const auto* start_data = successful_tool_data(started);
        check(start_data != nullptr, "scan_start accepts a well-formed scan_exact job");
        std::string job_id;
        if (start_data != nullptr) {
            check(start_data->at("job_kind").as_string() == "scan", "scan_start reports job_kind scan");
            check(start_data->at("operation").as_string() == "scan_exact", "scan_start echoes the chosen operation");
            const auto& state = start_data->at("state").as_string();
            check(state == "queued" || state == "running" || state == "completed",
                  "scan_start returns a job in a valid initial state");
            job_id = start_data->at("job_id").as_string();
        }

        if (!job_id.empty()) {
            argos::protocol::json::Value status_data;
            bool reached_terminal = false;
            for (int attempt = 0; attempt < 200'000 && !reached_terminal; ++attempt) {
                auto status = call_tool(server, 201, "memory_debug_job_status", JsonValue::object({
                    {"session_id", session_id}, {"job_id", job_id}
                }));
                const auto* data = successful_tool_data(status);
                if (data == nullptr) break;
                status_data = *data;
                const auto& state = status_data.at("state").as_string();
                reached_terminal = state == "completed" || state == "failed" || state == "cancelled";
            }
            check(reached_terminal, "job_status converges to a terminal state without any fixed sleep");
            if (reached_terminal) {
                check(status_data.at("state").as_string() == "completed",
                      "a tiny in-budget scan_exact job completes");
                check(status_data.at("results_available").as_bool(), "results_available once terminal");
                const auto& termination = status_data.at("termination");
                check(!termination.is_null(), "a terminal job always carries a termination block");
                if (!termination.is_null()) {
                    check(termination.at("stop_reason").as_string() == "range_exhausted",
                          "an untruncated sweep terminates as range_exhausted");
                    check(termination.at("coverage_complete").as_bool() && termination.at("results_complete").as_bool(),
                          "a full sweep reports complete coverage and results");
                    check(!termination.at("truncated").as_bool(), "a full sweep is not truncated");
                    check(termination.at("resume_token").is_null(),
                          "no resume_token is ever issued in this version");
                }
            }

            auto results = call_tool(server, 202, "memory_debug_job_results", JsonValue::object({
                {"session_id", session_id}, {"job_id", job_id}, {"offset", 0}, {"limit", 10}
            }));
            const auto* results_data = successful_tool_data(results);
            check(results_data != nullptr, "job_results returns data for a terminal job");
            if (results_data != nullptr) {
                const auto& items = results_data->at("items").as_array();
                check(items.size() == 1U && items.front().at("address").as_string() == "0x1004",
                      "job_results finds the same match the fixture memory contains");
                const auto& page = results_data->at("page");
                check(page.at("total").as_integer() == 1 && page.at("returned").as_integer() == 1 &&
                          !page.at("has_more").as_bool(),
                      "job_results pagination metadata matches a single-item result");
            }

            auto wrong_job = call_tool(server, 203, "memory_debug_job_status", JsonValue::object({
                {"session_id", session_id}, {"job_id", "does-not-exist"}
            }));
            check(!wrong_job.has_value() ? false : wrong_job->at("result").at("isError").as_bool(),
                  "job_status on an unknown job_id is an error");

            auto idempotent_cancel = call_tool(server, 204, "memory_debug_job_cancel", JsonValue::object({
                {"session_id", session_id}, {"job_id", job_id}
            }));
            const auto* cancel_data = successful_tool_data(idempotent_cancel);
            check(cancel_data != nullptr && cancel_data->at("state").as_string() == "completed",
                  "cancelling an already-completed job is idempotent and reports the winning state");

            auto released = call_tool(server, 205, "memory_debug_job_release", JsonValue::object({
                {"session_id", session_id}, {"job_id", job_id}
            }));
            const auto* released_data = successful_tool_data(released);
            check(released_data != nullptr && released_data->at("released").as_bool(),
                  "job_release succeeds on a terminal job");

            auto after_release = call_tool(server, 206, "memory_debug_job_status", JsonValue::object({
                {"session_id", session_id}, {"job_id", job_id}
            }));
            check(after_release.has_value() && after_release->at("result").at("isError").as_bool(),
                  "job_status after release reports the job as gone");
        }

        auto conflicting_start = call_tool(server, 207, "memory_debug_scan_start", JsonValue::object({
            {"session_id", session_id},
            {"operation", "scan_exact"},
            {"resume_token", "should-not-be-combined-with-operation"},
            {"request", JsonValue::object({{"pattern_hex", "2a"}})}
        }));
        check(is_invalid_arguments(conflicting_start),
              "scan_start rejects operation and resume_token supplied together");

        auto resume_attempt = call_tool(server, 208, "memory_debug_scan_start", JsonValue::object({
            {"session_id", session_id}, {"resume_token", "deadbeefdeadbeefdeadbeefdeadbeef"}
        }));
        if (resume_attempt) {
            const auto& structured = resume_attempt->at("result").at("structuredContent");
            check(!structured.at("ok").as_bool() && structured.at("error").at("code").as_string() == "unsupported" &&
                      structured.at("error").at("reason").as_string() == "resume_not_supported",
                  "resume_token continuation is a well-defined unsupported extension point, not a crash or a fake success");
        } else {
            check(false, "scan_start with only resume_token receives a response");
        }
    }

    if (!session_id.empty()) {
        auto inspected = call_tool(server, 20, "memory_debug_inspect_address", JsonValue::object({
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
        auto clamped = call_tool(server, 210, "memory_debug_inspect_address", JsonValue::object({
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

        auto guarded = call_tool(server, 21, "memory_debug_inspect_address", JsonValue::object({
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

        auto references = call_tool(server, 22, "memory_debug_inspect_address", JsonValue::object({
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
        auto partial_references = call_tool(server, 220, "memory_debug_inspect_address", JsonValue::object({
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

        check(is_invalid_arguments(call_tool(server, 23, "memory_debug_inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "6"}
              }))),
              "inspect_address rejects a pointer size that is not 4 or 8");

        check(is_invalid_arguments(call_tool(server, 24, "memory_debug_inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
                  {"references", JsonValue::object({
                      {"mode", "live_scan"}, {"byte_budget", 4096}, {"result_limit", 8},
                      {"index_id", "idx"}
                  })}
              }))),
              "index_id is rejected with reference mode live_scan");

        check(is_invalid_arguments(call_tool(server, 25, "memory_debug_inspect_address", JsonValue::object({
                  {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
                  {"references", JsonValue::object({
                      {"mode", "index"}, {"index_id", "idx"}, {"byte_budget", 4096}
                  })}
              }))),
              "byte_budget is rejected with reference mode index");

        auto impossible = call_tool(server, 26, "memory_debug_inspect_address", JsonValue::object({
            {"session_id", session_id}, {"address", "0x1004"}, {"pointer_size", "8"},
            {"min_executable_entries", 9}, {"vtable_entries", 4}
        }));
        check(impossible.has_value() && impossible->at("result").at("isError").as_bool(),
              "a minimum larger than the vtable sample is rejected");

        auto unsupported_index = call_tool(server, 27, "memory_debug_inspect_address", JsonValue::object({
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
            return tool.name.starts_with("memory_debug_unreal_runtime_");
        });
        check(!advertises_runtime, "unreal runtime tools are absent while the feature gate is off");

        auto refused = call_tool(server, 30, "memory_debug_unreal_runtime_discover", JsonValue::object({
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
            if (tool.name.starts_with("memory_debug_unreal_runtime_")) {
                ++runtime_tools;
                if (tool.name == "memory_debug_unreal_runtime_discover") discover = &tool;
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

    // The Santa Monica surface needs the gate *and* an operator-configured
    // peer. A request can never supply either, and the whole chain is exercised
    // against the controlled synthetic peer, never a game.
    {
        const auto& tools = catalog.definitions();
        const bool advertises = std::ranges::any_of(tools, [](const auto& tool) {
            return tool.name.starts_with("memory_debug_santamonica_runtime_");
        });
        check(!advertises, "santa monica tools are absent while the feature gate is off");

        auto refused = call_tool(server, 40, "memory_debug_santamonica_runtime_discover",
                                 JsonValue::object({{"session_id", session_id}}));
        const bool rejected = !refused.has_value() || refused->find("error") != nullptr ||
            refused->at("result").at("isError").as_bool();
        check(rejected, "calling the gated discovery without the gate fails");

        argos::security::SecurityPolicy gate_only;
        gate_only.enable_santamonica_runtime = true;
        argos::application::MemoryDebugService gate_only_service{
            std::make_unique<ContractProvider>(), gate_only
        };
        argos::protocol::mcp::ToolCatalog gate_only_catalog{gate_only_service, logger};
        const bool advertises_without_peer = std::ranges::any_of(
            gate_only_catalog.definitions(), [](const auto& tool) {
                return tool.name.starts_with("memory_debug_santamonica_runtime_");
            });
        check(!advertises_without_peer, "the gate alone does not advertise the surface");

#if defined(ARGOS_SANTAMONICA_PEER)
        argos::security::SecurityPolicy enabled;
        enabled.enable_santamonica_runtime = true;
        enabled.santamonica_peer_path = ARGOS_SANTAMONICA_PEER;
        argos::application::MemoryDebugService enabled_service{
            std::make_unique<ContractProvider>(), enabled
        };
        argos::protocol::mcp::ToolCatalog enabled_catalog{enabled_service, logger};
        argos::protocol::mcp::Server enabled_server{enabled_catalog, logger};

        std::size_t santamonica_tools = 0;
        for (const auto& tool : enabled_catalog.definitions()) {
            if (tool.name.starts_with("memory_debug_santamonica_runtime_")) ++santamonica_tools;
        }
        check(santamonica_tools == 6U, "enabling gate and peer advertises the full surface");

        std::string peer_session;
        auto attached = call_tool(enabled_server, 41, "memory_debug_attach", JsonValue::object({
            {"pid", 4242}, {"authorized", true}, {"access", "read_only"}
        }));
        if (const auto* data = successful_tool_data(attached); data != nullptr) {
            peer_session = data->at("session_id").as_string();
        }
        check(!peer_session.empty(), "attach succeeds for the santa monica flow");

        std::string runtime_id;
        if (!peer_session.empty()) {
            auto discovered = call_tool(enabled_server, 42,
                                        "memory_debug_santamonica_runtime_discover",
                                        JsonValue::object({{"session_id", peer_session}}));
            const auto* data = successful_tool_data(discovered);
            check(data != nullptr, "discovery against the controlled peer succeeds");
            if (data != nullptr) {
                runtime_id = data->at("runtime_id").as_string();
                check(data->at("profile_id").as_string() == "argos-controlled-peer",
                      "the published profile is the controlled peer, not a game build");
                check(data->at("source").as_string() == "controlled-synthetic",
                      "the payload says plainly that the peer is synthetic");
                check(data->at("consistency").as_string() == "validated_best_effort",
                      "a best-effort snapshot is never reported as stable");
                check(data->at("coverage_complete").as_bool(), "declared coverage is reported");
                const auto& counts = data->at("counts");
                check(counts.at("types").as_integer() == 3, "every streamed type is admitted");
                check(counts.at("fields").as_integer() == 5, "every streamed field is admitted");
                check(counts.at("enums").as_integer() == 1, "every streamed enum is admitted");
                check(counts.at("enum_values").as_integer() == 3, "every streamed enum value is admitted");
                check(counts.at("sli_functions").as_integer() == 2, "every streamed SLI entry is admitted");
            }
        }

        if (!runtime_id.empty()) {
            auto first_page = call_tool(enabled_server, 43, "memory_debug_santamonica_runtime_types",
                                        JsonValue::object({
                                            {"session_id", peer_session},
                                            {"runtime_id", runtime_id},
                                            {"limit", 2}
                                        }));
            const auto* page = successful_tool_data(first_page);
            check(page != nullptr, "the first type page is returned");
            std::string next_token;
            if (page != nullptr) {
                check(page->at("types").as_array().size() == 2U, "the page honors the limit");
                check(page->at("total_matched").as_integer() == 3, "paging reports the full match count");
                check(page->at("next_page_token").is_string(), "a further page is offered");
                if (page->at("next_page_token").is_string()) {
                    next_token = page->at("next_page_token").as_string();
                }
                const auto& first = page->at("types").as_array().front();
                check(first.at("type_id").is_string(), "metadata ids are opaque strings");
                check(first.at("name").as_string() == "SyntheticBase", "type names survive the chain");
            }
            if (!next_token.empty()) {
                auto second_page = call_tool(enabled_server, 44,
                                             "memory_debug_santamonica_runtime_types",
                                             JsonValue::object({
                                                 {"session_id", peer_session},
                                                 {"runtime_id", runtime_id},
                                                 {"limit", 2},
                                                 {"page_token", next_token}
                                             }));
                const auto* rest = successful_tool_data(second_page);
                check(rest != nullptr, "the continuation page is returned");
                if (rest != nullptr) {
                    check(rest->at("types").as_array().size() == 1U, "the last page holds the remainder");
                    check(rest->at("next_page_token").is_null(), "the final page offers no token");
                }
                // The token is bound to the query, not just to the context.
                auto crossed = call_tool(enabled_server, 45, "memory_debug_santamonica_runtime_enums",
                                         JsonValue::object({
                                             {"session_id", peer_session},
                                             {"runtime_id", runtime_id},
                                             {"page_token", next_token}
                                         }));
                check(crossed.has_value() && crossed->at("result").at("isError").as_bool(),
                      "a page token from another query is refused");
            }

            auto typed = call_tool(enabled_server, 46, "memory_debug_santamonica_runtime_type",
                                   JsonValue::object({
                                       {"session_id", peer_session},
                                       {"runtime_id", runtime_id},
                                       {"type_id", "2"},
                                       {"include_inherited", true}
                                   }));
            const auto* type_data = successful_tool_data(typed);
            check(type_data != nullptr, "one type is returned with its fields");
            if (type_data != nullptr) {
                check(type_data->at("type").at("name").as_string() == "SyntheticActor",
                      "the requested type is returned");
                check(type_data->at("type").at("base_type_id").as_string() == "1",
                      "the base type is reported as an opaque id");
                check(type_data->at("inheritance").as_array().size() == 1U,
                      "the inheritance chain is reported");
                const auto& fields = type_data->at("fields").as_array();
                check(fields.size() == 4U, "declared and inherited fields are returned");
                bool has_enum_field = false;
                bool has_pointer_field = false;
                for (const auto& field : fields) {
                    if (field.at("kind").as_string() == "enumeration") has_enum_field = true;
                    if (field.at("kind").as_string() == "pointer") has_pointer_field = true;
                }
                check(has_enum_field && has_pointer_field, "field kinds survive the whole chain");
            }

            auto without_inheritance = call_tool(enabled_server, 47,
                                                 "memory_debug_santamonica_runtime_type",
                                                 JsonValue::object({
                                                     {"session_id", peer_session},
                                                     {"runtime_id", runtime_id},
                                                     {"type_id", "2"},
                                                     {"include_inherited", false}
                                                 }));
            const auto* declared_only = successful_tool_data(without_inheritance);
            check(declared_only != nullptr && declared_only->at("fields").as_array().size() == 3U,
                  "inherited fields are only included on request");

            auto missing_type = call_tool(enabled_server, 48,
                                          "memory_debug_santamonica_runtime_type",
                                          JsonValue::object({
                                              {"session_id", peer_session},
                                              {"runtime_id", runtime_id},
                                              {"type_id", "9999"}
                                          }));
            check(missing_type.has_value() && missing_type->at("result").at("isError").as_bool(),
                  "an unknown type id is refused");

            auto enums = call_tool(enabled_server, 49, "memory_debug_santamonica_runtime_enums",
                                   JsonValue::object({
                                       {"session_id", peer_session}, {"runtime_id", runtime_id}
                                   }));
            const auto* enum_data = successful_tool_data(enums);
            check(enum_data != nullptr, "enums are returned");
            if (enum_data != nullptr) {
                const auto& entries = enum_data->at("enums").as_array();
                check(entries.size() == 1U, "the streamed enum is returned");
                if (!entries.empty()) {
                    const auto& values = entries.front().at("values").as_array();
                    check(values.size() == 3U, "every enum value is returned");
                    bool lossless = false;
                    for (const auto& value : values) {
                        if (value.at("value").as_string() == "18446744073709551615") lossless = true;
                    }
                    check(lossless, "a 64-bit enum value keeps its exact decimal spelling");
                }
            }

            auto functions = call_tool(enabled_server, 50,
                                       "memory_debug_santamonica_runtime_sli_functions",
                                       JsonValue::object({
                                           {"session_id", peer_session}, {"runtime_id", runtime_id}
                                       }));
            const auto* function_data = successful_tool_data(functions);
            check(function_data != nullptr, "SLI entries are returned");
            if (function_data != nullptr) {
                const auto& entries = function_data->at("sli_functions").as_array();
                check(entries.size() == 2U, "every SLI entry is returned");
                const bool none_invocable = std::ranges::none_of(entries, [](const auto& entry) {
                    return entry.at("invocable").as_bool();
                });
                check(none_invocable, "no SLI entry is ever reported as invocable");
            }

            auto foreign = call_tool(enabled_server, 51, "memory_debug_santamonica_runtime_types",
                                     JsonValue::object({
                                         {"session_id", session_id}, {"runtime_id", runtime_id}
                                     }));
            check(foreign.has_value() && foreign->at("result").at("isError").as_bool(),
                  "a context is invisible to a session that does not own it");

            auto released = call_tool(enabled_server, 52, "memory_debug_santamonica_runtime_release",
                                      JsonValue::object({
                                          {"session_id", peer_session}, {"runtime_id", runtime_id}
                                      }));
            check(successful_tool_data(released) != nullptr, "release succeeds");
            auto again = call_tool(enabled_server, 53, "memory_debug_santamonica_runtime_release",
                                   JsonValue::object({
                                       {"session_id", peer_session}, {"runtime_id", runtime_id}
                                   }));
            check(successful_tool_data(again) != nullptr, "release is idempotent for the owner");
            auto after_release = call_tool(enabled_server, 54,
                                           "memory_debug_santamonica_runtime_types",
                                           JsonValue::object({
                                               {"session_id", peer_session}, {"runtime_id", runtime_id}
                                           }));
            check(after_release.has_value() && after_release->at("result").at("isError").as_bool(),
                  "a released context answers no further query");

            // A fresh discovery gets a new snapshot identity, never the old one.
            auto rediscovered = call_tool(enabled_server, 55,
                                          "memory_debug_santamonica_runtime_discover",
                                          JsonValue::object({{"session_id", peer_session}}));
            const auto* second = successful_tool_data(rediscovered);
            check(second != nullptr, "a discovery after release succeeds");
            if (second != nullptr) {
                check(second->at("runtime_id").as_string() != runtime_id,
                      "a new discovery publishes a new context");
            }
        }
#endif
    }

    // Native path: parser -> policy -> application -> reader -> catalog -> MCP.
    {
        auto profiles = argos::security::parse_santamonica_build_profiles(
            "contract|gow2018-reflection-x64-v2|Contract.exe|4096|" + std::string(64, 'a') +
            "|100|150|800|A00|200|220|300|320|400|420|B00");
        check(profiles.has_value(), "native contract profile parses");
        argos::security::SecurityPolicy native_policy;
        native_policy.enable_santamonica_runtime = true;
        if (profiles) native_policy.santamonica_build_profiles = *profiles;
        argos::application::MemoryDebugService native_service{std::make_unique<ContractProvider>(true), native_policy};
        argos::protocol::mcp::ToolCatalog native_catalog{native_service, logger};
        argos::protocol::mcp::Server native_server{native_catalog, logger};
        auto attach = call_tool(native_server, 70, "memory_debug_attach", JsonValue::object({
            {"pid", 4242}, {"authorized", true}, {"access", "read_only"}}));
        if (const auto* attached = successful_tool_data(attach)) {
            const auto owner = attached->at("session_id").as_string();
            auto discover = call_tool(native_server, 71, "memory_debug_santamonica_runtime_discover",
                                      JsonValue::object({{"session_id", owner}}));
            if (const auto* found = successful_tool_data(discover)) {
                const auto runtime = found->at("runtime_id").as_string();
                const auto& counts = found->at("counts");
                check(found->at("source").as_string() == "native-type-table" &&
                      !found->at("coverage_complete").as_bool(), "native discovery preserves source and coverage");
                check(counts.at("types").as_integer() == 1 && counts.at("fields").as_integer() == 1 &&
                      counts.at("enums").as_integer() == 1 && counts.at("enum_values").as_integer() == 1 &&
                      counts.at("sli_functions").as_integer() == 1, "all configured native ranges reach the MCP catalog");
                auto page = call_tool(native_server, 72, "memory_debug_santamonica_runtime_types",
                                     JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}}));
                if (const auto* types = successful_tool_data(page); types && !types->at("types").as_array().empty()) {
                    const auto type_id = types->at("types").as_array().front().at("type_id").as_string();
                    auto detail = call_tool(native_server, 73, "memory_debug_santamonica_runtime_type",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"type_id", type_id}}));
                    if (const auto* type = successful_tool_data(detail)) {
                        check(type->at("fields").as_array().size() == 1 &&
                              type->at("fields").as_array().front().at("kind").as_string() == "enumeration",
                              "native enum fields are available through type detail");
                    }
                }
                const auto tool_failed = [](const std::optional<JsonValue>& response) {
                    return !response.has_value() || response->find("error") != nullptr ||
                        response->at("result").at("isError").as_bool();
                };
                check(found->at("resources_published").as_bool(), "a rooted profile publishes resources");
                auto resources = call_tool(native_server, 80, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}}));
                if (const auto* resource_page = successful_tool_data(resources)) {
                    const auto& entries = resource_page->at("resources").as_array();
                    check(entries.size() == 2U && resource_page->at("resource_count").as_integer() == 2,
                          "the synthetic store reaches the MCP surface");
                    if (entries.size() == 2U) {
                        check(entries[0].at("name").as_string() == "ContractOre" &&
                              entries[0].at("quantity").as_integer() == 5 &&
                              entries[0].at("acquired").as_bool() && entries[0].at("unlimited").as_bool() &&
                              entries[0].at("maximum").is_null(),
                              "an acquired uncapped resource is reported with its quantity");
                        check(entries[1].at("name").as_string() == "ContractKey" &&
                              !entries[1].at("acquired").as_bool() && entries[1].at("quantity").as_integer() == 0 &&
                              entries[1].at("maximum").as_integer() == 1,
                              "a never-acquired resource reports zero and its cap");
                    }
                    check(resource_page->at("consistency").as_string() == "validated_best_effort" &&
                          !resource_page->at("mutation_safe").as_bool(), "resource pages declare their consistency");
                } else {
                    check(false, "resources are readable from a read-only session");
                }
                auto filtered = call_tool(native_server, 81, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"name_contains", "ORE"},
                                       {"acquired_only", true}}));
                const auto* narrowed = successful_tool_data(filtered);
                check(narrowed != nullptr && narrowed->at("total_matched").as_integer() == 1,
                      "the resource filter is case-insensitive and honors acquired_only");
                auto first_page = call_tool(native_server, 82, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"limit", 1}}));
                const auto* paged = successful_tool_data(first_page);
                check(paged != nullptr && paged->at("next_page_token").is_string(),
                      "a partial resource page carries a continuation");
                if (paged != nullptr && paged->at("next_page_token").is_string()) {
                    const auto token = paged->at("next_page_token").as_string();
                    auto second_page = call_tool(native_server, 83, "memory_debug_santamonica_runtime_resources",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"limit", 1},
                                           {"page_token", token}}));
                    const auto* rest = successful_tool_data(second_page);
                    check(rest != nullptr && rest->at("resources").as_array().size() == 1U &&
                          rest->at("resources").as_array().front().at("name").as_string() == "ContractKey" &&
                          rest->at("next_page_token").is_null(),
                          "the continuation returns the last resource");
                    auto mixed = call_tool(native_server, 84, "memory_debug_santamonica_runtime_resources",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"refresh", true},
                                           {"page_token", token}}));
                    check(tool_failed(mixed), "refresh cannot continue an old page");
                    auto refreshed = call_tool(native_server, 86, "memory_debug_santamonica_runtime_resources",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"refresh", true}}));
                    const auto* renewed = successful_tool_data(refreshed);
                    check(renewed != nullptr && renewed->at("generation").as_integer() == 2,
                          "a refresh publishes a new generation");
                    auto stale = call_tool(native_server, 87, "memory_debug_santamonica_runtime_resources",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"limit", 1},
                                           {"page_token", token}}));
                    check(tool_failed(stale), "a page token from before a refresh is stale");
                }
                auto read_only_write = call_tool(native_server, 85, "memory_debug_santamonica_runtime_set_resource",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"name", "ContractOre"},
                                       {"quantity", 9}, {"confirmation", "AUTHORIZED_DEBUG_WRITE"}}));
                check(tool_failed(read_only_write), "a read-only session cannot set a resource");

                auto release = call_tool(native_server, 74, "memory_debug_santamonica_runtime_release",
                                         JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}}));
                check(successful_tool_data(release) != nullptr, "native context releases normally");
            }
        }
    }

    // Resource writes through a read_write session over the same synthetic image.
    {
        auto profiles = argos::security::parse_santamonica_build_profiles(
            "contract|gow2018-reflection-x64-v2|Contract.exe|4096|" + std::string(64, 'a') +
            "|100|150|800|A00|200|220|300|320|400|420|B00");
        check(profiles.has_value(), "the writable contract profile parses");
        argos::security::SecurityPolicy writable_policy;
        writable_policy.enable_santamonica_runtime = true;
        if (profiles) writable_policy.santamonica_build_profiles = *profiles;
        argos::application::MemoryDebugService writable_service{
            std::make_unique<ContractProvider>(true), writable_policy
        };
        argos::protocol::mcp::ToolCatalog writable_catalog{writable_service, logger};
        argos::protocol::mcp::Server writable_server{writable_catalog, logger};
        const auto tool_failed = [](const std::optional<JsonValue>& response) {
            return !response.has_value() || response->find("error") != nullptr ||
                response->at("result").at("isError").as_bool();
        };

        std::size_t resource_tools = 0;
        for (const auto& tool : writable_catalog.definitions()) {
            if (tool.name == "memory_debug_santamonica_runtime_resources" ||
                tool.name == "memory_debug_santamonica_runtime_set_resource") {
                ++resource_tools;
            }
        }
        check(resource_tools == 2U, "a rooted build profile advertises both resource tools");

        auto attach = call_tool(writable_server, 90, "memory_debug_attach", JsonValue::object({
            {"pid", 4242}, {"authorized", true}, {"access", "read_write"}}));
        const auto* attached = successful_tool_data(attach);
        check(attached != nullptr, "a read_write session attaches to the synthetic target");
        if (attached != nullptr) {
            const auto owner = attached->at("session_id").as_string();
            auto discover = call_tool(writable_server, 91, "memory_debug_santamonica_runtime_discover",
                                      JsonValue::object({{"session_id", owner}}));
            const auto* found = successful_tool_data(discover);
            check(found != nullptr, "a read_write session discovers the synthetic build");
            if (found != nullptr) {
                const auto runtime = found->at("runtime_id").as_string();
                const auto set = [&](const std::int64_t id, const std::string& resource,
                                     const std::int64_t quantity, const std::string& confirmation) {
                    return call_tool(writable_server, id, "memory_debug_santamonica_runtime_set_resource",
                        JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"name", resource},
                                           {"quantity", quantity}, {"confirmation", confirmation}}));
                };
                auto warm = call_tool(writable_server, 92, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}}));
                check(successful_tool_data(warm) != nullptr, "the store is readable before a write");

                auto written = set(93, "ContractOre", 9, "AUTHORIZED_DEBUG_WRITE");
                if (const auto* outcome = successful_tool_data(written)) {
                    check(outcome->at("previous").as_integer() == 5 && outcome->at("observed").as_integer() == 9 &&
                          outcome->at("requested").as_integer() == 9 && outcome->at("verified").as_bool(),
                          "a resource write is verified by reading it back");
                    check(outcome->at("mechanism").as_string() == "direct_balance_write" &&
                          !outcome->at("engine_transaction").as_bool(),
                          "a resource write never claims an engine transaction");
                } else {
                    check(false, "an acquired resource can be set");
                }
                auto cached = call_tool(writable_server, 94, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime},
                                       {"name_contains", "ContractOre"}}));
                const auto* after = successful_tool_data(cached);
                check(after != nullptr && after->at("resources").as_array().size() == 1U &&
                      after->at("resources").as_array().front().at("quantity").as_integer() == 9,
                      "a write invalidates the cached snapshot");
                check(tool_failed(set(95, "ContractKey", 1, "AUTHORIZED_DEBUG_WRITE")),
                      "a never-acquired resource cannot be set");
                check(tool_failed(set(96, "ContractOre", 7, "please")), "a write without the phrase is refused");
                check(tool_failed(set(97, "MissingResource", 1, "AUTHORIZED_DEBUG_WRITE")),
                      "an unknown resource name is refused");
                check(tool_failed(set(98, "contractore", 1, "AUTHORIZED_DEBUG_WRITE")),
                      "the resource name used for a write is exact");
                auto unchanged = call_tool(writable_server, 99, "memory_debug_santamonica_runtime_resources",
                    JsonValue::object({{"session_id", owner}, {"runtime_id", runtime}, {"refresh", true},
                                       {"name_contains", "ContractOre"}}));
                const auto* kept = successful_tool_data(unchanged);
                check(kept != nullptr && kept->at("resources").as_array().front().at("quantity").as_integer() == 9,
                      "refused writes leave the balance untouched");
            }
        }
    }

    // A profile without a resource root advertises no resource tool.
    {
        auto profiles = argos::security::parse_santamonica_build_profiles(
            "contract|gow2018-reflection-x64-v2|Contract.exe|4096|" + std::string(64, 'a') +
            "|100|150|800|A00|200|220|300|320|400|420");
        argos::security::SecurityPolicy unrooted_policy;
        unrooted_policy.enable_santamonica_runtime = true;
        if (profiles) unrooted_policy.santamonica_build_profiles = *profiles;
        argos::application::MemoryDebugService unrooted_service{
            std::make_unique<ContractProvider>(true), unrooted_policy
        };
        argos::protocol::mcp::ToolCatalog unrooted_catalog{unrooted_service, logger};
        const bool advertises_resources = std::ranges::any_of(unrooted_catalog.definitions(), [](const auto& tool) {
            return tool.name == "memory_debug_santamonica_runtime_resources" ||
                tool.name == "memory_debug_santamonica_runtime_set_resource";
        });
        check(!advertises_resources, "resource tools stay hidden without a resource root");
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
