#include "argos_mcp/protocol/mcp/server.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <istream>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace argos::protocol::mcp {
namespace {

using json::Value;

constexpr std::string_view modern_protocol_version = "2026-07-28";
constexpr std::string_view protocol_version_meta_key = "io.modelcontextprotocol/protocolVersion";
constexpr std::string_view client_info_meta_key = "io.modelcontextprotocol/clientInfo";
constexpr std::string_view client_capabilities_meta_key = "io.modelcontextprotocol/clientCapabilities";
constexpr std::string_view server_info_meta_key = "io.modelcontextprotocol/serverInfo";
constexpr std::int64_t catalog_ttl_ms = 300'000;
constexpr std::string_view instructions =
    "Use only on processes you own or are explicitly authorized to debug. "
    "Write access is disabled by default.";

enum class LineReadStatus {
    complete,
    end_of_stream,
    too_large
};

[[nodiscard]] LineReadStatus read_bounded_line(
    std::istream& input,
    std::string& line,
    const std::size_t max_size
) {
    line.clear();
    bool too_large = false;
    auto* buffer = input.rdbuf();
    for (;;) {
        const auto next = buffer->sbumpc();
        if (next == std::char_traits<char>::eof()) {
            if (too_large) return LineReadStatus::too_large;
            return line.empty() ? LineReadStatus::end_of_stream : LineReadStatus::complete;
        }
        if (static_cast<char>(next) == '\n') {
            return too_large ? LineReadStatus::too_large : LineReadStatus::complete;
        }
        if (line.size() < max_size) {
            line.push_back(static_cast<char>(next));
        } else {
            // Drain the rest of the oversized frame without retaining it so
            // the following newline-delimited request remains synchronized.
            too_large = true;
        }
    }
}

[[nodiscard]] Value server_info() {
    return Value::object({
        {"name", "argos-runtime-memory-mcp"},
        {"title", "Argos Runtime Memory Debug MCP"},
        {"version", "0.2.0"}
    });
}

[[nodiscard]] Value supported_versions() {
    return Value::array({"2026-07-28", "2025-11-25", "2025-06-18"});
}

[[nodiscard]] const Value& generic_tool_output_schema() {
    static const Value schema = Value::object({
        {"oneOf", Value::array({
            Value::object({
                {"type", "object"},
                {"properties", Value::object({
                    {"ok", Value::object({{"const", true}})},
                    {"data", Value::object({})}
                })},
                {"required", Value::array({"ok", "data"})},
                {"additionalProperties", false}
            }),
            Value::object({
                {"type", "object"},
                {"properties", Value::object({
                    {"ok", Value::object({{"const", false}})},
                    {"error", Value::object({
                        {"type", "object"},
                        {"properties", Value::object({
                            {"code", Value::object({{"type", "string"}})},
                            {"message", Value::object({{"type", "string"}})}
                        })},
                        {"required", Value::array({"code", "message"})},
                        {"additionalProperties", false}
                    })}
                })},
                {"required", Value::array({"ok", "error"})},
                {"additionalProperties", false}
            })
        })}
    });
    return schema;
}

[[nodiscard]] Value modern_result(Value result) {
    result["resultType"] = "complete";
    result["_meta"] = Value::object({
        {std::string{server_info_meta_key}, server_info()}
    });
    return result;
}

[[nodiscard]] Value tool_definition_to_json(const ToolDefinition& definition) {
    return Value::object({
        {"name", definition.name},
        {"title", definition.name},
        {"description", definition.description},
        {"inputSchema", definition.input_schema},
        {"outputSchema", generic_tool_output_schema()},
        {"annotations", definition.annotations}
    });
}

[[nodiscard]] bool valid_request_id(const Value& id) {
    return id.is_string() || id.is_integer();
}

[[nodiscard]] std::string request_key(const Value& id) {
    return id.dump();
}

[[nodiscard]] bool is_tool_call_request(const Value& message) {
    if (!message.is_object()) return false;
    const Value* method = message.find("method");
    const Value* id = message.find("id");
    return method != nullptr && method->is_string() && method->as_string() == "tools/call" &&
           id != nullptr && valid_request_id(*id);
}

[[nodiscard]] const Value* cancellation_request_id(const Value& message) {
    if (!message.is_object()) return nullptr;
    const Value* method = message.find("method");
    if (method == nullptr || !method->is_string() || method->as_string() != "notifications/cancelled") {
        return nullptr;
    }
    const Value* params = message.find("params");
    if (params == nullptr || !params->is_object()) return nullptr;
    const Value* request_id = params->find("requestId");
    return request_id != nullptr && valid_request_id(*request_id) ? request_id : nullptr;
}

}  // namespace

int Server::run(std::istream& input, std::ostream& output) {
    std::mutex output_mutex;
    std::mutex active_mutex;
    bool active{false};
    bool active_cancelled{false};
    std::string active_key;
    std::stop_source active_source;

    const auto write_response = [&output, &output_mutex](const Value& response) {
        std::scoped_lock lock(output_mutex);
        output << response.dump() << '\n' << std::flush;
    };
    // Declared after the closure it captures so reverse-order destruction
    // always joins the worker before destroying write_response during unwind.
    std::jthread worker;

    std::string line;
    line.reserve(4096U);
    for (;;) {
        const auto line_status = read_bounded_line(input, line, json::max_parse_input_bytes);
        if (line_status == LineReadStatus::end_of_stream) {
            break;
        }
        if (line_status == LineReadStatus::too_large) {
            write_response(rpc_error(Value{nullptr}, -32700, "Parse error"));
            logger_.log(observability::LogLevel::warning, "json_frame_too_large", "request exceeds 8 MiB");
            continue;
        }
        if (line.empty()) {
            continue;
        }
        auto parsed = json::parse(line);
        if (!parsed) {
            write_response(rpc_error(Value{nullptr}, -32700, "Parse error"));
            logger_.log(observability::LogLevel::warning, "json_parse_error", parsed.error().message);
            continue;
        }

        if (const Value* cancelled_id = cancellation_request_id(*parsed); cancelled_id != nullptr) {
            const std::string key = request_key(*cancelled_id);
            std::scoped_lock lock(active_mutex);
            if (active && key == active_key) {
                active_cancelled = true;
                active_source.request_stop();
                logger_.log(observability::LogLevel::info, "request_cancelled", key);
            }
            continue;
        }

        if (is_tool_call_request(*parsed)) {
            Value request = std::move(*parsed);
            const Value id = request.at("id");
            const std::string key = request_key(id);
            std::stop_source source;
            {
                std::scoped_lock lock(active_mutex);
                if (active) {
                    write_response(rpc_error(id, -32000, "Server busy with another tool call"));
                    continue;
                }
                active = true;
                active_cancelled = false;
                active_key = key;
                active_source = source;
            }

            worker = std::jthread([
                this, request = std::move(request), key, source, &write_response, &active_mutex,
                &active, &active_cancelled, &active_key
            ]() mutable {
                std::optional<Value> response;
                try {
                    response = handle_with_token(request, source.get_token());
                } catch (const std::exception& exception) {
                    logger_.log(observability::LogLevel::error, "request_exception", exception.what());
                    response = rpc_error(request.at("id"), -32603, "Internal error");
                } catch (...) {
                    logger_.log(observability::LogLevel::error, "request_exception", "unknown exception");
                    response = rpc_error(request.at("id"), -32603, "Internal error");
                }

                bool publish_response = false;
                {
                    // Completion and cancellation are linearized by the same
                    // mutex. A cancellation observed first suppresses every
                    // response carrying that request id, as required by MCP.
                    // Clearing active before serialization also removes the
                    // post-response window that produced spurious busy errors.
                    std::scoped_lock lock(active_mutex);
                    if (active_key == key) {
                        publish_response = !active_cancelled;
                        active = false;
                        active_cancelled = false;
                        active_key.clear();
                    }
                }
                if (publish_response && response) {
                    write_response(*response);
                }
            });
            continue;
        }

        try {
            auto response = handle(*parsed);
            if (response) {
                write_response(*response);
            }
        } catch (const std::exception& exception) {
            logger_.log(observability::LogLevel::error, "request_exception", exception.what());
            const Value* id = parsed->find("id");
            write_response(rpc_error(id == nullptr ? Value{nullptr} : *id, -32603, "Internal error"));
        } catch (...) {
            logger_.log(observability::LogLevel::error, "request_exception", "unknown exception");
            const Value* id = parsed->find("id");
            write_response(rpc_error(id == nullptr ? Value{nullptr} : *id, -32603, "Internal error"));
        }
    }

    {
        std::scoped_lock lock(active_mutex);
        if (active) {
            active_source.request_stop();
        }
    }
    if (worker.joinable()) {
        worker.join();
    }
    logger_.log(observability::LogLevel::info, "transport_closed", "stdin closed");
    return 0;
}

std::optional<Value> Server::handle(const Value& message) {
    return handle_with_token(message, {});
}

std::optional<Value> Server::handle_with_token(
    const Value& message,
    const std::stop_token cancellation
) {
    if (!message.is_object()) {
        return rpc_error(Value{nullptr}, -32600, "Invalid Request");
    }
    const Value* version = message.find("jsonrpc");
    const Value* method = message.find("method");
    const Value* id = message.find("id");
    const bool notification = id == nullptr;

    if (version == nullptr || !version->is_string() || version->as_string() != "2.0" ||
        method == nullptr || !method->is_string()) {
        return notification ? std::nullopt : std::optional<Value>{rpc_error(
            id == nullptr ? Value{nullptr} : *id, -32600, "Invalid Request"
        )};
    }
    if (!notification && !valid_request_id(*id)) {
        return rpc_error(Value{nullptr}, -32600, "Invalid Request");
    }

    const std::string_view method_name = method->as_string();
    const Value* params = message.find("params");

    // The 2026 protocol is self-describing per request. Presence of the
    // reserved protocolVersion key selects the modern path; legacy requests
    // remain handshake-scoped and are deliberately left untouched.
    const Value* request_meta = nullptr;
    const Value* requested_protocol = nullptr;
    const Value* modern_client_info = nullptr;
    const Value* modern_client_capabilities = nullptr;
    if (params != nullptr && params->is_object()) {
        request_meta = params->find("_meta");
        if (request_meta != nullptr && request_meta->is_object()) {
            requested_protocol = request_meta->find(protocol_version_meta_key);
            modern_client_info = request_meta->find(client_info_meta_key);
            modern_client_capabilities = request_meta->find(client_capabilities_meta_key);
        }
    }
    const bool modern = requested_protocol != nullptr;
    if (!modern && !notification && (modern_client_info != nullptr || modern_client_capabilities != nullptr)) {
        return rpc_error(
            *id,
            -32602,
            "Invalid params: modern metadata requires io.modelcontextprotocol/protocolVersion"
        );
    }
    if (modern && !notification) {
        if (!requested_protocol->is_string() || requested_protocol->as_string() != modern_protocol_version) {
            return rpc_error(
                *id,
                -32022,
                "Unsupported protocol version",
                Value::object({
                    {"supported", supported_versions()},
                    {"requested", *requested_protocol}
                })
            );
        }
        if (modern_client_info != nullptr && !modern_client_info->is_object()) {
            return rpc_error(
                *id,
                -32602,
                "Invalid params: io.modelcontextprotocol/clientInfo must be an object"
            );
        }
        if (modern_client_capabilities == nullptr || !modern_client_capabilities->is_object()) {
            return rpc_error(
                *id,
                -32602,
                "Invalid params: modern requests require io.modelcontextprotocol/clientCapabilities"
            );
        }
    }

    if (method_name == "notifications/initialized" || method_name == "notifications/cancelled") {
        return std::nullopt;
    }

    if (notification) {
        logger_.log(observability::LogLevel::debug, "notification_ignored", method_name);
        return std::nullopt;
    }

    if (method_name == "server/discover") {
        if (!modern) {
            return rpc_error(*id, -32601, "Method not found");
        }
        return rpc_result(*id, modern_result(Value::object({
            {"supportedVersions", supported_versions()},
            {"capabilities", Value::object({
                {"tools", Value::object({{"listChanged", false}})}
            })},
            {"instructions", std::string{instructions}},
            {"ttlMs", catalog_ttl_ms},
            {"cacheScope", "public"}
        })));
    }

    if (method_name == "initialize") {
        if (modern) {
            return rpc_error(*id, -32601, "Method not found");
        }
        std::string protocol_version = "2025-11-25";
        if (params != nullptr && params->is_object()) {
            const Value* requested = params->find("protocolVersion");
            if (requested != nullptr && requested->is_string()) {
                const std::string& candidate = requested->as_string();
                if (candidate == "2025-11-25" || candidate == "2025-06-18") {
                    protocol_version = candidate;
                }
            }
        }
        return rpc_result(*id, Value::object({
            {"protocolVersion", protocol_version},
            {"capabilities", Value::object({
                {"tools", Value::object({{"listChanged", false}})}
            })},
            {"serverInfo", server_info()},
            {"instructions", std::string{instructions}}
        }));
    }

    if (method_name == "ping") {
        if (modern) {
            return rpc_error(*id, -32601, "Method not found");
        }
        return rpc_result(*id, Value::object({}));
    }

    if (method_name == "tools/list") {
        const auto& tool_definitions = tools_.definitions();
        Value::Array definitions;
        definitions.reserve(tool_definitions.size());
        for (const auto& definition : tool_definitions) {
            definitions.push_back(tool_definition_to_json(definition));
        }
        Value result = Value::object();
        result["tools"] = Value{std::move(definitions)};
        if (modern) {
            result["ttlMs"] = catalog_ttl_ms;
            result["cacheScope"] = "public";
            result = modern_result(std::move(result));
        }
        return rpc_result(*id, std::move(result));
    }

    if (method_name == "tools/call") {
        if (params == nullptr || !params->is_object()) {
            return rpc_error(*id, -32602, "Invalid params");
        }
        const Value* name = params->find("name");
        if (name == nullptr || !name->is_string()) {
            return rpc_error(*id, -32602, "Invalid params: tool name is required");
        }
        Value empty_arguments = Value::object({});
        const Value* arguments = params->find("arguments");
        if (arguments == nullptr) {
            arguments = &empty_arguments;
        }
        if (!arguments->is_object()) {
            return rpc_error(*id, -32602, "Invalid params: arguments must be an object");
        }
        auto tool_result = tools_.invoke(name->as_string(), *arguments, cancellation);
        if (!tool_result) {
            return rpc_error(*id, -32602, "Unknown tool: " + name->as_string());
        }
        if (modern) {
            Value result = Value::object();
            result["content"] = Value::Array{};
            result["structuredContent"] = std::move(tool_result->structured);
            result["isError"] = tool_result->is_error;
            return rpc_result(*id, modern_result(std::move(result)));
        }
        std::string text = tool_result->structured.dump();
        Value text_content = Value::object();
        text_content["type"] = "text";
        text_content["text"] = std::move(text);
        Value::Array content;
        content.push_back(std::move(text_content));
        Value result = Value::object();
        result["content"] = Value{std::move(content)};
        result["structuredContent"] = std::move(tool_result->structured);
        result["isError"] = tool_result->is_error;
        return rpc_result(*id, std::move(result));
    }

    return rpc_error(*id, -32601, "Method not found");
}

Value Server::rpc_result(const Value& id, Value result) {
    Value response = Value::object();
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["result"] = std::move(result);
    return response;
}

Value Server::rpc_error(
    const Value& id,
    const std::int64_t code,
    std::string message,
    std::optional<Value> data
) {
    Value error = Value::object({
        {"code", code},
        {"message", std::move(message)}
    });
    if (data) {
        error["data"] = std::move(*data);
    }
    Value response = Value::object();
    response["jsonrpc"] = "2.0";
    response["id"] = id;
    response["error"] = std::move(error);
    return response;
}

}  // namespace argos::protocol::mcp
