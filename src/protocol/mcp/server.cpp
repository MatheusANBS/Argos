#include "argos_mcp/protocol/mcp/server.hpp"

#include <cstdint>
#include <exception>
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

[[nodiscard]] Value tool_definition_to_json(const ToolDefinition& definition) {
    return Value::object({
        {"name", definition.name},
        {"title", definition.name},
        {"description", definition.description},
        {"inputSchema", definition.input_schema},
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
    std::string active_key;
    std::stop_source active_source;
    std::jthread worker;

    const auto write_response = [&output, &output_mutex](const Value& response) {
        std::scoped_lock lock(output_mutex);
        output << response.dump() << '\n' << std::flush;
    };

    std::string line;
    while (std::getline(input, line)) {
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
                active_source.request_stop();
                logger_.log(observability::LogLevel::info, "request_cancelled", key);
            }
            continue;
        }

        if (is_tool_call_request(*parsed)) {
            const Value request = *parsed;
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
                active_key = key;
                active_source = source;
            }

            worker = std::jthread([
                this, request, key, source, &write_response, &active_mutex,
                &active, &active_key
            ]() mutable {
                try {
                    auto response = handle_with_token(request, source.get_token());
                    if (response) {
                        write_response(*response);
                    }
                } catch (const std::exception& exception) {
                    logger_.log(observability::LogLevel::error, "request_exception", exception.what());
                    write_response(rpc_error(request.at("id"), -32603, "Internal error"));
                } catch (...) {
                    logger_.log(observability::LogLevel::error, "request_exception", "unknown exception");
                    write_response(rpc_error(request.at("id"), -32603, "Internal error"));
                }
                std::scoped_lock lock(active_mutex);
                if (active_key == key) {
                    active = false;
                    active_key.clear();
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

    if (method_name == "notifications/initialized" || method_name == "notifications/cancelled") {
        return std::nullopt;
    }

    if (notification) {
        logger_.log(observability::LogLevel::debug, "notification_ignored", method_name);
        return std::nullopt;
    }

    if (method_name == "initialize") {
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
            {"serverInfo", Value::object({
                {"name", "argos-runtime-memory-mcp"},
                {"title", "Argos Runtime Memory Debug MCP"},
                {"version", "0.1.0"}
            })},
            {"instructions", "Use only on processes you own or are explicitly authorized to debug. Write access is disabled by default."}
        }));
    }

    if (method_name == "ping") {
        return rpc_result(*id, Value::object({}));
    }

    if (method_name == "tools/list") {
        Value::Array definitions;
        for (const auto& definition : tools_.definitions()) {
            definitions.push_back(tool_definition_to_json(definition));
        }
        return rpc_result(*id, Value::object({{"tools", Value{std::move(definitions)}}}));
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
        ToolCallResult tool_result = tools_.invoke(name->as_string(), *arguments, cancellation);
        const std::string text = tool_result.structured.dump();
        return rpc_result(*id, Value::object({
            {"content", Value::array({Value::object({
                {"type", "text"},
                {"text", text}
            })})},
            {"structuredContent", tool_result.structured},
            {"isError", tool_result.is_error}
        }));
    }

    return rpc_error(*id, -32601, "Method not found");
}

Value Server::rpc_result(const Value& id, Value result) {
    return Value::object({
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", std::move(result)}
    });
}

Value Server::rpc_error(
    const Value& id,
    const std::int64_t code,
    std::string message
) {
    return Value::object({
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", Value::object({
            {"code", code},
            {"message", std::move(message)}
        })}
    });
}

}  // namespace argos::protocol::mcp
