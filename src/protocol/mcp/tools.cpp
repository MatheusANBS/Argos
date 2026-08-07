#include "argos_mcp/protocol/mcp/tools.hpp"

#include "argos_mcp/domain/types.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace argos::protocol::mcp {
namespace {

using json::Value;

struct InputError {
    std::string message;
};

template <typename T>
using InputResult = std::expected<T, InputError>;

[[nodiscard]] ToolCallResult input_error(std::string message) {
    return ToolCallResult{
        Value::object({
            {"ok", false},
            {"error", Value::object({
                {"code", "invalid_arguments"},
                {"message", std::move(message)}
            })}
        }),
        true
    };
}

[[nodiscard]] ToolCallResult domain_error(const domain::DebugError& error) {
    return ToolCallResult{
        Value::object({
            {"ok", false},
            {"error", Value::object({
                {"code", std::string{domain::to_string(error.code)}},
                {"message", error.safe_message}
            })}
        }),
        true
    };
}

[[nodiscard]] ToolCallResult success(Value data) {
    return ToolCallResult{Value::object({{"ok", true}, {"data", std::move(data)}}), false};
}

[[nodiscard]] const Value::Object* require_object(const Value& value) {
    return value.is_object() ? &value.as_object() : nullptr;
}

[[nodiscard]] InputResult<std::string> string_arg(
    const Value& arguments,
    std::string_view key,
    bool required,
    std::string fallback = {}
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        if (required) {
            return std::unexpected(InputError{"missing string argument: " + std::string{key}});
        }
        return fallback;
    }
    if (!value->is_string()) {
        return std::unexpected(InputError{"argument must be a string: " + std::string{key}});
    }
    return value->as_string();
}

[[nodiscard]] InputResult<bool> bool_arg(
    const Value& arguments,
    std::string_view key,
    bool required,
    bool fallback = false
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        if (required) {
            return std::unexpected(InputError{"missing boolean argument: " + std::string{key}});
        }
        return fallback;
    }
    if (!value->is_bool()) {
        return std::unexpected(InputError{"argument must be boolean: " + std::string{key}});
    }
    return value->as_bool();
}

[[nodiscard]] InputResult<std::uint64_t> unsigned_arg(
    const Value& arguments,
    std::string_view key,
    bool required,
    std::uint64_t fallback = 0
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        if (required) {
            return std::unexpected(InputError{"missing integer argument: " + std::string{key}});
        }
        return fallback;
    }
    if (!value->is_integer() || value->as_integer() < 0) {
        return std::unexpected(InputError{"argument must be a non-negative integer: " + std::string{key}});
    }
    return static_cast<std::uint64_t>(value->as_integer());
}

[[nodiscard]] InputResult<domain::Address> parse_address_text(std::string_view input) {
    int base = 10;
    if (input.starts_with("0x") || input.starts_with("0X")) {
        input.remove_prefix(2U);
        base = 16;
    }
    if (input.empty()) {
        return std::unexpected(InputError{"address is empty"});
    }
    domain::Address address = 0;
    const auto [ptr, ec] = std::from_chars(input.data(), input.data() + input.size(), address, base);
    if (ec != std::errc{} || ptr != input.data() + input.size()) {
        return std::unexpected(InputError{"invalid address"});
    }
    return address;
}

[[nodiscard]] InputResult<domain::Address> address_arg(
    const Value& arguments,
    std::string_view key
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        return std::unexpected(InputError{"missing address argument: " + std::string{key}});
    }
    if (value->is_string()) {
        return parse_address_text(value->as_string());
    }
    if (value->is_integer() && value->as_integer() >= 0) {
        return static_cast<domain::Address>(value->as_integer());
    }
    return std::unexpected(InputError{"address must be a hexadecimal string or non-negative integer"});
}

[[nodiscard]] InputResult<std::optional<domain::Address>> optional_address_arg(
    const Value& arguments,
    std::string_view key
) {
    if (arguments.find(key) == nullptr) {
        return std::optional<domain::Address>{};
    }
    auto address = address_arg(arguments, key);
    if (!address) {
        return std::unexpected(address.error());
    }
    return std::optional<domain::Address>{*address};
}

[[nodiscard]] InputResult<domain::SessionId> session_arg(const Value& arguments) {
    auto text = string_arg(arguments, "session_id", true);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto id = domain::SessionId::create(std::move(*text));
    if (!id) {
        return std::unexpected(InputError{id.error()});
    }
    return *id;
}

[[nodiscard]] int hex_digit(char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
}

[[nodiscard]] InputResult<std::vector<std::byte>> parse_hex(std::string_view text) {
    std::string compact;
    compact.reserve(text.size());
    for (const char ch : text) {
        if (ch == ' ' || ch == ':' || ch == '-' || ch == '\t' || ch == '\n' || ch == '\r') {
            continue;
        }
        compact.push_back(ch);
    }
    if (compact.starts_with("0x") || compact.starts_with("0X")) {
        compact.erase(0, 2U);
    }
    if (compact.empty() || compact.size() % 2U != 0U) {
        return std::unexpected(InputError{"hex bytes must contain an even, non-zero number of digits"});
    }
    std::vector<std::byte> output;
    output.reserve(compact.size() / 2U);
    for (std::size_t index = 0; index < compact.size(); index += 2U) {
        const int high = hex_digit(compact[index]);
        const int low = hex_digit(compact[index + 1U]);
        if (high < 0 || low < 0) {
            return std::unexpected(InputError{"hex bytes contain an invalid digit"});
        }
        output.push_back(static_cast<std::byte>((high << 4) | low));
    }
    return output;
}

[[nodiscard]] std::string hex_bytes(std::span<const std::byte> bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << std::to_integer<unsigned int>(byte);
    }
    return output.str();
}

[[nodiscard]] std::string hex_address(domain::Address address) {
    std::ostringstream output;
    output << "0x" << std::hex << std::uppercase << address;
    return output.str();
}

[[nodiscard]] Value object_schema(
    Value::Object properties,
    Value::Array required = {},
    bool additional_properties = false
) {
    Value schema = Value::object({
        {"type", "object"},
        {"properties", Value{std::move(properties)}},
        {"additionalProperties", additional_properties}
    });
    if (!required.empty()) {
        schema["required"] = Value{std::move(required)};
    }
    return schema;
}

[[nodiscard]] Value string_schema(std::string description = {}) {
    Value schema = Value::object({{"type", "string"}});
    if (!description.empty()) schema["description"] = std::move(description);
    return schema;
}

[[nodiscard]] Value integer_schema(std::int64_t minimum, std::int64_t maximum) {
    return Value::object({
        {"type", "integer"},
        {"minimum", minimum},
        {"maximum", maximum}
    });
}

[[nodiscard]] Value boolean_schema() {
    return Value::object({{"type", "boolean"}});
}

[[nodiscard]] Value enum_string_schema(std::initializer_list<Value> values) {
    return Value::object({{"type", "string"}, {"enum", Value::array(values)}});
}

[[nodiscard]] Value read_only_annotations() {
    return Value::object({
        {"readOnlyHint", true},
        {"destructiveHint", false},
        {"idempotentHint", true},
        {"openWorldHint", false}
    });
}

[[nodiscard]] Value stateful_annotations() {
    return Value::object({
        {"readOnlyHint", false},
        {"destructiveHint", false},
        {"idempotentHint", false},
        {"openWorldHint", false}
    });
}

[[nodiscard]] Value destructive_annotations() {
    return Value::object({
        {"readOnlyHint", false},
        {"destructiveHint", true},
        {"idempotentHint", false},
        {"openWorldHint", false}
    });
}

[[nodiscard]] Value process_to_json(const domain::ProcessInfo& process) {
    Value value = Value::object({
        {"pid", static_cast<std::int64_t>(process.pid)},
        {"name", process.name},
        {"same_user", process.same_user}
    });
    value["executable"] = process.executable ? Value{*process.executable} : Value{nullptr};
    return value;
}

[[nodiscard]] Value session_to_json(const domain::SessionInfo& session) {
    return Value::object({
        {"session_id", session.id.value()},
        {"pid", static_cast<std::int64_t>(session.pid)},
        {"process_name", session.process_name},
        {"access", std::string{domain::to_string(session.access)}}
    });
}

[[nodiscard]] Value region_to_json(const domain::MemoryRegion& region) {
    return Value::object({
        {"start", hex_address(region.start)},
        {"end", hex_address(region.end)},
        {"size", static_cast<std::int64_t>(std::min<std::uint64_t>(
            region.size(), static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        ))},
        {"readable", region.readable},
        {"writable", region.writable},
        {"executable", region.executable},
        {"private", region.private_mapping},
        {"name", region.name}
    });
}

[[nodiscard]] Value module_to_json(const domain::ModuleInfo& module) {
    return Value::object({
        {"name", module.name},
        {"path", module.path},
        {"base", hex_address(module.base)},
        {"size", static_cast<std::int64_t>(std::min<std::uint64_t>(
            module.size, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        ))}
    });
}

[[nodiscard]] Value type_metadata_to_json(const domain::TypeMetadata& metadata) {
    Value::Array fields;
    fields.reserve(metadata.fields.size());
    for (const auto& field : metadata.fields) {
        fields.push_back(Value::object({
            {"name", field.name},
            {"type", field.type_name},
            {"offset", field.offset},
            {"size", static_cast<std::int64_t>(std::min<std::uint64_t>(
                field.size, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            ))}
        }));
    }
    return Value::object({
        {"type", metadata.type_name},
        {"size", static_cast<std::int64_t>(std::min<std::uint64_t>(
            metadata.size, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
        ))},
        {"source", metadata.source},
        {"confidence", metadata.confidence},
        {"truncated", metadata.truncated},
        {"fields", Value{std::move(fields)}}
    });
}

[[nodiscard]] Value reflection_metadata_to_json(const domain::ReflectionMetadata& metadata) {
    Value::Array symbols;
    symbols.reserve(metadata.symbols.size());
    for (const auto& symbol : metadata.symbols) {
        symbols.push_back(Value::object({
            {"name", symbol.name},
            {"kind", symbol.kind},
            {"relative_address", hex_address(symbol.relative_address)}
        }));
    }
    return Value::object({
        {"engine", metadata.engine},
        {"source", metadata.source},
        {"confidence", metadata.confidence},
        {"truncated", metadata.truncated},
        {"symbols", Value{std::move(symbols)}}
    });
}

[[nodiscard]] InputResult<std::vector<std::int64_t>> offsets_arg(const Value& arguments) {
    const Value* value = arguments.find("offsets");
    if (value == nullptr || !value->is_array()) {
        return std::unexpected(InputError{"offsets must be an array of signed integers"});
    }
    std::vector<std::int64_t> output;
    output.reserve(value->as_array().size());
    for (const auto& item : value->as_array()) {
        if (!item.is_integer()) {
            return std::unexpected(InputError{"every pointer offset must be an integer"});
        }
        output.push_back(item.as_integer());
    }
    return output;
}

[[nodiscard]] Value decode_typed(std::span<const std::byte> bytes, std::string_view type) {
    auto unsigned_le = [&bytes]() {
        std::uint64_t value = 0;
        for (std::size_t index = 0; index < bytes.size(); ++index) {
            value |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[index])) << (index * 8U);
        }
        return value;
    };

    if (type == "utf8") {
        std::string text;
        text.reserve(bytes.size());
        for (const auto byte : bytes) {
            const char ch = static_cast<char>(std::to_integer<unsigned int>(byte));
            if (ch == '\0') break;
            text.push_back(ch);
        }
        return Value::object({{"type", "utf8"}, {"value", std::move(text)}});
    }
    if (type == "f32" && bytes.size() == 4U) {
        std::uint32_t bits = static_cast<std::uint32_t>(unsigned_le());
        const float value = std::bit_cast<float>(bits);
        return Value::object({{"type", "f32"}, {"value", static_cast<double>(value)}});
    }
    if (type == "f64" && bytes.size() == 8U) {
        const double value = std::bit_cast<double>(unsigned_le());
        return Value::object({{"type", "f64"}, {"value", value}});
    }
    const std::uint64_t raw = unsigned_le();
    if (type == "i8") return Value::object({{"type", "i8"}, {"value", static_cast<std::int64_t>(static_cast<std::int8_t>(raw))}});
    if (type == "i16") return Value::object({{"type", "i16"}, {"value", static_cast<std::int64_t>(static_cast<std::int16_t>(raw))}});
    if (type == "i32") return Value::object({{"type", "i32"}, {"value", static_cast<std::int64_t>(static_cast<std::int32_t>(raw))}});
    if (type == "i64") return Value::object({{"type", "i64"}, {"value", static_cast<std::int64_t>(raw)}});
    return Value::object({
        {"type", std::string{type}},
        {"value_decimal", std::to_string(raw)},
        {"value_hex", hex_address(raw)}
    });
}

[[nodiscard]] std::size_t type_size(std::string_view type, std::size_t utf8_size) {
    if (type == "u8" || type == "i8") return 1U;
    if (type == "u16" || type == "i16") return 2U;
    if (type == "u32" || type == "i32" || type == "f32") return 4U;
    if (type == "u64" || type == "i64" || type == "f64") return 8U;
    if (type == "utf8") return utf8_size;
    return 0U;
}

}  // namespace

std::vector<ToolDefinition> ToolCatalog::definitions() const {
    const auto address = string_schema("Hexadecimal address such as 0x7FF612340000.");
    const auto session = string_schema("Opaque session_id returned by memory_debug.attach.");
    std::vector<ToolDefinition> tools;

    tools.push_back(ToolDefinition{
        "memory_debug.process_list",
        "List local processes. Results indicate whether ownership matches the server user.",
        object_schema({
            {"filter", string_schema("Optional case-insensitive process-name filter.")},
            {"limit", integer_schema(1, 4096)}
        }),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.attach",
        "Open an authorized debugging session for a process. Write access is disabled unless explicitly enabled in server configuration.",
        object_schema({
            {"pid", integer_schema(1, static_cast<std::int64_t>(std::numeric_limits<domain::ProcessId>::max()))},
            {"access", enum_string_schema({"read_only", "read_write"})},
            {"authorized", boolean_schema()}
        }, {"pid", "authorized"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.detach",
        "Close a debugging session and release its native process handle.",
        object_schema({{"session_id", session}}, {"session_id"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.sessions",
        "List active debugging sessions created by this MCP server process.",
        object_schema({}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.regions",
        "List virtual memory regions and their read/write/execute attributes.",
        object_schema({{"session_id", session}}, {"session_id"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.modules",
        "List loaded executable modules or file-backed mappings.",
        object_schema({{"session_id", session}}, {"session_id"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.pdb_type",
        "Inspect one native type from the PDB matching a loaded module. This is read-only and does not inject code into the target.",
        object_schema({
            {"session_id", session},
            {"module", string_schema("Loaded module name or exact path returned by memory_debug.modules.")},
            {"type", string_schema("Native type name, for example GameState or FMyActor.")},
            {"max_fields", integer_schema(1, 4096)}
        }, {"session_id", "module", "type"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.unity_type",
        "Read a Unity IL2CPP type from global-metadata.dat beside the loaded module, enriching it with a matching PDB when available.",
        object_schema({
            {"session_id", session},
            {"module", string_schema("Loaded GameAssembly module name or exact path returned by memory_debug.modules.")},
            {"type", string_schema("Unity type name, optionally namespace-qualified.")},
            {"max_fields", integer_schema(1, 4096)}
        }, {"session_id", "module", "type"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.unreal_type",
        "Read a reflected Unreal A/U/F/E/I type from the matching PDB emitted by the UHT/native build.",
        object_schema({
            {"session_id", session},
            {"module", string_schema("Loaded Unreal executable/module name or exact path returned by memory_debug.modules.")},
            {"type", string_schema("Unreal reflected type such as AActor, UObject or FMyStruct.")},
            {"max_fields", integer_schema(1, 4096)}
        }, {"session_id", "module", "type"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.unreal_reflection",
        "Enumerate Unreal UHT StaticClass and StaticStruct symbols from the matching PDB.",
        object_schema({
            {"session_id", session},
            {"module", string_schema("Loaded Unreal executable/module name or exact path returned by memory_debug.modules.")},
            {"max_symbols", integer_schema(1, 4096)}
        }, {"session_id", "module"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.read",
        "Read a bounded byte range from an authorized process and return lowercase hexadecimal bytes.",
        object_schema({
            {"session_id", session},
            {"address", address},
            {"size", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_read_bytes))}
        }, {"session_id", "address", "size"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.read_batch",
        "Read multiple small ranges in one call. Each item reports success or a safe error.",
        object_schema({
            {"session_id", session},
            {"items", Value::object({
                {"type", "array"},
                {"minItems", 1},
                {"maxItems", 256},
                {"items", object_schema({
                    {"address", address},
                    {"size", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_read_bytes))}
                }, {"address", "size"})}
            })}
        }, {"session_id", "items"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.read_typed",
        "Read and decode a little-endian integer, floating-point value, or bounded UTF-8 string.",
        object_schema({
            {"session_id", session},
            {"address", address},
            {"type", enum_string_schema({"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "utf8"})},
            {"size", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_read_bytes))}
        }, {"session_id", "address", "type"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.scan_exact",
        "Search readable memory for an exact byte pattern within explicit server limits.",
        object_schema({
            {"session_id", session},
            {"pattern_hex", string_schema("Exact bytes in hexadecimal form.")},
            {"alignment", integer_schema(1, 4096)},
            {"byte_budget", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_bytes))},
            {"result_limit", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_results))},
            {"start_address", address},
            {"end_address", address},
            {"writable_only", boolean_schema()}
        }, {"session_id", "pattern_hex"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.resolve_pointer_chain",
        "Resolve a conventional pointer chain. Each non-final offset is added before dereference; the final offset returns the resulting address.",
        object_schema({
            {"session_id", session},
            {"base_address", address},
            {"offsets", Value::object({
                {"type", "array"},
                {"minItems", 1},
                {"maxItems", 64},
                {"items", Value::object({{"type", "integer"}})}
            })},
            {"pointer_size", enum_string_schema({"4", "8"})}
        }, {"session_id", "base_address", "offsets"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.write",
        "Write bytes to an authorized read-write session. Disabled by default and requires a fixed per-call confirmation phrase.",
        object_schema({
            {"session_id", session},
            {"address", address},
            {"bytes_hex", string_schema("Bytes to write in hexadecimal form.")},
            {"confirmation", enum_string_schema({"AUTHORIZED_DEBUG_WRITE"})}
        }, {"session_id", "address", "bytes_hex", "confirmation"}),
        destructive_annotations()
    });

    return tools;
}

ToolCallResult ToolCatalog::invoke(
    const std::string_view name,
    const Value& arguments,
    const std::stop_token cancellation
) {
    if (require_object(arguments) == nullptr) {
        return input_error("tool arguments must be a JSON object");
    }

    logger_.log(observability::LogLevel::debug, "tool_call", name);

    if (name == "memory_debug.process_list") {
        auto filter = string_arg(arguments, "filter", false, "");
        auto limit = unsigned_arg(arguments, "limit", false, 256U);
        if (!filter) return input_error(filter.error().message);
        if (!limit || *limit == 0U || *limit > 4096U) return input_error("limit must be between 1 and 4096");
        auto result = service_.list_processes(*filter, static_cast<std::size_t>(*limit));
        if (!result) return domain_error(result.error());
        Value::Array processes;
        processes.reserve(result->size());
        for (const auto& process : *result) processes.push_back(process_to_json(process));
        return success(Value::object({{"processes", Value{std::move(processes)}}}));
    }

    if (name == "memory_debug.attach") {
        auto pid = unsigned_arg(arguments, "pid", true);
        auto access_text = string_arg(arguments, "access", false, "read_only");
        auto authorized = bool_arg(arguments, "authorized", true);
        if (!pid) return input_error(pid.error().message);
        if (!access_text) return input_error(access_text.error().message);
        if (!authorized) return input_error(authorized.error().message);
        if (*pid == 0U || *pid > std::numeric_limits<domain::ProcessId>::max()) return input_error("pid is out of range");
        domain::AccessMode access = domain::AccessMode::read_only;
        if (*access_text == "read_write") access = domain::AccessMode::read_write;
        else if (*access_text != "read_only") return input_error("access must be read_only or read_write");
        auto result = service_.attach(static_cast<domain::ProcessId>(*pid), access, *authorized);
        if (!result) return domain_error(result.error());
        return success(session_to_json(*result));
    }

    if (name == "memory_debug.detach") {
        auto session = session_arg(arguments);
        if (!session) return input_error(session.error().message);
        auto result = service_.detach(*session);
        if (!result) return domain_error(result.error());
        return success(Value::object({{"detached", true}}));
    }

    if (name == "memory_debug.sessions") {
        Value::Array sessions;
        for (const auto& session : service_.list_sessions()) sessions.push_back(session_to_json(session));
        return success(Value::object({{"sessions", Value{std::move(sessions)}}}));
    }

    if (name == "memory_debug.regions") {
        auto session = session_arg(arguments);
        if (!session) return input_error(session.error().message);
        auto result = service_.regions(*session);
        if (!result) return domain_error(result.error());
        Value::Array regions;
        regions.reserve(result->size());
        for (const auto& region : *result) regions.push_back(region_to_json(region));
        return success(Value::object({{"regions", Value{std::move(regions)}}}));
    }

    if (name == "memory_debug.modules") {
        auto session = session_arg(arguments);
        if (!session) return input_error(session.error().message);
        auto result = service_.modules(*session);
        if (!result) return domain_error(result.error());
        Value::Array modules;
        modules.reserve(result->size());
        for (const auto& module : *result) modules.push_back(module_to_json(module));
        return success(Value::object({{"modules", Value{std::move(modules)}}}));
    }

    if (name == "memory_debug.pdb_type") {
        auto session = session_arg(arguments);
        auto module = string_arg(arguments, "module", true);
        auto type = string_arg(arguments, "type", true);
        auto max_fields = unsigned_arg(arguments, "max_fields", false, 256U);
        if (!session) return input_error(session.error().message);
        if (!module) return input_error(module.error().message);
        if (!type) return input_error(type.error().message);
        if (!max_fields || *max_fields == 0U || *max_fields > 4096U) {
            return input_error("max_fields must be between 1 and 4096");
        }
        auto result = service_.pdb_type(*session, *module, *type, static_cast<std::size_t>(*max_fields));
        if (!result) return domain_error(result.error());
        return success(type_metadata_to_json(*result));
    }

    if (name == "memory_debug.unity_type") {
        auto session = session_arg(arguments);
        auto module = string_arg(arguments, "module", true);
        auto type = string_arg(arguments, "type", true);
        auto max_fields = unsigned_arg(arguments, "max_fields", false, 256U);
        if (!session) return input_error(session.error().message);
        if (!module) return input_error(module.error().message);
        if (!type) return input_error(type.error().message);
        if (!max_fields || *max_fields == 0U || *max_fields > 4096U) {
            return input_error("max_fields must be between 1 and 4096");
        }
        auto result = service_.unity_type(*session, *module, *type, static_cast<std::size_t>(*max_fields));
        if (!result) return domain_error(result.error());
        return success(type_metadata_to_json(*result));
    }

    if (name == "memory_debug.unreal_type") {
        auto session = session_arg(arguments);
        auto module = string_arg(arguments, "module", true);
        auto type = string_arg(arguments, "type", true);
        auto max_fields = unsigned_arg(arguments, "max_fields", false, 256U);
        if (!session) return input_error(session.error().message);
        if (!module) return input_error(module.error().message);
        if (!type) return input_error(type.error().message);
        if (!max_fields || *max_fields == 0U || *max_fields > 4096U) {
            return input_error("max_fields must be between 1 and 4096");
        }
        auto result = service_.unreal_type(*session, *module, *type, static_cast<std::size_t>(*max_fields));
        if (!result) return domain_error(result.error());
        return success(type_metadata_to_json(*result));
    }

    if (name == "memory_debug.unreal_reflection") {
        auto session = session_arg(arguments);
        auto module = string_arg(arguments, "module", true);
        auto max_symbols = unsigned_arg(arguments, "max_symbols", false, 256U);
        if (!session) return input_error(session.error().message);
        if (!module) return input_error(module.error().message);
        if (!max_symbols || *max_symbols == 0U || *max_symbols > 4096U) {
            return input_error("max_symbols must be between 1 and 4096");
        }
        auto result = service_.unreal_reflection(*session, *module, static_cast<std::size_t>(*max_symbols));
        if (!result) return domain_error(result.error());
        return success(reflection_metadata_to_json(*result));
    }

    if (name == "memory_debug.read") {
        auto session = session_arg(arguments);
        auto address = address_arg(arguments, "address");
        auto size = unsigned_arg(arguments, "size", true);
        if (!session) return input_error(session.error().message);
        if (!address) return input_error(address.error().message);
        if (!size || *size > std::numeric_limits<std::size_t>::max()) return input_error("invalid size");
        auto result = service_.read_memory(*session, *address, static_cast<std::size_t>(*size));
        if (!result) return domain_error(result.error());
        return success(Value::object({
            {"address", hex_address(*address)},
            {"size", static_cast<std::int64_t>(result->size())},
            {"bytes_hex", hex_bytes(*result)}
        }));
    }

    if (name == "memory_debug.read_batch") {
        auto session = session_arg(arguments);
        if (!session) return input_error(session.error().message);
        const Value* items_value = arguments.find("items");
        if (items_value == nullptr || !items_value->is_array()) return input_error("items must be an array");
        std::vector<application::BatchReadItem> items;
        items.reserve(items_value->as_array().size());
        for (const auto& item : items_value->as_array()) {
            if (!item.is_object()) return input_error("every batch item must be an object");
            auto address = address_arg(item, "address");
            auto size = unsigned_arg(item, "size", true);
            if (!address) return input_error(address.error().message);
            if (!size || *size > std::numeric_limits<std::size_t>::max()) return input_error("invalid batch size");
            items.push_back(application::BatchReadItem{*address, static_cast<std::size_t>(*size)});
        }
        auto result = service_.read_batch(*session, items);
        if (!result) return domain_error(result.error());
        Value::Array values;
        values.reserve(result->size());
        for (const auto& item : *result) {
            Value value = Value::object({
                {"address", hex_address(item.address)},
                {"success", item.success}
            });
            value["bytes_hex"] = item.success ? Value{hex_bytes(item.bytes)} : Value{nullptr};
            value["error"] = item.success ? Value{nullptr} : Value{item.error};
            values.push_back(std::move(value));
        }
        return success(Value::object({{"items", Value{std::move(values)}}}));
    }

    if (name == "memory_debug.read_typed") {
        auto session = session_arg(arguments);
        auto address = address_arg(arguments, "address");
        auto type = string_arg(arguments, "type", true);
        auto requested_size = unsigned_arg(arguments, "size", false, 256U);
        if (!session) return input_error(session.error().message);
        if (!address) return input_error(address.error().message);
        if (!type) return input_error(type.error().message);
        if (!requested_size || *requested_size > std::numeric_limits<std::size_t>::max()) return input_error("invalid size");
        const std::size_t size = type_size(*type, static_cast<std::size_t>(*requested_size));
        if (size == 0U) return input_error("unsupported typed read type");
        auto result = service_.read_memory(*session, *address, size);
        if (!result) return domain_error(result.error());
        if (result->size() != size) return domain_error(domain::DebugError{domain::DebugErrorCode::io_error, "short typed read"});
        Value decoded = decode_typed(*result, *type);
        decoded["address"] = hex_address(*address);
        decoded["bytes_hex"] = hex_bytes(*result);
        return success(std::move(decoded));
    }

    if (name == "memory_debug.scan_exact") {
        auto session = session_arg(arguments);
        auto pattern_text = string_arg(arguments, "pattern_hex", true);
        auto alignment = unsigned_arg(arguments, "alignment", false, 1U);
        auto budget = unsigned_arg(arguments, "byte_budget", false, service_.policy().max_scan_bytes);
        auto limit = unsigned_arg(arguments, "result_limit", false, service_.policy().max_scan_results);
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        auto writable_only = bool_arg(arguments, "writable_only", false, false);
        if (!session) return input_error(session.error().message);
        if (!pattern_text) return input_error(pattern_text.error().message);
        if (!alignment || !budget || !limit || !start_address || !end_address || !writable_only) {
            if (!start_address) return input_error(start_address.error().message);
            if (!end_address) return input_error(end_address.error().message);
            return input_error("invalid scan arguments");
        }
        auto pattern = parse_hex(*pattern_text);
        if (!pattern) return input_error(pattern.error().message);
        auto result = service_.scan_exact(
            *session, *pattern, static_cast<std::size_t>(*alignment),
            static_cast<std::size_t>(*budget), static_cast<std::size_t>(*limit), *writable_only,
            *start_address, *end_address, cancellation
        );
        if (!result) return domain_error(result.error());
        Value::Array matches;
        matches.reserve(result->matches.size());
        for (const auto& match : result->matches) matches.push_back(hex_address(match.address));
        return success(Value::object({
            {"matches", Value{std::move(matches)}},
            {"bytes_scanned", static_cast<std::int64_t>(result->bytes_scanned)},
            {"truncated", result->truncated}
        }));
    }

    if (name == "memory_debug.resolve_pointer_chain") {
        auto session = session_arg(arguments);
        auto base = address_arg(arguments, "base_address");
        auto offsets = offsets_arg(arguments);
        auto pointer_size_text = string_arg(arguments, "pointer_size", false, sizeof(void*) == 8U ? "8" : "4");
        if (!session) return input_error(session.error().message);
        if (!base) return input_error(base.error().message);
        if (!offsets) return input_error(offsets.error().message);
        if (!pointer_size_text) return input_error(pointer_size_text.error().message);
        const std::size_t pointer_size = *pointer_size_text == "4" ? 4U : (*pointer_size_text == "8" ? 8U : 0U);
        if (pointer_size == 0U) return input_error("pointer_size must be 4 or 8");
        auto result = service_.resolve_pointer_chain(*session, *base, *offsets, pointer_size);
        if (!result) return domain_error(result.error());
        return success(Value::object({{"address", hex_address(*result)}}));
    }

    if (name == "memory_debug.write") {
        auto session = session_arg(arguments);
        auto address = address_arg(arguments, "address");
        auto bytes_text = string_arg(arguments, "bytes_hex", true);
        auto confirmation = string_arg(arguments, "confirmation", true);
        if (!session) return input_error(session.error().message);
        if (!address) return input_error(address.error().message);
        if (!bytes_text) return input_error(bytes_text.error().message);
        if (!confirmation) return input_error(confirmation.error().message);
        auto bytes = parse_hex(*bytes_text);
        if (!bytes) return input_error(bytes.error().message);
        auto result = service_.write_memory(*session, *address, *bytes, *confirmation);
        if (!result) return domain_error(result.error());
        return success(Value::object({
            {"address", hex_address(*address)},
            {"bytes_written", static_cast<std::int64_t>(*result)}
        }));
    }

    return input_error("unknown tool: " + std::string{name});
}

}  // namespace argos::protocol::mcp
