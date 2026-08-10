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
    Value result = Value::object();
    result["ok"] = true;
    result["data"] = std::move(data);
    return ToolCallResult{std::move(result), false};
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

// Tri-state: absent means "do not filter on this attribute", which is distinct
// from an explicit false.
[[nodiscard]] InputResult<std::optional<bool>> optional_bool_arg(
    const Value& arguments,
    std::string_view key
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        return std::optional<bool>{};
    }
    if (!value->is_bool()) {
        return std::unexpected(InputError{"argument must be boolean: " + std::string{key}});
    }
    return std::optional<bool>{value->as_bool()};
}

[[nodiscard]] InputResult<std::optional<std::uint64_t>> optional_unsigned_arg(
    const Value& arguments,
    std::string_view key
) {
    const Value* value = arguments.find(key);
    if (value == nullptr) {
        return std::optional<std::uint64_t>{};
    }
    if (!value->is_integer() || value->as_integer() < 0) {
        return std::unexpected(InputError{"argument must be a non-negative integer: " + std::string{key}});
    }
    return std::optional<std::uint64_t>{static_cast<std::uint64_t>(value->as_integer())};
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

[[nodiscard]] InputResult<domain::ScanSessionId> scan_session_arg(const Value& arguments) {
    auto text = string_arg(arguments, "scan_id", true);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto id = domain::ScanSessionId::create(std::move(*text));
    if (!id) {
        return std::unexpected(InputError{id.error()});
    }
    return *id;
}

[[nodiscard]] InputResult<domain::ScanValueType> value_type_arg(const Value& arguments) {
    auto text = string_arg(arguments, "value_type", true);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto type = domain::scan_value_type_from_string(*text);
    if (!type) {
        return std::unexpected(InputError{"value_type must be one of u8,u16,u32,u64,i8,i16,i32,i64,f32,f64"});
    }
    return *type;
}

[[nodiscard]] InputResult<domain::ScanComparison> comparison_arg(const Value& arguments) {
    auto text = string_arg(arguments, "comparison", true);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto comparison = domain::scan_comparison_from_string(*text);
    if (!comparison) {
        return std::unexpected(InputError{"invalid comparison"});
    }
    return *comparison;
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

[[nodiscard]] InputResult<std::optional<std::vector<std::byte>>> optional_hex_arg(
    const Value& arguments,
    std::string_view key
) {
    if (arguments.find(key) == nullptr) {
        return std::optional<std::vector<std::byte>>{};
    }
    auto text = string_arg(arguments, key, true);
    if (!text) {
        return std::unexpected(text.error());
    }
    auto bytes = parse_hex(*text);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return std::optional<std::vector<std::byte>>{*bytes};
}

[[nodiscard]] std::string hex_bytes(std::span<const std::byte> bytes) {
    static constexpr std::string_view digits{"0123456789abcdef"};
    std::string output(bytes.size() * 2U, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto value = std::to_integer<unsigned int>(bytes[index]);
        output[index * 2U] = digits[value >> 4U];
        output[index * 2U + 1U] = digits[value & 0x0FU];
    }
    return output;
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

[[nodiscard]] Value string_scan_result_to_json(const application::StringScanResult& result) {
    Value::Array matches;
    matches.reserve(result.matches.size());
    for (const auto& match : result.matches) {
        matches.push_back(Value::object({
            {"address", hex_address(match.address)},
            {"text", match.text},
            {"encoding", match.encoding}
        }));
    }
    return Value::object({
        {"matches", Value{std::move(matches)}},
        {"bytes_scanned", static_cast<std::int64_t>(result.bytes_scanned)},
        {"truncated", result.truncated}
    });
}

[[nodiscard]] Value type_catalog_to_json(const domain::TypeCatalog& catalog) {
    Value::Array types;
    types.reserve(catalog.types.size());
    for (const auto& summary : catalog.types) {
        types.push_back(Value::object({
            {"name", summary.name},
            {"kind", summary.kind},
            {"size", static_cast<std::int64_t>(std::min<std::uint64_t>(
                summary.size, static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
            ))}
        }));
    }
    return Value::object({
        {"types", Value{std::move(types)}},
        {"source", catalog.source},
        {"confidence", catalog.confidence},
        {"truncated", catalog.truncated}
    });
}

[[nodiscard]] Value output_chunk_to_json(const domain::OutputChunk& chunk) {
    return Value::object({
        {"stdout_text", chunk.stdout_text},
        {"stderr_text", chunk.stderr_text},
        {"cursor", static_cast<std::int64_t>(chunk.cursor)},
        {"process_alive", chunk.process_alive}
    });
}

[[nodiscard]] Value scan_session_info_to_json(const domain::ScanSessionInfo& info) {
    return Value::object({
        {"scan_id", info.id.value()},
        {"value_type", std::string{domain::to_string(info.value_type)}},
        {"candidate_count", static_cast<std::int64_t>(info.candidate_count)},
        {"generation", static_cast<std::int64_t>(info.generation)}
    });
}

[[nodiscard]] Value scan_coverage_to_json(const domain::ScanCoverage& coverage) {
    return Value::object({
        {"bytes_scanned", static_cast<std::int64_t>(coverage.bytes_scanned)},
        {"bytes_eligible", static_cast<std::int64_t>(coverage.bytes_eligible)},
        {"regions_scanned", static_cast<std::int64_t>(coverage.regions_scanned)},
        {"regions_eligible", static_cast<std::int64_t>(coverage.regions_eligible)},
        {"coverage_ratio", coverage.coverage_ratio()},
        {"truncated_by_budget", coverage.truncated_by_budget},
        {"truncated_by_result_limit", coverage.truncated_by_result_limit},
        {"complete", coverage.complete()}
    });
}

[[nodiscard]] Value region_page_to_json(const domain::RegionPage& page) {
    Value::Array regions;
    regions.reserve(page.regions.size());
    for (const auto& region : page.regions) regions.push_back(region_to_json(region));
    return Value::object({
        {"regions", Value{std::move(regions)}},
        {"total_matched", static_cast<std::int64_t>(page.total_matched)},
        {"offset", static_cast<std::int64_t>(page.offset)},
        {"returned", static_cast<std::int64_t>(page.regions.size())},
        {"truncated", page.truncated}
    });
}

[[nodiscard]] Value address_space_summary_to_json(const domain::AddressSpaceSummary& summary) {
    return Value::object({
        {"region_count", static_cast<std::int64_t>(summary.region_count)},
        {"total_bytes", static_cast<std::int64_t>(summary.total_bytes)},
        {"readable_count", static_cast<std::int64_t>(summary.readable_count)},
        {"readable_bytes", static_cast<std::int64_t>(summary.readable_bytes)},
        {"writable_count", static_cast<std::int64_t>(summary.writable_count)},
        {"writable_bytes", static_cast<std::int64_t>(summary.writable_bytes)},
        {"executable_count", static_cast<std::int64_t>(summary.executable_count)},
        {"executable_bytes", static_cast<std::int64_t>(summary.executable_bytes)},
        {"private_count", static_cast<std::int64_t>(summary.private_count)},
        {"private_bytes", static_cast<std::int64_t>(summary.private_bytes)},
        {"scannable_bytes", static_cast<std::int64_t>(summary.scannable_bytes)},
        {"scannable_writable_bytes", static_cast<std::int64_t>(summary.scannable_writable_bytes)},
        {"largest_region_bytes", static_cast<std::int64_t>(summary.largest_region_bytes)},
        {"lowest_address", hex_address(summary.lowest_address)},
        {"highest_address", hex_address(summary.highest_address)}
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

// Accepts either `<key>` (raw little-endian hex) or `<key>_decimal` (decimal
// literal encoded server-side). Supplying both is rejected rather than silently
// preferring one, so a mistake surfaces at the call instead of as a wrong scan.
[[nodiscard]] InputResult<std::optional<std::vector<std::byte>>> scan_value_arg(
    const Value& arguments,
    std::string_view key,
    const domain::ScanValueType value_type
) {
    const std::string decimal_key = std::string{key} + "_decimal";
    auto hex = optional_hex_arg(arguments, key);
    if (!hex) {
        return std::unexpected(hex.error());
    }
    const Value* decimal = arguments.find(decimal_key);
    if (decimal == nullptr) {
        return *hex;
    }
    if (*hex) {
        return std::unexpected(InputError{
            "provide either " + std::string{key} + " or " + decimal_key + ", not both"
        });
    }
    if (!decimal->is_string()) {
        return std::unexpected(InputError{"argument must be a string: " + decimal_key});
    }
    auto encoded = domain::encode_scan_value(value_type, decimal->as_string());
    if (!encoded) {
        return std::unexpected(InputError{decimal_key + ": " + encoded.error()});
    }
    return std::optional<std::vector<std::byte>>{std::move(*encoded)};
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

ToolCatalog::ToolCatalog(
    application::MemoryDebugService& service,
    const observability::Logger& logger
) : service_(service), logger_(logger), definitions_(build_definitions()) {
    std::ranges::sort(definitions_, {}, &ToolDefinition::name);
}

std::vector<ToolDefinition> ToolCatalog::build_definitions() const {
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
        "Close a debugging session and release its native process handle. terminate is only accepted for sessions created by memory_debug.launch.",
        object_schema({
            {"session_id", session},
            {"terminate", boolean_schema()}
        }, {"session_id"}),
        destructive_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.launch",
        "Start an executable chosen by the operator and capture its stdout/stderr. Disabled unless the server was started with ARGOS_MCP_ALLOW_LAUNCH=1; not intended for attaching to third-party processes already running.",
        object_schema({
            {"executable", string_schema("Absolute path to the executable to launch.")},
            {"arguments", Value::object({
                {"type", "array"},
                {"items", string_schema()}
            })},
            {"working_directory", string_schema("Optional absolute working directory for the child process.")},
            {"access", enum_string_schema({"read_only", "read_write"})},
            {"authorized", boolean_schema()},
            {"capture_output", boolean_schema()}
        }, {"executable", "authorized"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.read_output",
        "Poll captured stdout/stderr from a session created by memory_debug.launch.",
        object_schema({
            {"session_id", session},
            {"since_cursor", integer_schema(0, std::numeric_limits<std::int64_t>::max())},
            {"max_bytes", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_captured_output_bytes))}
        }, {"session_id"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.sessions",
        "List active debugging sessions created by this MCP server process.",
        object_schema({}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.regions",
        "List virtual memory regions and their read/write/execute attributes. Supports server-side filtering and paging; a real target has tens of thousands of regions, so prefer a filter over listing everything.",
        object_schema({
            {"session_id", session},
            {"readable", boolean_schema()},
            {"writable", boolean_schema()},
            {"executable", boolean_schema()},
            {"private", boolean_schema()},
            {"start_address", address},
            {"end_address", address},
            {"min_size", integer_schema(0, 1LL << 62)},
            {"max_size", integer_schema(0, 1LL << 62)},
            {"name_contains", string_schema("Case-insensitive substring match against the region name.")},
            {"offset", integer_schema(0, 1LL << 40)},
            {"limit", integer_schema(1, 4096)}
        }, {"session_id"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.address_space_summary",
        "Aggregate size and counts of the target address space by class (readable, writable, executable, private). Answers how much memory a scan would have to sweep, in one small response, without listing regions.",
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
        "memory_debug.pdb_list_types",
        "Enumerate native types available in the PDB matching a loaded module, so a type name does not need to be already known before calling memory_debug.pdb_type.",
        object_schema({
            {"session_id", session},
            {"module", string_schema("Loaded module name or exact path returned by memory_debug.modules.")},
            {"name_filter", string_schema("Optional case-insensitive substring filter on the type name.")},
            {"kind_filter", enum_string_schema({"", "class", "struct", "enum", "union"})},
            {"max_symbols", integer_schema(1, 65536)}
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
        "memory_debug.scan_pointers_to",
        "Search memory for pointers referencing a known target address, the inverse of following a pointer.",
        object_schema({
            {"session_id", session},
            {"target_address", address},
            {"pointer_size", enum_string_schema({"4", "8"})},
            {"byte_budget", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_bytes))},
            {"result_limit", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_results))},
            {"start_address", address},
            {"end_address", address},
            {"writable_only", boolean_schema()}
        }, {"session_id", "target_address"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.scan_pointer_chains",
        "Perform a bounded multi-hop reverse pointer chain scan from a dynamic address back to a static module base + offset chain that stays stable across process restarts, reusing the same scan engine as scan_pointers_to.",
        object_schema({
            {"session_id", session},
            {"target_address", address},
            {"pointer_size", enum_string_schema({"4", "8"})},
            {"max_depth", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_pointer_chain_depth))},
            {"max_fanout", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_pointer_chain_fanout))},
            {"byte_budget", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_bytes))},
            {"result_limit", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_results))},
            {"start_address", address},
            {"end_address", address},
            {"writable_only", boolean_schema()}
        }, {"session_id", "target_address"}),
        read_only_annotations()
    });

    const auto value_type_schema = enum_string_schema({
        "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64"
    });
    const auto hex_value_schema = string_schema("Bytes in hexadecimal form matching value_type size.");
    const auto scan_id_schema = string_schema("Opaque scan_id returned by memory_debug.scan_first.");
    const auto decimal_value_schema = string_schema(
        "Decimal literal encoded server-side into little-endian bytes of value_type width, "
        "for example \"91293908\" or \"-1.5\". Mutually exclusive with the hex form."
    );

    tools.push_back(ToolDefinition{
        "memory_debug.scan_first",
        "Start an incremental (first scan / next scan) value-diff scan session to locate a dynamic field offset without a known value, PDB or RTTI.",
        object_schema({
            {"session_id", session},
            {"value_type", value_type_schema},
            {"comparison", enum_string_schema({"exact", "unknown", "in_range"})},
            {"value", hex_value_schema},
            {"value_decimal", decimal_value_schema},
            {"range_low", hex_value_schema},
            {"range_low_decimal", decimal_value_schema},
            {"range_high", hex_value_schema},
            {"range_high_decimal", decimal_value_schema},
            {"byte_budget", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_bytes))},
            {"result_limit", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_session_candidates))},
            {"writable_only", boolean_schema()},
            {"start_address", address},
            {"end_address", address}
        }, {"session_id", "value_type", "comparison"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.scan_next",
        "Re-read only the candidates from an active scan session and filter them by how their value changed, narrowing toward the real field offset.",
        object_schema({
            {"scan_id", scan_id_schema},
            {"comparison", enum_string_schema({
                "changed", "unchanged", "increased", "decreased", "increased_by", "decreased_by", "exact"
            })},
            {"value", hex_value_schema},
            {"value_decimal", decimal_value_schema},
            {"delta", hex_value_schema},
            {"delta_decimal", decimal_value_schema}
        }, {"scan_id", "comparison"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.scan_results",
        "Page through the current candidate addresses of an active scan session.",
        object_schema({
            {"scan_id", scan_id_schema},
            {"offset", integer_schema(0, std::numeric_limits<std::int64_t>::max())},
            {"limit", integer_schema(1, 4096)}
        }, {"scan_id"}),
        read_only_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.scan_reset",
        "Clear the candidates of an active scan session without a new attach/detach cycle.",
        object_schema({{"scan_id", scan_id_schema}}, {"scan_id"}),
        stateful_annotations()
    });

    tools.push_back(ToolDefinition{
        "memory_debug.strings",
        "Extract printable ASCII or UTF-16LE strings directly from process memory without downloading raw hex bytes.",
        object_schema({
            {"session_id", session},
            {"start_address", address},
            {"end_address", address},
            {"min_length", integer_schema(1, 4096)},
            {"encoding", enum_string_schema({"ascii", "utf16le"})},
            {"byte_budget", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_bytes))},
            {"result_limit", integer_schema(1, static_cast<std::int64_t>(service_.policy().max_scan_results))},
            {"writable_only", boolean_schema()}
        }, {"session_id"}),
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

std::optional<ToolCallResult> ToolCatalog::invoke(
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
        auto terminate = bool_arg(arguments, "terminate", false, false);
        if (!session) return input_error(session.error().message);
        if (!terminate) return input_error(terminate.error().message);
        auto result = service_.detach(*session, *terminate);
        if (!result) return domain_error(result.error());
        return success(Value::object({{"detached", true}}));
    }

    if (name == "memory_debug.launch") {
        auto executable = string_arg(arguments, "executable", true);
        auto working_directory = string_arg(arguments, "working_directory", false, "");
        auto access_text = string_arg(arguments, "access", false, "read_only");
        auto authorized = bool_arg(arguments, "authorized", true);
        auto capture_output = bool_arg(arguments, "capture_output", false, true);
        if (!executable) return input_error(executable.error().message);
        if (!working_directory) return input_error(working_directory.error().message);
        if (!access_text) return input_error(access_text.error().message);
        if (!authorized) return input_error(authorized.error().message);
        if (!capture_output) return input_error(capture_output.error().message);
        domain::AccessMode access = domain::AccessMode::read_only;
        if (*access_text == "read_write") access = domain::AccessMode::read_write;
        else if (*access_text != "read_only") return input_error("access must be read_only or read_write");

        std::vector<std::string> argument_list;
        const Value* arguments_value = arguments.find("arguments");
        if (arguments_value != nullptr) {
            if (!arguments_value->is_array()) return input_error("arguments must be an array of strings");
            argument_list.reserve(arguments_value->as_array().size());
            for (const auto& item : arguments_value->as_array()) {
                if (!item.is_string()) return input_error("every argument must be a string");
                argument_list.push_back(item.as_string());
            }
        }

        domain::LaunchSpec spec;
        spec.executable = *executable;
        spec.arguments = std::move(argument_list);
        spec.working_directory = working_directory->empty()
            ? std::nullopt : std::optional<std::string>{*working_directory};
        spec.capture_output = *capture_output;

        auto result = service_.launch(spec, access, *authorized);
        if (!result) return domain_error(result.error());
        return success(session_to_json(*result));
    }

    if (name == "memory_debug.read_output") {
        auto session = session_arg(arguments);
        auto since_cursor = unsigned_arg(arguments, "since_cursor", false, 0U);
        auto max_bytes = unsigned_arg(arguments, "max_bytes", false, service_.policy().max_captured_output_bytes);
        if (!session) return input_error(session.error().message);
        if (!since_cursor) return input_error(since_cursor.error().message);
        if (!max_bytes) return input_error(max_bytes.error().message);
        auto result = service_.read_output(*session, *since_cursor, static_cast<std::size_t>(*max_bytes));
        if (!result) return domain_error(result.error());
        return success(output_chunk_to_json(*result));
    }

    if (name == "memory_debug.sessions") {
        Value::Array sessions;
        for (const auto& session : service_.list_sessions()) sessions.push_back(session_to_json(session));
        return success(Value::object({{"sessions", Value{std::move(sessions)}}}));
    }

    if (name == "memory_debug.regions") {
        auto session = session_arg(arguments);
        auto readable = optional_bool_arg(arguments, "readable");
        auto writable = optional_bool_arg(arguments, "writable");
        auto executable = optional_bool_arg(arguments, "executable");
        auto private_mapping = optional_bool_arg(arguments, "private");
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        auto min_size = unsigned_arg(arguments, "min_size", false, 0U);
        auto max_size = optional_unsigned_arg(arguments, "max_size");
        auto name_contains = string_arg(arguments, "name_contains", false);
        auto offset = unsigned_arg(arguments, "offset", false, 0U);
        auto limit = unsigned_arg(arguments, "limit", false, 512U);
        if (!session) return input_error(session.error().message);
        if (!readable) return input_error(readable.error().message);
        if (!writable) return input_error(writable.error().message);
        if (!executable) return input_error(executable.error().message);
        if (!private_mapping) return input_error(private_mapping.error().message);
        if (!start_address) return input_error(start_address.error().message);
        if (!end_address) return input_error(end_address.error().message);
        if (!min_size) return input_error(min_size.error().message);
        if (!max_size) return input_error(max_size.error().message);
        if (!name_contains) return input_error(name_contains.error().message);
        if (!offset) return input_error(offset.error().message);
        if (!limit) return input_error(limit.error().message);
        if (*offset > std::numeric_limits<std::size_t>::max()) {
            return input_error("offset is out of range");
        }
        if (*limit == 0U || *limit > 4096U || *limit > std::numeric_limits<std::size_t>::max()) {
            return input_error("limit must be between 1 and 4096");
        }

        domain::RegionFilter filter{};
        filter.readable = *readable;
        filter.writable = *writable;
        filter.executable = *executable;
        filter.private_mapping = *private_mapping;
        filter.start_address = *start_address;
        filter.end_address = *end_address;
        filter.min_size = *min_size;
        filter.max_size = *max_size;
        filter.name_contains = *name_contains;

        auto result = service_.regions_page(
            *session, filter, static_cast<std::size_t>(*offset), static_cast<std::size_t>(*limit)
        );
        if (!result) return domain_error(result.error());
        return success(region_page_to_json(*result));
    }

    if (name == "memory_debug.address_space_summary") {
        auto session = session_arg(arguments);
        if (!session) return input_error(session.error().message);
        auto result = service_.address_space_summary(*session);
        if (!result) return domain_error(result.error());
        return success(address_space_summary_to_json(*result));
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

    if (name == "memory_debug.pdb_list_types") {
        auto session = session_arg(arguments);
        auto module = string_arg(arguments, "module", true);
        auto name_filter = string_arg(arguments, "name_filter", false, "");
        auto kind_filter = string_arg(arguments, "kind_filter", false, "");
        auto max_symbols = unsigned_arg(arguments, "max_symbols", false, 2048U);
        if (!session) return input_error(session.error().message);
        if (!module) return input_error(module.error().message);
        if (!name_filter) return input_error(name_filter.error().message);
        if (!kind_filter) return input_error(kind_filter.error().message);
        if (!max_symbols || *max_symbols == 0U || *max_symbols > 65536U) {
            return input_error("max_symbols must be between 1 and 65536");
        }
        auto result = service_.pdb_list_types(
            *session, *module, *name_filter, *kind_filter, static_cast<std::size_t>(*max_symbols)
        );
        if (!result) return domain_error(result.error());
        return success(type_catalog_to_json(*result));
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

    if (name == "memory_debug.scan_first") {
        auto session = session_arg(arguments);
        auto value_type = value_type_arg(arguments);
        auto comparison = comparison_arg(arguments);
        if (!value_type) return input_error(value_type.error().message);
        auto value = scan_value_arg(arguments, "value", *value_type);
        auto range_low = scan_value_arg(arguments, "range_low", *value_type);
        auto range_high = scan_value_arg(arguments, "range_high", *value_type);
        auto budget = unsigned_arg(arguments, "byte_budget", false, service_.policy().max_scan_bytes);
        auto limit = unsigned_arg(
            arguments, "result_limit", false, service_.policy().max_scan_session_candidates
        );
        auto writable_only = bool_arg(arguments, "writable_only", false, false);
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        if (!session) return input_error(session.error().message);
        if (!value_type) return input_error(value_type.error().message);
        if (!comparison) return input_error(comparison.error().message);
        if (!value) return input_error(value.error().message);
        if (!range_low) return input_error(range_low.error().message);
        if (!range_high) return input_error(range_high.error().message);
        if (!budget) return input_error(budget.error().message);
        if (!limit) return input_error(limit.error().message);
        if (!writable_only) return input_error(writable_only.error().message);
        if (!start_address) return input_error(start_address.error().message);
        if (!end_address) return input_error(end_address.error().message);
        if (static_cast<bool>(*range_low) != static_cast<bool>(*range_high)) {
            return input_error("range_low and range_high must be provided together");
        }
        std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range;
        if (*range_low && *range_high) {
            range = std::pair<std::vector<std::byte>, std::vector<std::byte>>{**range_low, **range_high};
        }
        auto result = service_.scan_first(
            *session, *value_type, *comparison, *value, range,
            static_cast<std::size_t>(*budget), static_cast<std::size_t>(*limit), *writable_only,
            *start_address, *end_address, cancellation
        );
        if (!result) return domain_error(result.error());
        auto payload = scan_session_info_to_json(result->info);
        payload["coverage"] = scan_coverage_to_json(result->coverage);
        return success(std::move(payload));
    }

    if (name == "memory_debug.scan_next") {
        auto scan_id = scan_session_arg(arguments);
        auto comparison = comparison_arg(arguments);
        if (!scan_id) return input_error(scan_id.error().message);
        if (!comparison) return input_error(comparison.error().message);
        auto value_type = service_.scan_value_type(*scan_id);
        if (!value_type) return domain_error(value_type.error());
        auto value = scan_value_arg(arguments, "value", *value_type);
        auto delta = scan_value_arg(arguments, "delta", *value_type);
        if (!value) return input_error(value.error().message);
        if (!delta) return input_error(delta.error().message);
        auto result = service_.scan_next(*scan_id, *comparison, *value, *delta, cancellation);
        if (!result) return domain_error(result.error());
        return success(scan_session_info_to_json(*result));
    }

    if (name == "memory_debug.scan_results") {
        auto scan_id = scan_session_arg(arguments);
        auto offset = unsigned_arg(arguments, "offset", false, 0U);
        auto limit = unsigned_arg(arguments, "limit", false, 256U);
        if (!scan_id) return input_error(scan_id.error().message);
        if (!offset) return input_error(offset.error().message);
        if (!limit || *limit == 0U || *limit > 4096U) return input_error("limit must be between 1 and 4096");
        auto result = service_.scan_results_page(
            *scan_id, static_cast<std::size_t>(*offset), static_cast<std::size_t>(*limit)
        );
        if (!result) return domain_error(result.error());
        Value::Array matches;
        matches.reserve(result->matches.size());
        for (const auto& match : result->matches) matches.push_back(hex_address(match.address));
        auto payload = scan_session_info_to_json(result->info);
        payload["total"] = static_cast<std::int64_t>(result->info.candidate_count);
        payload["offset"] = static_cast<std::int64_t>(result->offset);
        payload["returned"] = static_cast<std::int64_t>(result->matches.size());
        payload["truncated"] = result->truncated;
        payload["matches"] = Value{std::move(matches)};
        return success(std::move(payload));
    }

    if (name == "memory_debug.scan_reset") {
        auto scan_id = scan_session_arg(arguments);
        if (!scan_id) return input_error(scan_id.error().message);
        auto result = service_.scan_reset(*scan_id);
        if (!result) return domain_error(result.error());
        return success(Value::object({}));
    }

    if (name == "memory_debug.scan_pointers_to") {
        auto session = session_arg(arguments);
        auto target = address_arg(arguments, "target_address");
        auto pointer_size_text = string_arg(arguments, "pointer_size", false, sizeof(void*) == 8U ? "8" : "4");
        auto budget = unsigned_arg(arguments, "byte_budget", false, service_.policy().max_scan_bytes);
        auto limit = unsigned_arg(arguments, "result_limit", false, service_.policy().max_scan_results);
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        auto writable_only = bool_arg(arguments, "writable_only", false, false);
        if (!session) return input_error(session.error().message);
        if (!target) return input_error(target.error().message);
        if (!pointer_size_text) return input_error(pointer_size_text.error().message);
        if (!budget) return input_error(budget.error().message);
        if (!limit) return input_error(limit.error().message);
        if (!start_address) return input_error(start_address.error().message);
        if (!end_address) return input_error(end_address.error().message);
        if (!writable_only) return input_error(writable_only.error().message);
        const std::size_t pointer_size = *pointer_size_text == "4" ? 4U : (*pointer_size_text == "8" ? 8U : 0U);
        if (pointer_size == 0U) return input_error("pointer_size must be 4 or 8");
        auto result = service_.scan_pointers_to(
            *session, *target, pointer_size, static_cast<std::size_t>(*budget),
            static_cast<std::size_t>(*limit), *writable_only, *start_address, *end_address, cancellation
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

    if (name == "memory_debug.scan_pointer_chains") {
        auto session = session_arg(arguments);
        auto target = address_arg(arguments, "target_address");
        auto pointer_size_text = string_arg(arguments, "pointer_size", false, sizeof(void*) == 8U ? "8" : "4");
        auto max_depth = unsigned_arg(arguments, "max_depth", false, service_.policy().max_pointer_chain_depth);
        auto max_fanout = unsigned_arg(arguments, "max_fanout", false, service_.policy().max_pointer_chain_fanout);
        auto budget = unsigned_arg(arguments, "byte_budget", false, service_.policy().max_scan_bytes);
        auto limit = unsigned_arg(arguments, "result_limit", false, service_.policy().max_scan_results);
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        auto writable_only = bool_arg(arguments, "writable_only", false, false);
        if (!session) return input_error(session.error().message);
        if (!target) return input_error(target.error().message);
        if (!pointer_size_text) return input_error(pointer_size_text.error().message);
        if (!max_depth) return input_error(max_depth.error().message);
        if (!max_fanout) return input_error(max_fanout.error().message);
        if (!budget) return input_error(budget.error().message);
        if (!limit) return input_error(limit.error().message);
        if (!start_address) return input_error(start_address.error().message);
        if (!end_address) return input_error(end_address.error().message);
        if (!writable_only) return input_error(writable_only.error().message);
        const std::size_t pointer_size = *pointer_size_text == "4" ? 4U : (*pointer_size_text == "8" ? 8U : 0U);
        if (pointer_size == 0U) return input_error("pointer_size must be 4 or 8");
        auto result = service_.scan_pointer_chains(
            *session, *target, pointer_size, static_cast<std::size_t>(*max_depth),
            static_cast<std::size_t>(*max_fanout), static_cast<std::size_t>(*budget),
            static_cast<std::size_t>(*limit), *writable_only, *start_address, *end_address, cancellation
        );
        if (!result) return domain_error(result.error());
        Value::Array candidates;
        candidates.reserve(result->candidates.size());
        for (const auto& candidate : result->candidates) {
            Value::Array offsets;
            offsets.reserve(candidate.hop_offsets.size());
            for (const auto offset : candidate.hop_offsets) offsets.push_back(static_cast<std::int64_t>(offset));
            candidates.push_back(Value::object({
                {"module", candidate.module_name},
                {"module_base", hex_address(candidate.module_base)},
                {"hop_offsets", Value{std::move(offsets)}},
                {"resolved_address", hex_address(candidate.resolved_address)}
            }));
        }
        return success(Value::object({
            {"candidates", Value{std::move(candidates)}},
            {"bytes_scanned", static_cast<std::int64_t>(result->bytes_scanned)},
            {"truncated", result->truncated}
        }));
    }

    if (name == "memory_debug.strings") {
        auto session = session_arg(arguments);
        auto start_address = optional_address_arg(arguments, "start_address");
        auto end_address = optional_address_arg(arguments, "end_address");
        auto min_length = unsigned_arg(arguments, "min_length", false, 4U);
        auto encoding = string_arg(arguments, "encoding", false, "ascii");
        auto budget = unsigned_arg(arguments, "byte_budget", false, service_.policy().max_scan_bytes);
        auto limit = unsigned_arg(arguments, "result_limit", false, service_.policy().max_scan_results);
        auto writable_only = bool_arg(arguments, "writable_only", false, false);
        if (!session) return input_error(session.error().message);
        if (!start_address) return input_error(start_address.error().message);
        if (!end_address) return input_error(end_address.error().message);
        if (!min_length) return input_error(min_length.error().message);
        if (!encoding) return input_error(encoding.error().message);
        if (!budget) return input_error(budget.error().message);
        if (!limit) return input_error(limit.error().message);
        if (!writable_only) return input_error(writable_only.error().message);
        auto result = service_.extract_strings(
            *session, static_cast<std::size_t>(*min_length), *encoding,
            static_cast<std::size_t>(*budget), static_cast<std::size_t>(*limit), *writable_only,
            *start_address, *end_address, cancellation
        );
        if (!result) return domain_error(result.error());
        return success(string_scan_result_to_json(*result));
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

    return std::nullopt;
}

}  // namespace argos::protocol::mcp
