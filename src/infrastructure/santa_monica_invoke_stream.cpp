#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include "detail/wire_bytes.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;
using wire::Cursor;
using wire::Writer;

constexpr std::uint16_t wire_version = 1;
constexpr std::array<std::byte, 4> frame_magic{
    std::byte{'S'}, std::byte{'M'}, std::byte{'I'}, std::byte{'F'}};

enum class FrameKind : std::uint16_t { command = 1, result = 2 };

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica invoke frame failed", reason};
}

[[nodiscard]] std::optional<std::uint8_t> encode_value_kind(const sm::EngineValueKind kind) {
    switch (kind) {
        case sm::EngineValueKind::integer: return std::uint8_t{0};
        case sm::EngineValueKind::floating: return std::uint8_t{1};
        case sm::EngineValueKind::boolean: return std::uint8_t{2};
        case sm::EngineValueKind::text: return std::uint8_t{3};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<sm::EngineValueKind> decode_value_kind(const std::uint8_t value) {
    switch (value) {
        case 0: return sm::EngineValueKind::integer;
        case 1: return sm::EngineValueKind::floating;
        case 2: return sm::EngineValueKind::boolean;
        case 3: return sm::EngineValueKind::text;
        default: return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::uint8_t> encode_state(const sm::EngineOperationState state) {
    switch (state) {
        case sm::EngineOperationState::queued: return std::uint8_t{0};
        case sm::EngineOperationState::running: return std::uint8_t{1};
        case sm::EngineOperationState::commit_in_progress: return std::uint8_t{2};
        case sm::EngineOperationState::completed: return std::uint8_t{3};
        case sm::EngineOperationState::cancelled: return std::uint8_t{4};
        case sm::EngineOperationState::failed: return std::uint8_t{5};
        case sm::EngineOperationState::outcome_unknown: return std::uint8_t{6};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<sm::EngineOperationState> decode_state(const std::uint8_t value) {
    switch (value) {
        case 0: return sm::EngineOperationState::queued;
        case 1: return sm::EngineOperationState::running;
        case 2: return sm::EngineOperationState::commit_in_progress;
        case 3: return sm::EngineOperationState::completed;
        case 4: return sm::EngineOperationState::cancelled;
        case 5: return sm::EngineOperationState::failed;
        case 6: return sm::EngineOperationState::outcome_unknown;
        default: return std::nullopt;
    }
}

// Text is length-prefixed raw bytes limited to printable ASCII. Unlike
// wire::Writer::string it permits an empty value, because a function may
// legitimately return an empty string; a non-empty result read from a target is
// sanitized to printable ASCII before it ever reaches this codec.
void write_text(Writer& out, const std::string& value) {
    out.u32(static_cast<std::uint32_t>(value.size()));
    for (const char ch : value) out.u8(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
}

[[nodiscard]] bool read_text(Cursor& in, std::string& out) {
    std::uint32_t length{};
    if (!in.u32(length)) return false;
    if (length > max_invoke_text_bytes) return in.reject("invalid_text_length");
    out.clear();
    out.reserve(length);
    for (std::uint32_t index = 0; index < length; ++index) {
        std::uint8_t byte{};
        if (!in.u8(byte)) return false;
        if (byte < 0x20U || byte > 0x7EU) return in.reject("invalid_text_byte");
        out.push_back(static_cast<char>(byte));
    }
    return true;
}

// One typed value (argument or return slot). integer/floating ride in a u64 by
// two's-complement / IEEE-754 bit pattern so no compiler ABI reaches the wire.
[[nodiscard]] bool write_value(
    Writer& out, const sm::EngineValueKind kind, const std::int64_t integer, const double floating,
    const bool boolean, const std::string& text) {
    const auto code = encode_value_kind(kind);
    if (!code) return false;
    out.u8(*code);
    switch (kind) {
        case sm::EngineValueKind::integer:
            out.u64(static_cast<std::uint64_t>(integer));
            return true;
        case sm::EngineValueKind::floating:
            out.u64(std::bit_cast<std::uint64_t>(floating));
            return true;
        case sm::EngineValueKind::boolean:
            out.boolean(boolean);
            return true;
        case sm::EngineValueKind::text:
            if (text.size() > max_invoke_text_bytes) return false;
            write_text(out, text);
            return true;
    }
    return false;
}

[[nodiscard]] bool read_value(
    Cursor& in, sm::EngineValueKind& kind, std::int64_t& integer, double& floating, bool& boolean,
    std::string& text) {
    std::uint8_t code{};
    if (!in.u8(code)) return false;
    const auto decoded = decode_value_kind(code);
    if (!decoded) return in.reject("invalid_value_kind");
    kind = *decoded;
    switch (kind) {
        case sm::EngineValueKind::integer: {
            std::uint64_t raw{};
            if (!in.u64(raw)) return false;
            integer = static_cast<std::int64_t>(raw);
            return true;
        }
        case sm::EngineValueKind::floating: {
            std::uint64_t raw{};
            if (!in.u64(raw)) return false;
            floating = std::bit_cast<double>(raw);
            return true;
        }
        case sm::EngineValueKind::boolean:
            return in.boolean(boolean);
        case sm::EngineValueKind::text:
            return read_text(in, text);
    }
    return in.reject("invalid_value_kind");
}

[[nodiscard]] Result<std::vector<std::byte>> finish_frame(
    Writer& payload, const FrameKind kind, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    if (payload.size() > max_invoke_payload_bytes) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "frame_too_large"));
    }
    Writer frame;
    for (const auto byte : frame_magic) frame.u8(static_cast<std::uint8_t>(byte));
    frame.u16(wire_version);
    frame.u16(static_cast<std::uint16_t>(invoke_header_bytes));
    frame.u16(static_cast<std::uint16_t>(kind));
    frame.u16(0);
    frame.u32(static_cast<std::uint32_t>(payload.size()));
    frame.u64(request_id);
    frame.u64(sequence);
    auto bytes = frame.take();
    const auto body = payload.take();
    bytes.insert(bytes.end(), body.begin(), body.end());
    return bytes;
}

// Validates the fixed 32-byte header and returns a cursor over the payload, or
// a typed error. Mirrors the reflection receiver's checks exactly.
[[nodiscard]] Result<std::vector<std::byte>> take_payload(
    const std::span<const std::byte> frame, const FrameKind expected_kind,
    const std::uint64_t expected_request, const std::uint64_t expected_sequence) {
    if (frame.size() < invoke_header_bytes || frame.size() > max_invoke_frame_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_frame_size"));
    }
    Cursor head{frame.first(invoke_header_bytes)};
    std::uint8_t magic_byte{};
    for (const auto expected : frame_magic) {
        if (!head.u8(magic_byte) || static_cast<std::byte>(magic_byte) != expected) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_magic"));
        }
    }
    std::uint16_t version{};
    std::uint16_t header_bytes{};
    std::uint16_t kind{};
    std::uint16_t reserved{};
    std::uint32_t payload_bytes{};
    std::uint64_t request{};
    std::uint64_t sequence{};
    if (!head.u16(version) || !head.u16(header_bytes) || !head.u16(kind) || !head.u16(reserved) ||
        !head.u32(payload_bytes) || !head.u64(request) || !head.u64(sequence) || !head.exhausted()) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "malformed_header"));
    }
    if (version != wire_version) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "unsupported_frame_version"));
    }
    if (header_bytes != invoke_header_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_header_length"));
    }
    if (reserved != 0) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_reserved_field"));
    }
    if (kind != static_cast<std::uint16_t>(expected_kind)) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }
    if (request != expected_request) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_request_id"));
    }
    if (sequence != expected_sequence) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_sequence"));
    }
    if (payload_bytes != frame.size() - invoke_header_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "payload_length_mismatch"));
    }
    const auto body = frame.subspan(invoke_header_bytes);
    return std::vector<std::byte>{body.begin(), body.end()};
}

}  // namespace

Result<std::vector<std::byte>> encode_invoke_command(
    const sm::EngineInvokeRequest& request, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    if (request_id == 0) return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_request_id"));
    if (sequence == 0) return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_sequence"));
    if (request.arguments.size() > max_invoke_arguments) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "too_many_arguments"));
    }
    if (!sm::valid_idempotency_key(request.idempotency_key)) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "idempotency_key_invalid"));
    }
    try {
        Writer payload;
        payload.u64(request.function_id.value);
        payload.u32(static_cast<std::uint32_t>(request.arguments.size()));
        for (const auto& argument : request.arguments) {
            if (!write_value(payload, argument.kind, argument.integer, argument.floating,
                             argument.boolean, argument.text)) {
                return std::unexpected(fail(DebugErrorCode::invalid_argument, "unencodable_argument"));
            }
        }
        write_text(payload, request.idempotency_key);
        return finish_frame(payload, FrameKind::command, request_id, sequence);
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

Result<std::vector<std::byte>> encode_invoke_result(
    const sm::EngineInvokeResult& result, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    if (request_id == 0) return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_request_id"));
    if (sequence == 0) return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_sequence"));
    const auto state = encode_state(result.state);
    if (!state) return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_state"));
    try {
        Writer payload;
        payload.u8(*state);
        if (!write_value(payload, result.return_kind, result.integer, result.floating, result.boolean,
                         result.text)) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "unencodable_result"));
        }
        payload.u64(result.duration_us);
        return finish_frame(payload, FrameKind::result, request_id, sequence);
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

Result<sm::EngineInvokeRequest> decode_invoke_command(
    const std::span<const std::byte> frame, const std::uint64_t expected_request,
    const std::uint64_t expected_sequence) {
    auto payload = take_payload(frame, FrameKind::command, expected_request, expected_sequence);
    if (!payload) return std::unexpected(payload.error());

    Cursor body{*payload};
    sm::EngineInvokeRequest request;
    std::uint32_t argument_count{};
    if (!body.u64(request.function_id.value) || !body.u32(argument_count)) {
        return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
    }
    if (argument_count > max_invoke_arguments) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "too_many_arguments"));
    }
    request.arguments.resize(argument_count);
    for (auto& argument : request.arguments) {
        if (!read_value(body, argument.kind, argument.integer, argument.floating, argument.boolean,
                        argument.text)) {
            return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
        }
    }
    if (!read_text(body, request.idempotency_key) || !body.exhausted()) {
        return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
    }
    if (!sm::valid_idempotency_key(request.idempotency_key)) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "idempotency_key_invalid"));
    }
    return request;
}

Result<sm::EngineInvokeResult> decode_invoke_result(
    const std::span<const std::byte> frame, const std::uint64_t expected_request,
    const std::uint64_t expected_sequence) {
    auto payload = take_payload(frame, FrameKind::result, expected_request, expected_sequence);
    if (!payload) return std::unexpected(payload.error());

    Cursor body{*payload};
    sm::EngineInvokeResult result;
    std::uint8_t state{};
    if (!body.u8(state)) return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
    const auto decoded_state = decode_state(state);
    if (!decoded_state) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_state"));
    result.state = *decoded_state;
    if (!read_value(body, result.return_kind, result.integer, result.floating, result.boolean,
                    result.text)) {
        return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
    }
    if (!body.u64(result.duration_us) || !body.exhausted()) {
        return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
    }
    return result;
}

}  // namespace argos::infrastructure::santamonica
