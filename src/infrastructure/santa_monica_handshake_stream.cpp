#include "argos_mcp/infrastructure/santa_monica_handshake_stream.hpp"

#include "detail/wire_bytes.hpp"

#include <array>
#include <new>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;
using wire::Cursor;
using wire::Writer;

constexpr std::uint16_t wire_version = 1;
constexpr std::size_t max_payload_bytes = max_handshake_frame_bytes - handshake_header_bytes;
constexpr std::size_t max_identity_bytes = 128;
constexpr std::array<std::byte, 4> frame_magic{
    std::byte{'S'}, std::byte{'M'}, std::byte{'B'}, std::byte{'H'}};

enum class FrameKind : std::uint16_t { hello = 1, attest = 2, accept = 3, reject = 4 };

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica handshake frame rejected", reason};
}

[[nodiscard]] std::optional<FrameKind> decode_kind(const std::uint16_t value) {
    switch (value) {
        case 1: return FrameKind::hello;
        case 2: return FrameKind::attest;
        case 3: return FrameKind::accept;
        case 4: return FrameKind::reject;
        default: return std::nullopt;
    }
}

[[nodiscard]] std::optional<HandshakeRejectReason> decode_reject_reason(const std::uint16_t value) {
    switch (value) {
        case 1: return HandshakeRejectReason::unauthorized;
        case 2: return HandshakeRejectReason::invalid_request;
        case 3: return HandshakeRejectReason::invalid_state;
        case 4: return HandshakeRejectReason::unsupported;
        case 5: return HandshakeRejectReason::internal_error;
        default: return std::nullopt;
    }
}

[[nodiscard]] bool write_payload(Writer& out, const HandshakeMessage& message) {
    return std::visit([&out](const auto& value) -> bool {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, bridge::HandshakeHello>) {
            // The request id lives in the header alone: one source of truth.
            out.u32(value.protocol_version);
            out.raw(value.server_nonce.bytes);
            out.u64(value.offered_capabilities);
        } else if constexpr (std::is_same_v<T, bridge::HandshakeAttest>) {
            out.u32(value.protocol_version);
            out.u32(value.bridge_version);
            out.raw(value.bridge_nonce.bytes);
            out.raw(value.profile_digest.bytes);
            out.raw(value.bridge_digest.bytes);
            if (!out.string(value.process_instance, max_identity_bytes)) return false;
            if (!out.string(value.bridge_epoch, max_identity_bytes)) return false;
            out.u64(value.requested_capabilities);
            out.raw(value.tag.bytes);
        } else if constexpr (std::is_same_v<T, bridge::HandshakeAccept>) {
            out.u64(value.granted_capabilities);
            out.raw(value.tag.bytes);
        } else {
            static_assert(std::is_same_v<T, HandshakeReject>);
            if (!decode_reject_reason(static_cast<std::uint16_t>(value.reason))) return false;
            out.u16(static_cast<std::uint16_t>(value.reason));
        }
        return true;
    }, message);
}

[[nodiscard]] FrameKind kind_of(const HandshakeMessage& message) {
    return std::visit([](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, bridge::HandshakeHello>) return FrameKind::hello;
        else if constexpr (std::is_same_v<T, bridge::HandshakeAttest>) return FrameKind::attest;
        else if constexpr (std::is_same_v<T, bridge::HandshakeAccept>) return FrameKind::accept;
        else return FrameKind::reject;
    }, message);
}

[[nodiscard]] bool read_payload(Cursor& in, const FrameKind kind, const std::uint64_t request_id,
                                HandshakeMessage& out) {
    switch (kind) {
        case FrameKind::hello: {
            bridge::HandshakeHello hello;
            if (!in.u32(hello.protocol_version) || !in.bytes(hello.server_nonce.bytes) ||
                !in.u64(hello.offered_capabilities)) {
                return false;
            }
            hello.request_id = request_id;
            out = std::move(hello);
            return true;
        }
        case FrameKind::attest: {
            bridge::HandshakeAttest attest;
            if (!in.u32(attest.protocol_version) || !in.u32(attest.bridge_version) ||
                !in.bytes(attest.bridge_nonce.bytes) || !in.bytes(attest.profile_digest.bytes) ||
                !in.bytes(attest.bridge_digest.bytes) ||
                !in.string(attest.process_instance, max_identity_bytes) ||
                !in.string(attest.bridge_epoch, max_identity_bytes) ||
                !in.u64(attest.requested_capabilities) || !in.bytes(attest.tag.bytes)) {
                return false;
            }
            out = std::move(attest);
            return true;
        }
        case FrameKind::accept: {
            bridge::HandshakeAccept accept;
            if (!in.u64(accept.granted_capabilities) || !in.bytes(accept.tag.bytes)) return false;
            out = accept;
            return true;
        }
        case FrameKind::reject: {
            std::uint16_t raw{};
            if (!in.u16(raw)) return false;
            const auto reason = decode_reject_reason(raw);
            if (!reason) return in.reject("invalid_reject_reason");
            out = HandshakeReject{*reason};
            return true;
        }
    }
    return in.reject("invalid_frame_kind");
}

struct ParsedHeader {
    FrameKind kind{FrameKind::reject};
    std::size_t payload_bytes{};
};

[[nodiscard]] Result<ParsedHeader> parse_header(
    const std::span<const std::byte> header, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    if (header.size() != handshake_header_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "truncated_header"));
    }
    Cursor in{header};
    std::uint8_t magic_byte{};
    for (const auto expected : frame_magic) {
        if (!in.u8(magic_byte) || static_cast<std::byte>(magic_byte) != expected) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_magic"));
        }
    }
    std::uint16_t version{};
    std::uint16_t header_bytes{};
    std::uint16_t kind{};
    std::uint16_t reserved{};
    std::uint32_t payload_bytes{};
    std::uint64_t declared_request{};
    std::uint64_t declared_sequence{};
    // A full header is already in hand, so these reads cannot truncate.
    if (!in.u16(version) || !in.u16(header_bytes) || !in.u16(kind) || !in.u16(reserved) ||
        !in.u32(payload_bytes) || !in.u64(declared_request) || !in.u64(declared_sequence) ||
        !in.exhausted()) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "malformed_header"));
    }
    if (version != wire_version) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "unsupported_frame_version"));
    }
    if (header_bytes != handshake_header_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_header_length"));
    }
    if (reserved != 0) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_reserved_field"));
    }
    const auto decoded = decode_kind(kind);
    if (!decoded) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_frame_kind"));
    }
    if (request_id == 0 || declared_request != request_id) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_request_id"));
    }
    if (sequence == 0 || declared_sequence != sequence) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_sequence"));
    }
    if (payload_bytes > max_payload_bytes) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "frame_too_large"));
    }
    return ParsedHeader{*decoded, static_cast<std::size_t>(payload_bytes)};
}

}  // namespace

Result<std::vector<std::byte>> encode_handshake_frame(
    const HandshakeMessage& message, const std::uint64_t request_id, const std::uint64_t sequence) {
    if (request_id == 0) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_request_id"));
    }
    if (sequence == 0) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_sequence"));
    }
    if (const auto* hello = std::get_if<bridge::HandshakeHello>(&message);
        hello != nullptr && hello->request_id != request_id) {
        // The header is the single source of truth; an inconsistent pair is a
        // caller mistake, never something the decoder has to reconcile.
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "inconsistent_request_id"));
    }
    try {
        Writer payload;
        if (!write_payload(payload, message)) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "unencodable_message"));
        }
        if (payload.size() > max_payload_bytes) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "frame_too_large"));
        }
        Writer frame;
        for (const auto byte : frame_magic) frame.u8(static_cast<std::uint8_t>(byte));
        frame.u16(wire_version);
        frame.u16(static_cast<std::uint16_t>(handshake_header_bytes));
        frame.u16(static_cast<std::uint16_t>(kind_of(message)));
        frame.u16(0);
        frame.u32(static_cast<std::uint32_t>(payload.size()));
        frame.u64(request_id);
        frame.u64(sequence);
        auto bytes = frame.take();
        const auto body = payload.take();
        bytes.insert(bytes.end(), body.begin(), body.end());
        return bytes;
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

Result<std::size_t> handshake_payload_size(
    const std::span<const std::byte> header, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    const auto parsed = parse_header(header, request_id, sequence);
    if (!parsed) return std::unexpected(parsed.error());
    return parsed->payload_bytes;
}

Result<HandshakeMessage> decode_handshake_frame(
    const std::span<const std::byte> frame, const std::uint64_t request_id,
    const std::uint64_t sequence) {
    if (frame.size() < handshake_header_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "truncated_header"));
    }
    const auto parsed = parse_header(frame.first(handshake_header_bytes), request_id, sequence);
    if (!parsed) return std::unexpected(parsed.error());
    const auto body_bytes = frame.size() - handshake_header_bytes;
    if (body_bytes < parsed->payload_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "truncated_frame"));
    }
    if (body_bytes > parsed->payload_bytes) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "trailing_frame_bytes"));
    }
    try {
        Cursor body{frame.subspan(handshake_header_bytes)};
        HandshakeMessage message;
        if (!read_payload(body, parsed->kind, request_id, message)) {
            return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
        }
        if (!body.exhausted()) {
            return std::unexpected(fail(DebugErrorCode::parse_error, body.reason()));
        }
        return message;
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

}  // namespace argos::infrastructure::santamonica
