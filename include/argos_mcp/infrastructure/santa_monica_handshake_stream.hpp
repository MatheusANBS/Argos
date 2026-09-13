#pragma once

#include "argos_mcp/domain/santa_monica_bridge.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace argos::infrastructure::santamonica {

namespace bridge = domain::santamonica;

inline constexpr std::size_t handshake_header_bytes = 32;
inline constexpr std::size_t max_handshake_frame_bytes = 4096;

// Coarse on purpose: a peer that has not proved possession of the session
// secret never learns which check failed.
enum class HandshakeRejectReason : std::uint16_t {
    unauthorized = 1,
    invalid_request = 2,
    invalid_state = 3,
    unsupported = 4,
    internal_error = 5,
};

struct HandshakeReject {
    HandshakeRejectReason reason{HandshakeRejectReason::internal_error};
};

using HandshakeMessage = std::variant<bridge::HandshakeHello, bridge::HandshakeAttest,
                                      bridge::HandshakeAccept, HandshakeReject>;

// Portable, versioned wire encoding for the ADR-0024 handshake. It carries no
// secret, performs no authentication and installs no transport: the caller
// drives the sequence and the domain decides what a decoded frame means.
[[nodiscard]] domain::Result<std::vector<std::byte>> encode_handshake_frame(
    const HandshakeMessage& message, std::uint64_t request_id, std::uint64_t sequence);

// Validates the fixed header of the frame expected next and returns the
// declared payload size, so a transport reads the body without guessing.
[[nodiscard]] domain::Result<std::size_t> handshake_payload_size(
    std::span<const std::byte> header, std::uint64_t request_id, std::uint64_t sequence);

// Decodes one complete frame. Trailing bytes are a failure, never ignored.
[[nodiscard]] domain::Result<HandshakeMessage> decode_handshake_frame(
    std::span<const std::byte> frame, std::uint64_t request_id, std::uint64_t sequence);

}  // namespace argos::infrastructure::santamonica
