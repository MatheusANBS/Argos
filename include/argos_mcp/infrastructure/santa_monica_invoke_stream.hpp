#pragma once

#include "argos_mcp/domain/santa_monica_invoke.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// Request/response wire codec for one engine-function invocation (Spec 0014
// stage 4, ADR-0023 framing). Unlike the reflection stream this is not a
// long-lived reader: a command frame goes to the bridge and exactly one result
// frame comes back, so the codec is a pair of pure encode/decode functions over
// complete frames. It performs no I/O, installs no transport and authenticates
// nothing -- the handshake (ADR-0024) and channel (ADR-0025) do that. Every
// length is checked against the frame before a destination is sized, and an
// unexpected request-id/sequence/version/kind is rejected, exactly as the
// reflection receiver does.
namespace argos::infrastructure::santamonica {

namespace sm = domain::santamonica;

inline constexpr std::size_t invoke_header_bytes = 32;
inline constexpr std::size_t max_invoke_frame_bytes = 64U * 1024U;
inline constexpr std::size_t max_invoke_payload_bytes = max_invoke_frame_bytes - invoke_header_bytes;
inline constexpr std::size_t max_invoke_arguments = 16;
inline constexpr std::size_t max_invoke_text_bytes = 4096;

// Server -> bridge: the validated command to run one allowlisted SLI function.
[[nodiscard]] domain::Result<std::vector<std::byte>> encode_invoke_command(
    const sm::EngineInvokeRequest& request, std::uint64_t request_id, std::uint64_t sequence);

// Bridge -> server: the outcome of that command. The state may be any terminal
// value, including outcome_unknown; the codec does not judge it.
[[nodiscard]] domain::Result<std::vector<std::byte>> encode_invoke_result(
    const sm::EngineInvokeResult& result, std::uint64_t request_id, std::uint64_t sequence);

// Bridge side: parse a complete command frame, rejecting a header whose
// request-id or sequence is not the expected one.
[[nodiscard]] domain::Result<sm::EngineInvokeRequest> decode_invoke_command(
    std::span<const std::byte> frame, std::uint64_t expected_request, std::uint64_t expected_sequence);

// Server side: parse a complete result frame under the same header discipline.
[[nodiscard]] domain::Result<sm::EngineInvokeResult> decode_invoke_result(
    std::span<const std::byte> frame, std::uint64_t expected_request, std::uint64_t expected_sequence);

}  // namespace argos::infrastructure::santamonica
