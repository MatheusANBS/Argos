#include "argos_mcp/infrastructure/santa_monica_bridge_peer.hpp"

#include "argos_mcp/infrastructure/santa_monica_bridge_crypto.hpp"

#include <algorithm>
#include <new>
#include <utility>

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica bridge session failed", reason};
}

[[nodiscard]] reflection::Sha256Digest constant_digest(const unsigned char value) {
    reflection::Sha256Digest digest;
    digest.bytes.fill(static_cast<std::byte>(value));
    return digest;
}

// A rejection tells the peer that the session is over without describing which
// check failed; the detailed reason stays on the server side.
[[nodiscard]] HandshakeRejectReason reject_reason(const DebugErrorCode code) {
    switch (code) {
        case DebugErrorCode::unauthorized:
        case DebugErrorCode::access_denied:
            return HandshakeRejectReason::unauthorized;
        case DebugErrorCode::invalid_argument:
        case DebugErrorCode::parse_error:
            return HandshakeRejectReason::invalid_request;
        case DebugErrorCode::invalid_state:
            return HandshakeRejectReason::invalid_state;
        case DebugErrorCode::unsupported:
            return HandshakeRejectReason::unsupported;
        default:
            return HandshakeRejectReason::internal_error;
    }
}

void notify_rejection(LocalBridgeChannel& channel, const std::uint64_t request_id,
                      const std::uint64_t sequence, const DebugError& error,
                      const LocalBridgeChannel::Clock::time_point deadline) {
    // Best effort only: the session is already lost if this cannot be sent.
    const auto sent = send_handshake_frame(channel, HandshakeReject{reject_reason(error.code)},
                                           request_id, sequence, deadline, {});
    static_cast<void>(sent);
}

}  // namespace

reflection::ProfileIdentity controlled_peer_profile() {
    return {1,
            "argos-controlled-peer",
            constant_digest(0x11),
            constant_digest(0x22),
            1,
            1,
            {{"argos-controlled-peer.exe", 65536, constant_digest(0x33)}},
            reflection::Architecture::x64};
}

bridge::HandshakeBinding controlled_peer_binding(
    std::string process_instance, std::string bridge_epoch, const std::uint64_t request_id) {
    const auto profile = controlled_peer_profile();
    return {profile.protocol_version, profile.bridge_version, profile.profile_digest,
            profile.bridge_digest,    std::move(process_instance), std::move(bridge_epoch),
            request_id};
}

Result<void> serve_bridge_peer(
    LocalBridgeChannel& channel, bridge::BridgeSecret secret, bridge::HandshakeBinding binding,
    const PeerSnapshot& snapshot, const LocalBridgeChannel::Clock::time_point deadline,
    const std::stop_token cancellation) {
    auto authenticator = create_hmac_authenticator(std::move(secret));
    if (!authenticator) return std::unexpected(authenticator.error());
    auto random = create_system_random();
    if (!random) return std::unexpected(random.error());

    const auto request_id = binding.request_id;
    bridge::BridgeHandshakeClient client{**authenticator, std::move(binding),
                                         bridge::known_bridge_capabilities};

    auto hello = receive_handshake_frame(channel, request_id, 1, deadline, cancellation);
    if (!hello) return std::unexpected(hello.error());
    const auto* offer = std::get_if<bridge::HandshakeHello>(&*hello);
    if (offer == nullptr) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }

    auto attest = client.attest(*offer, **random);
    if (!attest) {
        notify_rejection(channel, request_id, 2, attest.error(), deadline);
        return std::unexpected(attest.error());
    }
    if (auto sent = send_handshake_frame(channel, *attest, request_id, 2, deadline, cancellation);
        !sent) {
        return std::unexpected(sent.error());
    }

    auto accept = receive_handshake_frame(channel, request_id, 3, deadline, cancellation);
    if (!accept) return std::unexpected(accept.error());
    if (const auto* rejected = std::get_if<HandshakeReject>(&*accept)) {
        static_cast<void>(rejected);
        return std::unexpected(fail(DebugErrorCode::unauthorized, "handshake_rejected"));
    }
    const auto* granted = std::get_if<bridge::HandshakeAccept>(&*accept);
    if (granted == nullptr) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }
    if (auto verified = client.verify(*granted); !verified) {
        return std::unexpected(verified.error());
    }
    if ((client.granted_capabilities() &
         static_cast<std::uint64_t>(bridge::BridgeCapability::reflection_read)) == 0) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "capability_unavailable"));
    }

    // Only now, with both sides proved, does any snapshot leave the peer.
    std::uint64_t sequence = 1;
    const auto emit = [&](const ReflectionMessage& message) -> Result<void> {
        auto frame = encode_reflection_frame(message, request_id, sequence++);
        if (!frame) return std::unexpected(frame.error());
        return channel.write(*frame, deadline, cancellation);
    };
    if (auto begin = emit(SnapshotBegin{snapshot.boundary}); !begin) {
        return std::unexpected(begin.error());
    }
    for (const auto& record : snapshot.records) {
        if (auto written = emit(record); !written) return std::unexpected(written.error());
    }
    return emit(SnapshotEnd{snapshot.boundary});
}

Result<std::unique_ptr<const reflection::ReflectionCatalog>> read_bridge_snapshot(
    LocalBridgeChannel& channel, bridge::BridgeSecret secret, bridge::HandshakeBinding binding,
    const reflection::ProfileIdentity& expected_profile, const reflection::ReflectionLimits& limits,
    const LocalBridgeChannel::Clock::time_point deadline, const std::stop_token cancellation) {
    auto authenticator = create_hmac_authenticator(std::move(secret));
    if (!authenticator) return std::unexpected(authenticator.error());
    auto random = create_system_random();
    if (!random) return std::unexpected(random.error());

    const auto request_id = binding.request_id;
    bridge::BridgeHandshakeServer server{**authenticator, std::move(binding),
                                         bridge::known_bridge_capabilities};

    auto hello = server.hello(**random);
    if (!hello) return std::unexpected(hello.error());
    if (auto sent = send_handshake_frame(channel, *hello, request_id, 1, deadline, cancellation);
        !sent) {
        return std::unexpected(sent.error());
    }

    auto attest = receive_handshake_frame(channel, request_id, 2, deadline, cancellation);
    if (!attest) return std::unexpected(attest.error());
    if (const auto* rejected = std::get_if<HandshakeReject>(&*attest)) {
        static_cast<void>(rejected);
        return std::unexpected(fail(DebugErrorCode::unauthorized, "handshake_rejected"));
    }
    const auto* proof = std::get_if<bridge::HandshakeAttest>(&*attest);
    if (proof == nullptr) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }
    auto accept = server.accept(*proof);
    if (!accept) {
        notify_rejection(channel, request_id, 3, accept.error(), deadline);
        return std::unexpected(accept.error());
    }
    if (auto sent = send_handshake_frame(channel, *accept, request_id, 3, deadline, cancellation);
        !sent) {
        return std::unexpected(sent.error());
    }

    try {
        const auto now = LocalBridgeChannel::Clock::now();
        const auto remaining = deadline > now
            ? std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            : std::chrono::milliseconds{1};
        ReflectionStreamLimits stream_limits;
        stream_limits.max_duration = std::min(stream_limits.max_duration, remaining);
        // The stream borrows the channel for the rest of this discovery only;
        // this session owns and closes it.
        ReflectionStreamReader reader{std::make_unique<ChannelReflectionStream>(channel), request_id,
                                      stream_limits};
        return reflection::ReflectionCatalog::read(reader, expected_profile, limits, cancellation);
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

}  // namespace argos::infrastructure::santamonica
