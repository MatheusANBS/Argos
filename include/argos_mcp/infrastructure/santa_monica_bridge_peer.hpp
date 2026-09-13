#pragma once

#include "argos_mcp/domain/santa_monica_bridge.hpp"
#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_channel.hpp"

#include <cstdint>
#include <memory>
#include <stop_token>
#include <string>
#include <vector>

namespace argos::infrastructure::santamonica {

// Identity of the controlled peer the server launches (ADR-0025). These are
// synthetic constants: the peer proves the protocol end to end, never a game
// build. A real bridge computes its own digests from the approved artifact.
[[nodiscard]] reflection::ProfileIdentity controlled_peer_profile();

[[nodiscard]] bridge::HandshakeBinding controlled_peer_binding(
    std::string process_instance, std::string bridge_epoch, std::uint64_t request_id);

struct PeerSnapshot {
    reflection::ReadBoundary boundary;
    std::vector<reflection::ReflectionRecord> records;
};

// Bridge side of one discovery: proves itself, verifies the server and then
// streams the snapshot. It never reads a game: the caller supplies the records.
[[nodiscard]] domain::Result<void> serve_bridge_peer(
    LocalBridgeChannel& channel, bridge::BridgeSecret secret, bridge::HandshakeBinding binding,
    const PeerSnapshot& snapshot, LocalBridgeChannel::Clock::time_point deadline,
    std::stop_token cancellation);

// Server side of one discovery: handshake, then the snapshot admitted by the
// domain catalog. A failure anywhere publishes nothing.
[[nodiscard]] domain::Result<std::unique_ptr<const reflection::ReflectionCatalog>>
read_bridge_snapshot(
    LocalBridgeChannel& channel, bridge::BridgeSecret secret, bridge::HandshakeBinding binding,
    const reflection::ProfileIdentity& expected_profile, const reflection::ReflectionLimits& limits,
    LocalBridgeChannel::Clock::time_point deadline, std::stop_token cancellation);

}  // namespace argos::infrastructure::santamonica
