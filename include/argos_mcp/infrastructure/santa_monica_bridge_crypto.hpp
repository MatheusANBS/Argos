#pragma once

#include "argos_mcp/domain/santa_monica_bridge.hpp"

#include <memory>
#include <span>

namespace argos::infrastructure::santamonica {

namespace bridge = domain::santamonica;

// HMAC-SHA-256 and nonces come from the operating system provider (Windows
// CNG). No cryptographic primitive is implemented in this repository and there
// is no fallback: where the provider is absent the factory fails and the
// handshake stays unavailable, rather than accepting a peer without proof.
[[nodiscard]] domain::Result<std::unique_ptr<const bridge::MessageAuthenticator>>
create_hmac_authenticator(bridge::BridgeSecret secret);

[[nodiscard]] domain::Result<std::unique_ptr<bridge::RandomSource>> create_system_random();

// SHA-256 from the same provider, used to derive an identity from a profile
// definition. Like the rest of this header, it implements no primitive itself.
[[nodiscard]] domain::Result<bridge::Sha256Digest> sha256(std::span<const std::byte> message);

}  // namespace argos::infrastructure::santamonica
