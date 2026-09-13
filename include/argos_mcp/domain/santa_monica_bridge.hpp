#pragma once

#include "argos_mcp/domain/santa_monica_runtime.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain::santamonica {

inline constexpr std::size_t handshake_nonce_bytes = 32;
inline constexpr std::size_t handshake_tag_bytes = 32;
inline constexpr std::size_t min_bridge_secret_bytes = 32;
inline constexpr std::size_t max_bridge_secret_bytes = 64;

// Domain separation: a proof for one direction never verifies for the other.
inline constexpr std::string_view bridge_attest_label = "argos-santamonica-bridge-attest-v1";
inline constexpr std::string_view server_accept_label = "argos-santamonica-server-accept-v1";

struct HandshakeNonce {
    std::array<std::byte, handshake_nonce_bytes> bytes{};
    [[nodiscard]] bool operator==(const HandshakeNonce&) const = default;
};

// Deliberately without operator==: tags are compared in constant time only.
struct HandshakeTag {
    std::array<std::byte, handshake_tag_bytes> bytes{};
};

// Closed capability set. Lua, gameplay and SLI invocation require their own
// ADR and proofs; this version negotiates read-only reflection alone.
enum class BridgeCapability : std::uint64_t {
    reflection_read = 1ULL << 0,
};
inline constexpr std::uint64_t known_bridge_capabilities =
    static_cast<std::uint64_t>(BridgeCapability::reflection_read);

// Ephemeral per-session secret delivered by a protected bootstrap channel.
// Fixed storage so no reallocation leaves a copy behind; zeroized on move and
// destruction; never reaches a transcript, error, log or wire field.
class BridgeSecret final {
public:
    [[nodiscard]] static Result<BridgeSecret> create(std::span<const std::byte> material);
    BridgeSecret(BridgeSecret&& other) noexcept;
    BridgeSecret& operator=(BridgeSecret&& other) noexcept;
    BridgeSecret(const BridgeSecret&) = delete;
    BridgeSecret& operator=(const BridgeSecret&) = delete;
    ~BridgeSecret();

    [[nodiscard]] std::span<const std::byte> material() const noexcept {
        return std::span{material_}.first(size_);
    }

private:
    BridgeSecret() = default;
    std::array<std::byte, max_bridge_secret_bytes> material_{};
    std::size_t size_{};
};

// What the server expects this channel to be bound to. Every field enters the
// transcript, so a declared identity is never believed without a valid tag.
struct HandshakeBinding {
    std::uint32_t protocol_version{1};
    std::uint32_t bridge_version{1};
    Sha256Digest profile_digest;
    Sha256Digest bridge_digest;
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t request_id{};
};

struct HandshakeHello {
    std::uint32_t protocol_version{1};
    std::uint64_t request_id{};
    HandshakeNonce server_nonce;
    std::uint64_t offered_capabilities{};
};

struct HandshakeAttest {
    std::uint32_t protocol_version{1};
    std::uint32_t bridge_version{1};
    HandshakeNonce bridge_nonce;
    Sha256Digest profile_digest;
    Sha256Digest bridge_digest;
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t requested_capabilities{};
    HandshakeTag tag;
};

struct HandshakeAccept {
    std::uint64_t granted_capabilities{};
    HandshakeTag tag;
};

// Port: the MAC primitive and its key live in infrastructure, never here.
class MessageAuthenticator {
public:
    virtual ~MessageAuthenticator() = default;
    [[nodiscard]] virtual Result<HandshakeTag> tag(std::span<const std::byte> message) const = 0;
};

// Port: nonces come from the operating system CSPRNG.
class RandomSource {
public:
    virtual ~RandomSource() = default;
    [[nodiscard]] virtual Result<void> fill(std::span<std::byte> destination) = 0;
};

// Canonical MAC input; any divergence in a bound field changes these bytes.
[[nodiscard]] Result<std::vector<std::byte>> handshake_transcript(
    std::string_view label, const HandshakeBinding& binding, const HandshakeNonce& server_nonce,
    const HandshakeNonce& bridge_nonce, std::uint64_t capabilities);

// Overwrites through a volatile view so the wipe is not optimized away. It
// clears the object it is given, not copies an allocator or the OS may hold.
void secure_zero(std::span<std::byte> bytes) noexcept;

// No early exit on the first differing byte.
[[nodiscard]] bool constant_time_equal(
    std::span<const std::byte> left, std::span<const std::byte> right) noexcept;

// Server side of one handshake. Single use: completion closes the negotiation
// and any failure invalidates it, requiring a new session, secret and nonce.
class BridgeHandshakeServer final {
public:
    BridgeHandshakeServer(const MessageAuthenticator& authenticator, HandshakeBinding binding,
                          std::uint64_t offered_capabilities);
    BridgeHandshakeServer(const BridgeHandshakeServer&) = delete;
    BridgeHandshakeServer& operator=(const BridgeHandshakeServer&) = delete;

    [[nodiscard]] Result<HandshakeHello> hello(RandomSource& random);
    [[nodiscard]] Result<HandshakeAccept> accept(const HandshakeAttest& attest);
    [[nodiscard]] bool established() const noexcept { return state_ == State::established; }
    [[nodiscard]] std::uint64_t granted_capabilities() const noexcept { return granted_; }

private:
    enum class State { idle, offered, established, failed };
    [[nodiscard]] DebugError reject(DebugErrorCode code, const char* reason);

    const MessageAuthenticator& authenticator_;
    HandshakeBinding binding_;
    std::uint64_t offered_;
    std::uint64_t granted_{};
    HandshakeNonce server_nonce_;
    State state_{State::idle};
};

// Bridge side of the same handshake, with the same single-use discipline. It
// proves itself to the server and only accepts a channel after verifying the
// server in turn, so neither side trusts a declaration without a tag.
class BridgeHandshakeClient final {
public:
    BridgeHandshakeClient(const MessageAuthenticator& authenticator, HandshakeBinding binding,
                          std::uint64_t requested_capabilities);
    BridgeHandshakeClient(const BridgeHandshakeClient&) = delete;
    BridgeHandshakeClient& operator=(const BridgeHandshakeClient&) = delete;

    [[nodiscard]] Result<HandshakeAttest> attest(const HandshakeHello& hello, RandomSource& random);
    [[nodiscard]] Result<void> verify(const HandshakeAccept& accept);
    [[nodiscard]] bool established() const noexcept { return state_ == State::established; }
    [[nodiscard]] std::uint64_t granted_capabilities() const noexcept { return granted_; }

private:
    enum class State { idle, attested, established, failed };
    [[nodiscard]] DebugError reject(DebugErrorCode code, const char* reason);

    const MessageAuthenticator& authenticator_;
    HandshakeBinding binding_;
    std::uint64_t requested_;
    std::uint64_t granted_{};
    HandshakeNonce server_nonce_;
    HandshakeNonce bridge_nonce_;
    State state_{State::idle};
};

}  // namespace argos::domain::santamonica
