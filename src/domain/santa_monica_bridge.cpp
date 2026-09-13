#include "argos_mcp/domain/santa_monica_bridge.hpp"

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>

namespace argos::domain::santamonica {
namespace {

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica bridge handshake failed", reason};
}

[[nodiscard]] bool printable(const std::string_view value, const std::size_t limit) noexcept {
    return !value.empty() && value.size() <= limit && std::ranges::all_of(value, [](const char c) {
        return c >= ' ' && c <= '~';
    });
}

[[nodiscard]] bool present(const Sha256Digest& digest) noexcept {
    return std::ranges::any_of(digest.bytes, [](const std::byte value) { return value != std::byte{}; });
}

[[nodiscard]] bool present(const HandshakeNonce& nonce) noexcept {
    return std::ranges::any_of(nonce.bytes, [](const std::byte value) { return value != std::byte{}; });
}

class Transcript {
public:
    void u32(const std::uint32_t value) { integer(value, 4); }
    void u64(const std::uint64_t value) { integer(value, 8); }
    void raw(const std::span<const std::byte> value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    void text(const std::string_view value) {
        u32(static_cast<std::uint32_t>(value.size()));
        for (const char c : value) bytes_.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    }
    [[nodiscard]] std::vector<std::byte> take() noexcept { return std::move(bytes_); }

private:
    void integer(const std::uint64_t value, const std::size_t width) {
        for (std::size_t index = 0; index < width; ++index) {
            bytes_.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU)));
        }
    }
    std::vector<std::byte> bytes_;
};

}  // namespace

// The domain cannot call SecureZeroMemory or explicit_bzero: no OS here.
void secure_zero(const std::span<std::byte> bytes) noexcept {
    volatile std::byte* cursor = bytes.data();
    for (std::size_t index = 0; index < bytes.size(); ++index) cursor[index] = std::byte{};
}

Result<BridgeSecret> BridgeSecret::create(const std::span<const std::byte> material) {
    if (material.size() < min_bridge_secret_bytes || material.size() > max_bridge_secret_bytes) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_secret_length"));
    }
    BridgeSecret secret;
    std::ranges::copy(material, secret.material_.begin());
    secret.size_ = material.size();
    return secret;
}

BridgeSecret::BridgeSecret(BridgeSecret&& other) noexcept
    : material_(other.material_), size_(other.size_) {
    secure_zero(other.material_);
    other.size_ = 0;
}

BridgeSecret& BridgeSecret::operator=(BridgeSecret&& other) noexcept {
    if (this != &other) {
        secure_zero(material_);
        material_ = other.material_;
        size_ = other.size_;
        secure_zero(other.material_);
        other.size_ = 0;
    }
    return *this;
}

BridgeSecret::~BridgeSecret() {
    secure_zero(material_);
    size_ = 0;
}

bool constant_time_equal(
    const std::span<const std::byte> left, const std::span<const std::byte> right) noexcept {
    // Length is not secret; content comparison never exits early.
    if (left.size() != right.size()) return false;
    unsigned char difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<unsigned char>(left[index] ^ right[index]);
    }
    return difference == 0;
}

Result<std::vector<std::byte>> handshake_transcript(
    const std::string_view label, const HandshakeBinding& binding, const HandshakeNonce& server_nonce,
    const HandshakeNonce& bridge_nonce, const std::uint64_t capabilities) {
    if (!printable(label, 64)) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_transcript_label"));
    }
    if (!valid_identity_token(binding.process_instance) ||
        !valid_identity_token(binding.bridge_epoch)) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_handshake_identity"));
    }
    try {
        Transcript out;
        out.text(label);
        out.u32(binding.protocol_version);
        out.u32(binding.bridge_version);
        out.u64(capabilities);
        out.raw(server_nonce.bytes);
        out.raw(bridge_nonce.bytes);
        out.raw(binding.profile_digest.bytes);
        out.raw(binding.bridge_digest.bytes);
        out.text(binding.process_instance);
        out.text(binding.bridge_epoch);
        out.u64(binding.request_id);
        return out.take();
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

BridgeHandshakeServer::BridgeHandshakeServer(
    const MessageAuthenticator& authenticator, HandshakeBinding binding,
    const std::uint64_t offered_capabilities)
    : authenticator_(authenticator), binding_(std::move(binding)), offered_(offered_capabilities) {}

DebugError BridgeHandshakeServer::reject(const DebugErrorCode code, const char* reason) {
    state_ = State::failed;
    granted_ = 0;
    server_nonce_ = {};
    return fail(code, reason);
}

Result<HandshakeHello> BridgeHandshakeServer::hello(RandomSource& random) {
    if (state_ != State::idle) {
        // A duplicate call never tears down a negotiation that already succeeded.
        if (state_ == State::established) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "handshake_state"));
        }
        return std::unexpected(reject(DebugErrorCode::invalid_state, "handshake_state"));
    }
    if (binding_.protocol_version != 1 || binding_.bridge_version == 0 || binding_.request_id == 0 ||
        !present(binding_.profile_digest) || !present(binding_.bridge_digest) ||
        !valid_identity_token(binding_.process_instance) ||
        !valid_identity_token(binding_.bridge_epoch)) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_binding"));
    }
    if (offered_ == 0 || (offered_ & ~known_bridge_capabilities) != 0) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_capability_offer"));
    }
    HandshakeNonce nonce;
    auto filled = random.fill(nonce.bytes);
    // A degenerate nonce is treated as an unusable source, never as a value.
    if (!filled || !present(nonce)) {
        return std::unexpected(reject(DebugErrorCode::io_error, "nonce_unavailable"));
    }
    server_nonce_ = nonce;
    state_ = State::offered;
    return HandshakeHello{binding_.protocol_version, binding_.request_id, nonce, offered_};
}

Result<HandshakeAccept> BridgeHandshakeServer::accept(const HandshakeAttest& attest) {
    if (state_ != State::offered) {
        if (state_ == State::established) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "handshake_state"));
        }
        return std::unexpected(reject(DebugErrorCode::invalid_state, "handshake_state"));
    }
    // Structural checks cover values the peer chose for itself; they leak
    // nothing about the expected identity.
    if (!present(attest.bridge_nonce) || attest.bridge_nonce == server_nonce_) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_bridge_nonce"));
    }
    if (attest.requested_capabilities == 0 ||
        (attest.requested_capabilities & ~known_bridge_capabilities) != 0 ||
        (attest.requested_capabilities & ~offered_) != 0) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_capability_request"));
    }

    // The transcript covers what was actually exchanged, so the tag proves
    // possession of the session secret over this exact declaration.
    const HandshakeBinding declared{attest.protocol_version, attest.bridge_version,
                                    attest.profile_digest,   attest.bridge_digest,
                                    attest.process_instance, attest.bridge_epoch,
                                    binding_.request_id};
    auto transcript = handshake_transcript(bridge_attest_label, declared, server_nonce_,
                                           attest.bridge_nonce, attest.requested_capabilities);
    if (!transcript) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_attestation"));
    }
    auto expected = authenticator_.tag(*transcript);
    if (!expected) {
        return std::unexpected(reject(DebugErrorCode::io_error, "authenticator_unavailable"));
    }
    if (!constant_time_equal(expected->bytes, attest.tag.bytes)) {
        return std::unexpected(reject(DebugErrorCode::unauthorized, "invalid_tag"));
    }

    // Only a peer that already proved possession reaches this comparison, and
    // the single reason never says which field diverged.
    if (attest.protocol_version != binding_.protocol_version ||
        attest.bridge_version != binding_.bridge_version ||
        !(attest.profile_digest == binding_.profile_digest) ||
        !(attest.bridge_digest == binding_.bridge_digest) ||
        attest.process_instance != binding_.process_instance ||
        attest.bridge_epoch != binding_.bridge_epoch) {
        return std::unexpected(reject(DebugErrorCode::unauthorized, "identity_mismatch"));
    }

    const auto granted = attest.requested_capabilities & offered_ & known_bridge_capabilities;
    auto accepted = handshake_transcript(server_accept_label, binding_, server_nonce_,
                                         attest.bridge_nonce, granted);
    if (!accepted) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_binding"));
    }
    auto tag = authenticator_.tag(*accepted);
    if (!tag) {
        return std::unexpected(reject(DebugErrorCode::io_error, "authenticator_unavailable"));
    }
    granted_ = granted;
    state_ = State::established;
    return HandshakeAccept{granted, *tag};
}

BridgeHandshakeClient::BridgeHandshakeClient(
    const MessageAuthenticator& authenticator, HandshakeBinding binding,
    const std::uint64_t requested_capabilities)
    : authenticator_(authenticator), binding_(std::move(binding)), requested_(requested_capabilities) {}

DebugError BridgeHandshakeClient::reject(const DebugErrorCode code, const char* reason) {
    state_ = State::failed;
    granted_ = 0;
    server_nonce_ = {};
    bridge_nonce_ = {};
    return fail(code, reason);
}

Result<HandshakeAttest> BridgeHandshakeClient::attest(
    const HandshakeHello& hello, RandomSource& random) {
    if (state_ != State::idle) {
        if (state_ == State::established) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "handshake_state"));
        }
        return std::unexpected(reject(DebugErrorCode::invalid_state, "handshake_state"));
    }
    if (binding_.protocol_version != 1 || binding_.bridge_version == 0 || binding_.request_id == 0 ||
        !present(binding_.profile_digest) || !present(binding_.bridge_digest) ||
        !valid_identity_token(binding_.process_instance) ||
        !valid_identity_token(binding_.bridge_epoch)) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_binding"));
    }
    if (requested_ == 0 || (requested_ & ~known_bridge_capabilities) != 0) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_capability_request"));
    }
    // The offer is the server's, so it is checked before anything is signed.
    if (hello.protocol_version != binding_.protocol_version || hello.request_id != binding_.request_id ||
        !present(hello.server_nonce)) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_offer"));
    }
    if (hello.offered_capabilities == 0 ||
        (hello.offered_capabilities & ~known_bridge_capabilities) != 0) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_capability_offer"));
    }
    const auto requested = requested_ & hello.offered_capabilities;
    if (requested == 0) {
        return std::unexpected(reject(DebugErrorCode::unsupported, "capability_unavailable"));
    }
    HandshakeNonce nonce;
    auto filled = random.fill(nonce.bytes);
    if (!filled || !present(nonce) || nonce == hello.server_nonce) {
        return std::unexpected(reject(DebugErrorCode::io_error, "nonce_unavailable"));
    }
    auto transcript = handshake_transcript(bridge_attest_label, binding_, hello.server_nonce, nonce,
                                           requested);
    if (!transcript) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_binding"));
    }
    auto tag = authenticator_.tag(*transcript);
    if (!tag) {
        return std::unexpected(reject(DebugErrorCode::io_error, "authenticator_unavailable"));
    }
    server_nonce_ = hello.server_nonce;
    bridge_nonce_ = nonce;
    requested_ = requested;
    state_ = State::attested;
    return HandshakeAttest{binding_.protocol_version,
                           binding_.bridge_version,
                           nonce,
                           binding_.profile_digest,
                           binding_.bridge_digest,
                           binding_.process_instance,
                           binding_.bridge_epoch,
                           requested,
                           *tag};
}

Result<void> BridgeHandshakeClient::verify(const HandshakeAccept& accept) {
    if (state_ != State::attested) {
        if (state_ == State::established) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "handshake_state"));
        }
        return std::unexpected(reject(DebugErrorCode::invalid_state, "handshake_state"));
    }
    // A grant is never wider than what this bridge asked for.
    if (accept.granted_capabilities == 0 || (accept.granted_capabilities & ~requested_) != 0) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_capability_grant"));
    }
    auto transcript = handshake_transcript(server_accept_label, binding_, server_nonce_, bridge_nonce_,
                                           accept.granted_capabilities);
    if (!transcript) {
        return std::unexpected(reject(DebugErrorCode::invalid_argument, "invalid_handshake_binding"));
    }
    auto expected = authenticator_.tag(*transcript);
    if (!expected) {
        return std::unexpected(reject(DebugErrorCode::io_error, "authenticator_unavailable"));
    }
    if (!constant_time_equal(expected->bytes, accept.tag.bytes)) {
        return std::unexpected(reject(DebugErrorCode::unauthorized, "invalid_tag"));
    }
    granted_ = accept.granted_capabilities;
    state_ = State::established;
    return {};
}

}  // namespace argos::domain::santamonica
