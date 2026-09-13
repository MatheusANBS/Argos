#include "argos_mcp/domain/santa_monica_bridge.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_crypto.hpp"
#include "argos_mcp/infrastructure/santa_monica_handshake_stream.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// ---------------------------------------------------------------------------
// Fixtures and doubles.
// ---------------------------------------------------------------------------

Sha256Digest digest(const unsigned char value) {
    Sha256Digest result;
    result.bytes.fill(static_cast<std::byte>(value));
    return result;
}

HandshakeNonce nonce(const unsigned char value) {
    HandshakeNonce result;
    result.bytes.fill(static_cast<std::byte>(value));
    return result;
}

HandshakeBinding binding() {
    return {1, 1, digest(1), digest(2), "synthetic-process-1", "synthetic-epoch-1", 42};
}

std::vector<std::byte> secret_material(const unsigned char value, const std::size_t size = 32) {
    return std::vector<std::byte>(size, static_cast<std::byte>(value));
}

// Deterministic stand-in for the MAC: key dependent, message dependent and
// with no cryptographic claim. The real primitive is exercised separately.
class FakeAuthenticator final : public MessageAuthenticator {
public:
    explicit FakeAuthenticator(const std::uint64_t key) noexcept : key_(key) {}

    [[nodiscard]] Result<HandshakeTag> tag(const std::span<const std::byte> message) const override {
        if (fails) {
            return std::unexpected(DebugError{DebugErrorCode::io_error,
                                              "private-path native detail 0x1234", "private-native-reason"});
        }
        HandshakeTag out;
        for (std::uint64_t lane = 0; lane < 4; ++lane) {
            std::uint64_t hash = 1469598103934665603ULL ^ key_ ^ (lane * 0x100ULL);
            for (const auto byte : message) {
                hash ^= static_cast<std::uint64_t>(byte);
                hash *= 1099511628211ULL;
            }
            for (std::uint64_t index = 0; index < 8; ++index) {
                out.bytes[lane * 8 + index] =
                    static_cast<std::byte>(static_cast<std::uint8_t>((hash >> (8U * index)) & 0xFFU));
            }
        }
        return out;
    }

    bool fails{false};

private:
    std::uint64_t key_;
};

class FakeRandom final : public RandomSource {
public:
    [[nodiscard]] Result<void> fill(const std::span<std::byte> destination) override {
        ++calls;
        if (fails) {
            return std::unexpected(DebugError{DebugErrorCode::io_error, "native rng detail", "native"});
        }
        for (std::size_t index = 0; index < destination.size(); ++index) {
            destination[index] = zero ? std::byte{}
                                      : static_cast<std::byte>(static_cast<std::uint8_t>(seed + index));
        }
        return {};
    }

    std::uint8_t seed{1};
    bool zero{false};
    bool fails{false};
    std::size_t calls{};
};

HandshakeAttest sign_attest(const MessageAuthenticator& authenticator, const HandshakeBinding& declared,
                            const HandshakeNonce& server_nonce, const HandshakeNonce& bridge_nonce,
                            const std::uint64_t capabilities,
                            const std::string_view label = bridge_attest_label) {
    HandshakeAttest attest{declared.protocol_version,
                           declared.bridge_version,
                           bridge_nonce,
                           declared.profile_digest,
                           declared.bridge_digest,
                           declared.process_instance,
                           declared.bridge_epoch,
                           capabilities,
                           {}};
    auto transcript = handshake_transcript(label, declared, server_nonce, bridge_nonce, capabilities);
    check(transcript.has_value(), "fixture transcript builds");
    if (!transcript) return attest;
    auto tag = authenticator.tag(*transcript);
    check(tag.has_value(), "fixture tag computes");
    if (tag) attest.tag = *tag;
    return attest;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

void test_secret() {
    check(!BridgeSecret::create(secret_material(1, 31)), "secret below 32 bytes refused");
    check(!BridgeSecret::create(secret_material(1, 65)), "secret above 64 bytes refused");
    check(!BridgeSecret::create({}), "empty secret refused");
    auto minimum = BridgeSecret::create(secret_material(0xA5, 32));
    auto maximum = BridgeSecret::create(secret_material(0xA5, 64));
    check(minimum && minimum->material().size() == 32, "32-byte secret accepted");
    check(maximum && maximum->material().size() == 64, "64-byte secret accepted");
    if (minimum) {
        check(std::ranges::all_of(minimum->material(),
                                  [](const std::byte value) { return value == std::byte{0xA5}; }),
              "secret keeps its material");
        auto moved = std::move(*minimum);
        check(moved.material().size() == 32, "moved secret keeps its material");
        check(minimum->material().empty(), "moved-from secret holds nothing");
    }

    // The wipe is an invariant, so it is checked on the object storage itself.
    alignas(BridgeSecret) std::byte storage[sizeof(BridgeSecret)]{};
    auto created = BridgeSecret::create(secret_material(0xA5, 48));
    check(created.has_value(), "secret for the wipe check builds");
    if (created) {
        auto* secret = new (static_cast<void*>(storage)) BridgeSecret(std::move(*created));
        const bool stored = std::ranges::any_of(
            storage, [](const std::byte value) { return value == std::byte{0xA5}; });
        secret->~BridgeSecret();
        const bool wiped = std::ranges::none_of(
            storage, [](const std::byte value) { return value == std::byte{0xA5}; });
        check(stored, "secret material is present while the object lives");
        check(wiped, "secret material is zeroized on destruction");
    }
}

void test_constant_time_equal() {
    const std::array<std::byte, 4> left{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    auto right = left;
    check(constant_time_equal(left, right), "equal spans compare equal");
    right[0] = std::byte{9};
    check(!constant_time_equal(left, right), "first-byte difference detected");
    right = left;
    right[3] = std::byte{9};
    check(!constant_time_equal(left, right), "last-byte difference detected");
    check(!constant_time_equal(left, std::span{left}.first(3)), "different lengths never compare equal");
    check(constant_time_equal({}, {}), "empty spans compare equal");
}

void test_transcript() {
    const auto base = handshake_transcript(bridge_attest_label, binding(), nonce(3), nonce(4),
                                           known_bridge_capabilities);
    check(base.has_value(), "valid transcript builds");
    if (!base) return;

    // Byte-exact canonical form, built independently of the production code.
    std::vector<std::byte> expected;
    const auto u32 = [&expected](const std::uint32_t value) {
        for (std::uint32_t index = 0; index < 4; ++index) {
            expected.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU)));
        }
    };
    const auto u64 = [&expected](const std::uint64_t value) {
        for (std::uint64_t index = 0; index < 8; ++index) {
            expected.push_back(static_cast<std::byte>(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU)));
        }
    };
    const auto text = [&expected, &u32](const std::string_view value) {
        u32(static_cast<std::uint32_t>(value.size()));
        for (const char c : value) expected.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
    };
    const auto raw = [&expected](const std::span<const std::byte> value) {
        expected.insert(expected.end(), value.begin(), value.end());
    };
    text(bridge_attest_label);
    u32(1);
    u32(1);
    u64(known_bridge_capabilities);
    raw(nonce(3).bytes);
    raw(nonce(4).bytes);
    raw(digest(1).bytes);
    raw(digest(2).bytes);
    text("synthetic-process-1");
    text("synthetic-epoch-1");
    u64(42);
    check(*base == expected, "transcript matches the documented canonical form");

    check(*handshake_transcript(bridge_attest_label, binding(), nonce(3), nonce(4),
                                known_bridge_capabilities) == *base,
          "transcript is deterministic");

    // Every bound field must change the bytes, or it is not really bound.
    std::vector<std::vector<std::byte>> variants;
    const auto record = [&variants](Result<std::vector<std::byte>> value, const char* label) {
        check(value.has_value(), label);
        if (value) variants.push_back(std::move(*value));
    };
    auto changed = binding();
    changed.protocol_version = 2;
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "protocol variant builds");
    changed = binding();
    changed.bridge_version = 2;
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "bridge version variant builds");
    changed = binding();
    changed.profile_digest = digest(9);
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "profile digest variant builds");
    changed = binding();
    changed.bridge_digest = digest(9);
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "bridge digest variant builds");
    changed = binding();
    changed.process_instance = "synthetic-process-2";
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "process variant builds");
    changed = binding();
    changed.bridge_epoch = "synthetic-epoch-2";
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "epoch variant builds");
    changed = binding();
    changed.request_id = 43;
    record(handshake_transcript(bridge_attest_label, changed, nonce(3), nonce(4), known_bridge_capabilities),
           "request variant builds");
    record(handshake_transcript(server_accept_label, binding(), nonce(3), nonce(4), known_bridge_capabilities),
           "label variant builds");
    record(handshake_transcript(bridge_attest_label, binding(), nonce(5), nonce(4), known_bridge_capabilities),
           "server nonce variant builds");
    record(handshake_transcript(bridge_attest_label, binding(), nonce(3), nonce(5), known_bridge_capabilities),
           "bridge nonce variant builds");
    record(handshake_transcript(bridge_attest_label, binding(), nonce(3), nonce(4), 0),
           "capability variant builds");
    for (const auto& variant : variants) {
        check(variant != *base, "each bound field changes the transcript");
    }
    for (std::size_t outer = 0; outer < variants.size(); ++outer) {
        for (std::size_t inner = outer + 1; inner < variants.size(); ++inner) {
            check(variants[outer] != variants[inner], "bound fields do not collide with each other");
        }
    }

    check(!handshake_transcript("", binding(), nonce(3), nonce(4), 1), "empty label refused");
    check(!handshake_transcript(std::string(65, 'a'), binding(), nonce(3), nonce(4), 1),
          "oversized label refused");
    check(!handshake_transcript(std::string("bad\x01label", 9), binding(), nonce(3), nonce(4), 1),
          "non-printable label refused");
    auto invalid = binding();
    invalid.process_instance = "bad process";
    check(!handshake_transcript(bridge_attest_label, invalid, nonce(3), nonce(4), 1),
          "non-canonical process instance refused");
    invalid = binding();
    invalid.bridge_epoch = std::string(129, 'a');
    check(!handshake_transcript(bridge_attest_label, invalid, nonce(3), nonce(4), 1),
          "oversized bridge epoch refused");
    invalid = binding();
    invalid.bridge_epoch.clear();
    check(!handshake_transcript(bridge_attest_label, invalid, nonce(3), nonce(4), 1),
          "empty bridge epoch refused");
}

void test_handshake_success() {
    const FakeAuthenticator authenticator{7};
    FakeRandom random;
    BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
    auto hello = server.hello(random);
    check(hello.has_value(), "hello issued");
    if (!hello) return;
    check(hello->request_id == 42 && hello->protocol_version == 1, "hello carries the bound request");
    check(hello->offered_capabilities == known_bridge_capabilities, "hello offers the policy capabilities");
    check(!server.established(), "offering does not establish the channel");

    const auto attest = sign_attest(authenticator, binding(), hello->server_nonce, nonce(9),
                                    known_bridge_capabilities);
    auto accept = server.accept(attest);
    check(accept.has_value(), "valid attestation accepted");
    if (!accept) return;
    check(server.established() && server.granted_capabilities() == known_bridge_capabilities,
          "channel established with the granted capabilities");
    check(accept->granted_capabilities == known_bridge_capabilities, "grant is reported to the bridge");

    // The bridge verifies the server in turn, over its own transcript.
    auto expected = handshake_transcript(server_accept_label, binding(), hello->server_nonce, nonce(9),
                                         accept->granted_capabilities);
    check(expected.has_value(), "accept transcript builds");
    if (expected) {
        auto tag = authenticator.tag(*expected);
        check(tag && constant_time_equal(tag->bytes, accept->tag.bytes),
              "accept proves the server to the bridge");
    }

    // A grant is never larger than what the peer asked for.
    const FakeAuthenticator other{7};
    FakeRandom other_random;
    BridgeHandshakeServer narrow{other, binding(), known_bridge_capabilities};
    auto narrow_hello = narrow.hello(other_random);
    check(narrow_hello.has_value(), "second hello issued");
    if (narrow_hello) {
        const auto requested = static_cast<std::uint64_t>(BridgeCapability::reflection_read);
        const auto narrow_attest = sign_attest(other, binding(), narrow_hello->server_nonce, nonce(9),
                                               requested);
        auto narrow_accept = narrow.accept(narrow_attest);
        check(narrow_accept && narrow_accept->granted_capabilities == requested,
              "grant is the intersection of offer and request");
    }
}

void test_handshake_rejections() {
    const FakeAuthenticator authenticator{7};

    struct Case {
        const char* label;
        const char* reason;
        DebugErrorCode code;
    };

    const auto run = [&](const Case& scenario, const auto& build) {
        FakeRandom random;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(hello.has_value(), "hello issued");
        if (!hello) return;
        auto result = server.accept(build(*hello));
        check(!result, scenario.label);
        if (!result) {
            check(result.error().reason == scenario.reason, scenario.reason);
            check(result.error().code == scenario.code, "rejection uses the documented code");
        }
        check(!server.established(), "a rejected handshake is never established");
        auto again = server.accept(build(*hello));
        check(!again && again.error().reason == "handshake_state", "a failed handshake stays failed");
    };

    run({"wrong secret refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            const FakeAuthenticator impostor{8};
            return sign_attest(impostor, binding(), hello.server_nonce, nonce(9), known_bridge_capabilities);
        });
    run({"proof from the other direction refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            return sign_attest(authenticator, binding(), hello.server_nonce, nonce(9),
                               known_bridge_capabilities, server_accept_label);
        });
    run({"proof bound to another nonce refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto attest = sign_attest(authenticator, binding(), hello.server_nonce, nonce(8),
                                      known_bridge_capabilities);
            attest.bridge_nonce = nonce(9);
            return attest;
        });
    run({"tampered tag refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto attest = sign_attest(authenticator, binding(), hello.server_nonce, nonce(9),
                                      known_bridge_capabilities);
            attest.tag.bytes[31] ^= std::byte{1};
            return attest;
        });
    run({"identity divergence refused after the proof", "identity_mismatch", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto declared = binding();
            declared.bridge_epoch = "synthetic-epoch-2";
            return sign_attest(authenticator, declared, hello.server_nonce, nonce(9),
                               known_bridge_capabilities);
        });
    run({"foreign profile digest refused after the proof", "identity_mismatch", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto declared = binding();
            declared.profile_digest = digest(9);
            return sign_attest(authenticator, declared, hello.server_nonce, nonce(9),
                               known_bridge_capabilities);
        });
    run({"zero bridge nonce refused", "invalid_bridge_nonce", DebugErrorCode::invalid_argument},
        [&](const HandshakeHello& hello) {
            return sign_attest(authenticator, binding(), hello.server_nonce, HandshakeNonce{},
                               known_bridge_capabilities);
        });
    run({"mirrored server nonce refused", "invalid_bridge_nonce", DebugErrorCode::invalid_argument},
        [&](const HandshakeHello& hello) {
            return sign_attest(authenticator, binding(), hello.server_nonce, hello.server_nonce,
                               known_bridge_capabilities);
        });
    run({"unknown capability refused", "invalid_capability_request", DebugErrorCode::invalid_argument},
        [&](const HandshakeHello& hello) {
            return sign_attest(authenticator, binding(), hello.server_nonce, nonce(9), 1ULL << 63);
        });
    run({"empty capability request refused", "invalid_capability_request", DebugErrorCode::invalid_argument},
        [&](const HandshakeHello& hello) {
            return sign_attest(authenticator, binding(), hello.server_nonce, nonce(9), 0);
        });
    run({"capability inflated after signing refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto attest = sign_attest(authenticator, binding(), hello.server_nonce, nonce(9), 0);
            attest.requested_capabilities = known_bridge_capabilities;
            return attest;
        });
    run({"version changed after signing refused", "invalid_tag", DebugErrorCode::unauthorized},
        [&](const HandshakeHello& hello) {
            auto attest = sign_attest(authenticator, binding(), hello.server_nonce, nonce(9),
                                      known_bridge_capabilities);
            attest.bridge_version = 2;
            return attest;
        });

    {
        FakeAuthenticator failing{7};
        FakeRandom random;
        BridgeHandshakeServer server{failing, binding(), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(hello.has_value(), "hello issued");
        if (hello) {
            const FakeAuthenticator honest{7};
            const auto attest = sign_attest(honest, binding(), hello->server_nonce, nonce(9),
                                            known_bridge_capabilities);
            failing.fails = true;
            auto result = server.accept(attest);
            check(!result && result.error().reason == "authenticator_unavailable",
                  "authenticator failure is reported without native detail");
            if (!result) {
                check(result.error().safe_message.find("private") == std::string::npos,
                      "authenticator diagnostics never reach the caller");
            }
        }
    }
}

void test_binding_and_state() {
    const FakeAuthenticator authenticator{7};

    const auto expect_binding_failure = [&](HandshakeBinding invalid, const char* label) {
        FakeRandom random;
        BridgeHandshakeServer server{authenticator, std::move(invalid), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(!hello && hello.error().reason == "invalid_handshake_binding", label);
        check(random.calls == 0, "an invalid binding never consumes a nonce");
    };
    auto invalid = binding();
    invalid.protocol_version = 2;
    expect_binding_failure(invalid, "unsupported protocol version refused");
    invalid = binding();
    invalid.bridge_version = 0;
    expect_binding_failure(invalid, "zero bridge version refused");
    invalid = binding();
    invalid.request_id = 0;
    expect_binding_failure(invalid, "zero request id refused");
    invalid = binding();
    invalid.profile_digest = {};
    expect_binding_failure(invalid, "absent profile digest refused");
    invalid = binding();
    invalid.bridge_digest = {};
    expect_binding_failure(invalid, "absent bridge digest refused");
    invalid = binding();
    invalid.process_instance = "bad process";
    expect_binding_failure(invalid, "non-canonical process instance refused");
    invalid = binding();
    invalid.bridge_epoch.clear();
    expect_binding_failure(invalid, "empty bridge epoch refused");

    for (const std::uint64_t offer : {std::uint64_t{0}, std::uint64_t{1ULL << 63}}) {
        FakeRandom random;
        BridgeHandshakeServer server{authenticator, binding(), offer};
        auto hello = server.hello(random);
        check(!hello && hello.error().reason == "invalid_capability_offer",
              "an offer outside the closed set is refused");
    }
    {
        FakeRandom random;
        random.fails = true;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(!hello && hello.error().reason == "nonce_unavailable", "a failing CSPRNG blocks the handshake");
    }
    {
        FakeRandom random;
        random.zero = true;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(!hello && hello.error().reason == "nonce_unavailable", "a degenerate nonce is never used");
    }
    {
        FakeRandom random;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        auto early = server.accept(sign_attest(authenticator, binding(), nonce(3), nonce(9),
                                               known_bridge_capabilities));
        check(!early && early.error().reason == "handshake_state", "accept before hello refused");
        auto hello = server.hello(random);
        check(!hello && hello.error().reason == "handshake_state", "a failed handshake stays failed");
    }
    {
        FakeRandom random;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        check(server.hello(random).has_value(), "first hello issued");
        auto again = server.hello(random);
        check(!again && again.error().reason == "handshake_state", "a second hello refused");
    }
    {
        FakeRandom first;
        FakeRandom second;
        second.seed = 40;
        BridgeHandshakeServer server{authenticator, binding(), known_bridge_capabilities};
        auto hello = server.hello(first);
        check(hello.has_value(), "hello issued");
        if (hello) {
            const auto attest = sign_attest(authenticator, binding(), hello->server_nonce, nonce(9),
                                            known_bridge_capabilities);
            check(server.accept(attest).has_value(), "handshake established");
            auto replay = server.accept(attest);
            check(!replay && replay.error().reason == "handshake_state",
                  "a replayed attestation is refused after establishment");
            check(server.established() && server.granted_capabilities() == known_bridge_capabilities,
                  "misuse never tears down an established channel");
            auto late = server.hello(second);
            check(!late && late.error().reason == "handshake_state", "hello after establishment refused");
            check(server.established(), "an established channel survives a late hello");
        }
    }
    {
        // The same attestation never authenticates a second, fresh handshake.
        FakeRandom first;
        FakeRandom second;
        second.seed = 40;
        BridgeHandshakeServer original{authenticator, binding(), known_bridge_capabilities};
        auto hello = original.hello(first);
        check(hello.has_value(), "hello issued");
        if (hello) {
            const auto attest = sign_attest(authenticator, binding(), hello->server_nonce, nonce(9),
                                            known_bridge_capabilities);
            check(original.accept(attest).has_value(), "handshake established");
            BridgeHandshakeServer replayed{authenticator, binding(), known_bridge_capabilities};
            auto fresh = replayed.hello(second);
            check(fresh.has_value(), "fresh hello issued");
            check(fresh && !(fresh->server_nonce == hello->server_nonce), "each handshake uses a fresh nonce");
            auto result = replayed.accept(attest);
            check(!result && result.error().reason == "invalid_tag",
                  "an attestation from another handshake is refused");
        }
    }
}

// ---------------------------------------------------------------------------
// The real primitive.
// ---------------------------------------------------------------------------

#if defined(_WIN32)

std::array<std::byte, 32> sha256(const std::span<const std::byte> message) {
    std::array<std::byte, 32> out{};
    BCRYPT_ALG_HANDLE algorithm{};
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return out;
    }
    BCRYPT_HASH_HANDLE hash{};
    if (BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0))) {
        if (!message.empty()) {
            BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(message.data())),
                           static_cast<ULONG>(message.size()), 0);
        }
        BCryptFinishHash(hash, reinterpret_cast<PUCHAR>(out.data()), static_cast<ULONG>(out.size()), 0);
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return out;
}

// HMAC built from the raw hash, per RFC 2104, as an independent cross-check of
// the provider's own HMAC mode.
std::array<std::byte, 32> manual_hmac(const std::span<const std::byte> key,
                                      const std::span<const std::byte> message) {
    std::array<std::byte, 64> block{};
    std::ranges::copy(key, block.begin());  // Our keys are 32..64 bytes.
    std::vector<std::byte> inner;
    inner.reserve(block.size() + message.size());
    for (const auto byte : block) inner.push_back(byte ^ std::byte{0x36});
    inner.insert(inner.end(), message.begin(), message.end());
    const auto digested = sha256(inner);
    std::vector<std::byte> outer;
    outer.reserve(block.size() + digested.size());
    for (const auto byte : block) outer.push_back(byte ^ std::byte{0x5c});
    outer.insert(outer.end(), digested.begin(), digested.end());
    return sha256(outer);
}

std::string hex(const std::span<const std::byte> bytes) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        const auto value = static_cast<unsigned char>(byte);
        out.push_back(digits[value >> 4U]);
        out.push_back(digits[value & 0x0FU]);
    }
    return out;
}

void test_system_crypto() {
    // Known answer for the underlying hash, so the cross-check below rests on
    // a verified primitive rather than on the provider agreeing with itself.
    const std::string_view abc = "abc";
    const auto abc_bytes = std::as_bytes(std::span{abc});
    check(hex(sha256(abc_bytes)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "provider SHA-256 matches the published vector");

    for (const std::size_t size : {std::size_t{32}, std::size_t{48}, std::size_t{64}}) {
        const auto material = secret_material(0x5a, size);
        auto secret = BridgeSecret::create(material);
        check(secret.has_value(), "secret builds");
        if (!secret) continue;
        auto authenticator = infra::create_hmac_authenticator(std::move(*secret));
        check(authenticator.has_value(), "HMAC authenticator builds");
        if (!authenticator) continue;
        const std::string_view text = "argos santa monica handshake transcript";
        const auto message = std::as_bytes(std::span{text});
        auto tag = (*authenticator)->tag(message);
        check(tag.has_value(), "tag computes");
        if (!tag) continue;
        check(hex(tag->bytes) == hex(manual_hmac(material, message)),
              "provider HMAC matches the RFC 2104 construction over SHA-256");
        auto again = (*authenticator)->tag(message);
        check(again && constant_time_equal(again->bytes, tag->bytes), "tag is deterministic");

        std::vector<std::byte> altered(message.begin(), message.end());
        altered[0] ^= std::byte{1};
        auto different = (*authenticator)->tag(altered);
        check(different && !constant_time_equal(different->bytes, tag->bytes),
              "one flipped message bit changes the tag");

        auto other_material = material;
        other_material[0] ^= std::byte{1};
        auto other_secret = BridgeSecret::create(other_material);
        check(other_secret.has_value(), "second secret builds");
        if (!other_secret) continue;
        auto other = infra::create_hmac_authenticator(std::move(*other_secret));
        check(other.has_value(), "second authenticator builds");
        if (!other) continue;
        auto other_tag = (*other)->tag(message);
        check(other_tag && !constant_time_equal(other_tag->bytes, tag->bytes),
              "one flipped key bit changes the tag");

        auto empty = (*authenticator)->tag({});
        check(empty && hex(empty->bytes) == hex(manual_hmac(material, {})), "empty message is supported");
    }

    auto random = infra::create_system_random();
    check(random.has_value(), "system CSPRNG builds");
    if (!random) return;
    HandshakeNonce first;
    HandshakeNonce second;
    check((*random)->fill(first.bytes).has_value(), "nonce filled");
    check((*random)->fill(second.bytes).has_value(), "second nonce filled");
    check(!(first == HandshakeNonce{}) && !(second == HandshakeNonce{}), "nonces are not zero");
    check(!(first == second), "nonces differ between calls");

    // The real primitive drives a real handshake end to end.
    auto secret = BridgeSecret::create(secret_material(0x31, 32));
    auto peer_secret = BridgeSecret::create(secret_material(0x31, 32));
    check(secret && peer_secret, "session secrets build");
    if (!secret || !peer_secret) return;
    auto server_side = infra::create_hmac_authenticator(std::move(*secret));
    auto bridge_side = infra::create_hmac_authenticator(std::move(*peer_secret));
    check(server_side && bridge_side, "both sides build an authenticator");
    if (!server_side || !bridge_side) return;
    BridgeHandshakeServer server{**server_side, binding(), known_bridge_capabilities};
    auto hello = server.hello(**random);
    check(hello.has_value(), "hello issued with a real nonce");
    if (!hello) return;
    HandshakeNonce bridge_nonce;
    check((*random)->fill(bridge_nonce.bytes).has_value(), "bridge nonce filled");
    const auto attest = sign_attest(**bridge_side, binding(), hello->server_nonce, bridge_nonce,
                                    known_bridge_capabilities);
    auto accept = server.accept(attest);
    check(accept.has_value() && server.established(), "real handshake completes");
}

#else

void test_system_crypto() {
    auto authenticator = infra::create_hmac_authenticator(*BridgeSecret::create(secret_material(1, 32)));
    check(!authenticator && authenticator.error().code == DebugErrorCode::unsupported,
          "without a provider the handshake is unavailable, never unauthenticated");
    auto random = infra::create_system_random();
    check(!random && random.error().code == DebugErrorCode::unsupported, "no fallback CSPRNG");
}

#endif


// ---------------------------------------------------------------------------
// Handshake wire format (ADR-0024).
// ---------------------------------------------------------------------------

class Bytes {
public:
    void u8(const std::uint8_t value) { data.push_back(static_cast<std::byte>(value)); }
    void u16(const std::uint16_t value) { integer(value, 2); }
    void u32(const std::uint32_t value) { integer(value, 4); }
    void u64(const std::uint64_t value) { integer(value, 8); }
    void raw(const std::span<const std::byte> value) {
        data.insert(data.end(), value.begin(), value.end());
    }
    void text(const std::string_view value) {
        u32(static_cast<std::uint32_t>(value.size()));
        for (const char c : value) u8(static_cast<std::uint8_t>(c));
    }
    std::vector<std::byte> data;

private:
    void integer(const std::uint64_t value, const std::size_t width) {
        for (std::size_t index = 0; index < width; ++index) {
            u8(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU));
        }
    }
};

std::vector<std::byte> expected_frame(const std::uint16_t kind, const std::vector<std::byte>& payload,
                                      const std::uint64_t request_id, const std::uint64_t sequence) {
    Bytes out;
    out.u8('S');
    out.u8('M');
    out.u8('B');
    out.u8('H');
    out.u16(1);
    out.u16(32);
    out.u16(kind);
    out.u16(0);
    out.u32(static_cast<std::uint32_t>(payload.size()));
    out.u64(request_id);
    out.u64(sequence);
    out.raw(payload);
    return out.data;
}

HandshakeHello sample_hello() {
    return {1, 42, nonce(3), known_bridge_capabilities};
}

HandshakeAttest sample_attest() {
    HandshakeAttest attest{1, 1, nonce(4), digest(1), digest(2), "synthetic-process-1",
                           "synthetic-epoch-1", known_bridge_capabilities, {}};
    attest.tag.bytes.fill(std::byte{0x7f});
    return attest;
}

HandshakeAccept sample_accept() {
    HandshakeAccept accept{known_bridge_capabilities, {}};
    accept.tag.bytes.fill(std::byte{0x5e});
    return accept;
}

void test_frame_format() {
    Bytes hello_payload;
    hello_payload.u32(1);
    hello_payload.raw(nonce(3).bytes);
    hello_payload.u64(known_bridge_capabilities);
    auto hello = infra::encode_handshake_frame(sample_hello(), 42, 1);
    check(hello.has_value(), "hello frame encodes");
    check(hello && *hello == expected_frame(1, hello_payload.data, 42, 1),
          "hello frame matches the documented bytes");
    if (hello) {
        check(hello->size() == infra::handshake_header_bytes + hello_payload.data.size(),
              "hello frame carries exactly its header and payload");
        check((*hello)[0] == std::byte{'S'} && (*hello)[1] == std::byte{'M'} &&
              (*hello)[2] == std::byte{'B'} && (*hello)[3] == std::byte{'H'}, "magic is SMBH");
    }

    Bytes attest_payload;
    attest_payload.u32(1);
    attest_payload.u32(1);
    attest_payload.raw(nonce(4).bytes);
    attest_payload.raw(digest(1).bytes);
    attest_payload.raw(digest(2).bytes);
    attest_payload.text("synthetic-process-1");
    attest_payload.text("synthetic-epoch-1");
    attest_payload.u64(known_bridge_capabilities);
    attest_payload.raw(sample_attest().tag.bytes);
    auto attest = infra::encode_handshake_frame(sample_attest(), 42, 2);
    check(attest && *attest == expected_frame(2, attest_payload.data, 42, 2),
          "attest frame matches the documented bytes");

    Bytes accept_payload;
    accept_payload.u64(known_bridge_capabilities);
    accept_payload.raw(sample_accept().tag.bytes);
    auto accept = infra::encode_handshake_frame(sample_accept(), 42, 3);
    check(accept && *accept == expected_frame(3, accept_payload.data, 42, 3),
          "accept frame matches the documented bytes");

    Bytes reject_payload;
    reject_payload.u16(1);
    auto reject = infra::encode_handshake_frame(
        infra::HandshakeReject{infra::HandshakeRejectReason::unauthorized}, 42, 3);
    check(reject && *reject == expected_frame(4, reject_payload.data, 42, 3),
          "reject frame matches the documented bytes");

    // Every handshake frame fits the negotiated ceiling by a wide margin.
    check(attest && attest->size() <= infra::max_handshake_frame_bytes, "attest fits the frame ceiling");
}

void test_frame_round_trip() {
    auto hello = infra::encode_handshake_frame(sample_hello(), 42, 1);
    check(hello.has_value(), "hello encodes");
    if (hello) {
        auto decoded = infra::decode_handshake_frame(*hello, 42, 1);
        check(decoded.has_value(), "hello decodes");
        if (decoded) {
            const auto* value = std::get_if<HandshakeHello>(&*decoded);
            check(value != nullptr, "hello keeps its kind");
            if (value != nullptr) {
                check(value->protocol_version == 1 &&
                      value->offered_capabilities == known_bridge_capabilities,
                      "hello fields round-trip");
                check(value->server_nonce == nonce(3), "server nonce round-trips");
                check(value->request_id == 42, "request id comes from the header");
            }
        }
        auto size = infra::handshake_payload_size(
            std::span{*hello}.first(infra::handshake_header_bytes), 42, 1);
        check(size && *size == hello->size() - infra::handshake_header_bytes,
              "declared payload size matches the frame");
    }

    auto attest = infra::encode_handshake_frame(sample_attest(), 42, 2);
    check(attest.has_value(), "attest encodes");
    if (attest) {
        auto decoded = infra::decode_handshake_frame(*attest, 42, 2);
        check(decoded.has_value(), "attest decodes");
        if (decoded) {
            const auto* value = std::get_if<HandshakeAttest>(&*decoded);
            check(value != nullptr, "attest keeps its kind");
            if (value != nullptr) {
                const auto original = sample_attest();
                check(value->protocol_version == 1 && value->bridge_version == 1, "versions round-trip");
                check(value->bridge_nonce == original.bridge_nonce, "bridge nonce round-trips");
                check(value->profile_digest == original.profile_digest &&
                      value->bridge_digest == original.bridge_digest, "digests round-trip");
                check(value->process_instance == original.process_instance &&
                      value->bridge_epoch == original.bridge_epoch, "identity round-trips");
                check(value->requested_capabilities == known_bridge_capabilities,
                      "requested capabilities round-trip");
                check(constant_time_equal(value->tag.bytes, original.tag.bytes), "tag round-trips");
            }
        }
    }

    auto accept = infra::encode_handshake_frame(sample_accept(), 42, 3);
    check(accept.has_value(), "accept encodes");
    if (accept) {
        auto decoded = infra::decode_handshake_frame(*accept, 42, 3);
        const auto* value = decoded ? std::get_if<HandshakeAccept>(&*decoded) : nullptr;
        check(value != nullptr && value->granted_capabilities == known_bridge_capabilities &&
              constant_time_equal(value->tag.bytes, sample_accept().tag.bytes), "accept round-trips");
    }

    for (const auto reason : {infra::HandshakeRejectReason::unauthorized,
                              infra::HandshakeRejectReason::invalid_request,
                              infra::HandshakeRejectReason::invalid_state,
                              infra::HandshakeRejectReason::unsupported,
                              infra::HandshakeRejectReason::internal_error}) {
        auto frame = infra::encode_handshake_frame(infra::HandshakeReject{reason}, 42, 4);
        check(frame.has_value(), "reject encodes");
        if (!frame) continue;
        auto decoded = infra::decode_handshake_frame(*frame, 42, 4);
        const auto* value = decoded ? std::get_if<infra::HandshakeReject>(&*decoded) : nullptr;
        check(value != nullptr && value->reason == reason, "every reject reason round-trips");
    }
}

void test_frame_rejections() {
    check(!infra::encode_handshake_frame(sample_hello(), 0, 1), "zero request id refused");
    check(!infra::encode_handshake_frame(sample_attest(), 42, 0), "zero sequence refused");
    {
        auto inconsistent = sample_hello();
        inconsistent.request_id = 43;
        check(!infra::encode_handshake_frame(inconsistent, 42, 1), "inconsistent request id refused");
    }
    {
        auto invalid = sample_attest();
        invalid.process_instance.clear();
        check(!infra::encode_handshake_frame(invalid, 42, 2), "empty identity refused");
        invalid = sample_attest();
        invalid.bridge_epoch = std::string(129, 'a');
        check(!infra::encode_handshake_frame(invalid, 42, 2), "oversized identity refused");
        invalid = sample_attest();
        invalid.process_instance = std::string("bad\x01name", 8);
        check(!infra::encode_handshake_frame(invalid, 42, 2), "non-printable identity refused");
    }
    check(!infra::encode_handshake_frame(
              infra::HandshakeReject{static_cast<infra::HandshakeRejectReason>(99)}, 42, 3),
          "unknown reject reason refused");

    const auto base = infra::encode_handshake_frame(sample_attest(), 42, 2);
    check(base.has_value(), "base frame encodes");
    if (!base) return;

    const auto expect = [](std::vector<std::byte> frame, const char* reason,
                           const DebugErrorCode code = DebugErrorCode::parse_error) {
        auto decoded = infra::decode_handshake_frame(frame, 42, 2);
        check(!decoded, reason);
        if (!decoded) {
            check(decoded.error().reason == reason, reason);
            check(decoded.error().code == code, "rejection uses the documented code");
        }
    };

    auto frame = *base;
    frame[3] = std::byte{'X'};
    expect(frame, "invalid_magic");
    frame = *base;
    frame[4] = std::byte{2};
    expect(frame, "unsupported_frame_version", DebugErrorCode::unsupported);
    frame = *base;
    frame[6] = std::byte{33};
    expect(frame, "invalid_header_length");
    frame = *base;
    frame[8] = std::byte{5};
    expect(frame, "invalid_frame_kind");
    frame = *base;
    frame[8] = std::byte{0};
    expect(frame, "invalid_frame_kind");
    frame = *base;
    frame[10] = std::byte{1};
    expect(frame, "invalid_reserved_field");
    frame = *base;
    frame[16] = std::byte{43};
    expect(frame, "unexpected_request_id");
    frame = *base;
    frame[24] = std::byte{3};
    expect(frame, "unexpected_sequence");
    frame = *base;
    frame[12] = std::byte{0x88};
    frame[13] = std::byte{0x13};  // 5000 bytes, above the 4 KiB frame ceiling
    expect(frame, "frame_too_large", DebugErrorCode::limit_exceeded);
    frame = *base;
    frame.pop_back();
    expect(frame, "truncated_frame");
    frame = *base;
    frame.push_back(std::byte{0});
    expect(frame, "trailing_frame_bytes");
    frame.assign(base->begin(), std::next(base->begin(), 16));
    expect(frame, "truncated_header");

    // The identity strings inside the payload keep their own ceilings.
    constexpr std::size_t identity_offset = infra::handshake_header_bytes + 4 + 4 + 32 + 32 + 32;
    frame = *base;
    frame[identity_offset] = std::byte{0};
    expect(frame, "invalid_string_length");
    frame = *base;
    frame[identity_offset] = std::byte{129};
    expect(frame, "invalid_string_length");
    frame = *base;
    frame[identity_offset + 4] = std::byte{0x01};
    expect(frame, "invalid_string_byte");

    // A payload longer than the message it declares is never tolerated.
    auto accept = infra::encode_handshake_frame(sample_accept(), 42, 3);
    check(accept.has_value(), "accept encodes");
    if (accept) {
        auto padded = *accept;
        padded.push_back(std::byte{0});
        padded[12] = static_cast<std::byte>(
            static_cast<std::uint8_t>(padded.size() - infra::handshake_header_bytes));
        auto decoded = infra::decode_handshake_frame(padded, 42, 3);
        check(!decoded && decoded.error().reason == "trailing_payload_bytes",
              "a payload longer than its message is refused");
    }

    auto reject = infra::encode_handshake_frame(
        infra::HandshakeReject{infra::HandshakeRejectReason::unauthorized}, 42, 3);
    check(reject.has_value(), "reject encodes");
    if (reject) {
        auto unknown = *reject;
        unknown[infra::handshake_header_bytes] = std::byte{9};
        auto decoded = infra::decode_handshake_frame(unknown, 42, 3);
        check(!decoded && decoded.error().reason == "invalid_reject_reason",
              "an unknown reject reason is refused");
    }

    auto size = infra::handshake_payload_size(std::span{*base}.first(16), 42, 2);
    check(!size && size.error().reason == "truncated_header", "a short header is refused");
    size = infra::handshake_payload_size(*base, 42, 2);
    check(!size && size.error().reason == "truncated_header", "a whole frame is not a header");
}

void test_wire_handshake() {
    const FakeAuthenticator server_side{11};
    const FakeAuthenticator bridge_side{11};
    FakeRandom random;
    BridgeHandshakeServer server{server_side, binding(), known_bridge_capabilities};

    auto hello = server.hello(random);
    check(hello.has_value(), "hello issued");
    if (!hello) return;
    auto hello_frame = infra::encode_handshake_frame(*hello, hello->request_id, 1);
    check(hello_frame.has_value(), "hello frame encodes");
    if (!hello_frame) return;
    auto received_hello = infra::decode_handshake_frame(*hello_frame, hello->request_id, 1);
    check(received_hello.has_value(), "bridge decodes the hello");
    if (!received_hello) return;
    const auto* opening = std::get_if<HandshakeHello>(&*received_hello);
    check(opening != nullptr, "hello arrives as a hello");
    if (opening == nullptr) return;

    const auto attest = sign_attest(bridge_side, binding(), opening->server_nonce, nonce(9),
                                    opening->offered_capabilities);
    auto attest_frame = infra::encode_handshake_frame(attest, opening->request_id, 2);
    check(attest_frame.has_value(), "attest frame encodes");
    if (!attest_frame) return;
    auto received_attest = infra::decode_handshake_frame(*attest_frame, hello->request_id, 2);
    check(received_attest.has_value(), "server decodes the attestation");
    if (!received_attest) return;
    const auto* proof = std::get_if<HandshakeAttest>(&*received_attest);
    check(proof != nullptr, "attestation arrives as an attestation");
    if (proof == nullptr) return;

    auto accept = server.accept(*proof);
    check(accept.has_value() && server.established(), "handshake completes over the wire");
    if (!accept) return;
    auto accept_frame = infra::encode_handshake_frame(*accept, hello->request_id, 3);
    check(accept_frame.has_value(), "accept frame encodes");
    if (!accept_frame) return;
    auto received_accept = infra::decode_handshake_frame(*accept_frame, hello->request_id, 3);
    const auto* granted = received_accept ? std::get_if<HandshakeAccept>(&*received_accept) : nullptr;
    check(granted != nullptr, "bridge decodes the acceptance");
    if (granted == nullptr) return;

    auto expected = handshake_transcript(server_accept_label, binding(), opening->server_nonce, nonce(9),
                                         granted->granted_capabilities);
    check(expected.has_value(), "bridge builds the accept transcript");
    if (!expected) return;
    auto tag = bridge_side.tag(*expected);
    check(tag && constant_time_equal(tag->bytes, granted->tag.bytes),
          "the bridge verifies the server from the decoded frame");

    // A frame from this handshake never passes at another position.
    check(!infra::decode_handshake_frame(*attest_frame, hello->request_id, 3),
          "a frame replayed into another position is refused");
    check(!infra::decode_handshake_frame(*attest_frame, hello->request_id + 1, 2),
          "a frame from another request is refused");
}


// ---------------------------------------------------------------------------
// Bridge side of the handshake.
// ---------------------------------------------------------------------------

void test_mutual_handshake() {
    const FakeAuthenticator shared{21};
    FakeRandom server_random;
    FakeRandom bridge_random;
    bridge_random.seed = 90;
    BridgeHandshakeServer server{shared, binding(), known_bridge_capabilities};
    BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};

    auto hello = server.hello(server_random);
    check(hello.has_value(), "server offers");
    if (!hello) return;
    auto attest = client.attest(*hello, bridge_random);
    check(attest.has_value(), "bridge attests");
    if (!attest) return;
    auto accept = server.accept(*attest);
    check(accept.has_value(), "server accepts the bridge");
    if (!accept) return;
    auto verified = client.verify(*accept);
    check(verified.has_value(), "bridge verifies the server");
    check(server.established() && client.established(), "both sides establish the channel");
    check(server.granted_capabilities() == client.granted_capabilities() &&
          client.granted_capabilities() == known_bridge_capabilities,
          "both sides agree on the granted capabilities");

    // A second, independent handshake never reuses a nonce or a proof.
    FakeRandom other_server_random;
    other_server_random.seed = 200;
    BridgeHandshakeServer fresh{shared, binding(), known_bridge_capabilities};
    auto fresh_hello = fresh.hello(other_server_random);
    check(fresh_hello.has_value(), "fresh server offers");
    if (fresh_hello) {
        check(!(fresh_hello->server_nonce == hello->server_nonce), "each offer carries a fresh nonce");
        auto replay = fresh.accept(*attest);
        check(!replay && replay.error().reason == "invalid_tag",
              "an attestation never authenticates another handshake");
    }
}

void test_client_rejections() {
    const FakeAuthenticator shared{21};

    const auto offer = [&] {
        FakeRandom random;
        BridgeHandshakeServer server{shared, binding(), known_bridge_capabilities};
        auto hello = server.hello(random);
        check(hello.has_value(), "server offers");
        return hello.value_or(HandshakeHello{});
    };

    const auto expect_offer_failure = [&](HandshakeHello hello, const char* reason) {
        FakeRandom random;
        random.seed = 90;
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        auto attest = client.attest(hello, random);
        check(!attest, reason);
        if (!attest) check(attest.error().reason == reason, reason);
        check(!client.established(), "a rejected offer never establishes the channel");
    };

    auto hello = offer();
    hello.request_id = 43;
    expect_offer_failure(hello, "invalid_handshake_offer");
    hello = offer();
    hello.protocol_version = 2;
    expect_offer_failure(hello, "invalid_handshake_offer");
    hello = offer();
    hello.server_nonce = {};
    expect_offer_failure(hello, "invalid_handshake_offer");
    hello = offer();
    hello.offered_capabilities = 0;
    expect_offer_failure(hello, "invalid_capability_offer");
    hello = offer();
    hello.offered_capabilities = 1ULL << 63;
    expect_offer_failure(hello, "invalid_capability_offer");

    {
        FakeRandom random;
        random.seed = 90;
        BridgeHandshakeClient client{shared, binding(), 1ULL << 62};
        auto attest = client.attest(offer(), random);
        check(!attest && attest.error().reason == "invalid_capability_request",
              "a request outside the closed set is refused");
    }
    {
        auto invalid = binding();
        invalid.bridge_epoch = "bad epoch";
        FakeRandom random;
        BridgeHandshakeClient client{shared, std::move(invalid), known_bridge_capabilities};
        auto attest = client.attest(offer(), random);
        check(!attest && attest.error().reason == "invalid_handshake_binding",
              "a non-canonical binding is refused before signing");
        check(random.calls == 0, "an invalid binding never consumes a nonce");
    }
    {
        FakeRandom random;
        random.fails = true;
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        auto attest = client.attest(offer(), random);
        check(!attest && attest.error().reason == "nonce_unavailable",
              "a failing CSPRNG blocks the attestation");
    }
    {
        // A nonce equal to the server's is refused, not silently reused.
        const auto server_hello = offer();
        FakeRandom random;
        random.seed = 1;
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        auto attest = client.attest(server_hello, random);
        check(!attest && attest.error().reason == "nonce_unavailable",
              "a mirrored nonce is refused");
    }

    // Verification of the server.
    const auto establish = [&](BridgeHandshakeClient& client) {
        FakeRandom random;
        random.seed = 90;
        auto attest = client.attest(offer(), random);
        check(attest.has_value(), "bridge attests");
        return attest.has_value();
    };
    {
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        if (establish(client)) {
            HandshakeAccept forged{known_bridge_capabilities, {}};
            auto verified = client.verify(forged);
            check(!verified && verified.error().reason == "invalid_tag",
                  "a server without the secret is refused");
            auto again = client.verify(forged);
            check(!again && again.error().reason == "handshake_state", "a failed bridge stays failed");
        }
    }
    {
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        if (establish(client)) {
            auto verified = client.verify({0, {}});
            check(!verified && verified.error().reason == "invalid_capability_grant",
                  "an empty grant is refused");
        }
    }
    {
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        if (establish(client)) {
            auto verified = client.verify({known_bridge_capabilities | (1ULL << 40), {}});
            check(!verified && verified.error().reason == "invalid_capability_grant",
                  "a grant wider than the request is refused");
        }
    }
    {
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        auto early = client.verify({known_bridge_capabilities, {}});
        check(!early && early.error().reason == "handshake_state", "verify before attest is refused");
    }
    {
        FakeRandom random;
        random.seed = 90;
        BridgeHandshakeClient client{shared, binding(), known_bridge_capabilities};
        const auto server_hello = offer();
        check(client.attest(server_hello, random).has_value(), "bridge attests");
        auto again = client.attest(server_hello, random);
        check(!again && again.error().reason == "handshake_state", "a second attestation is refused");
    }

    // Divergent bindings are caught by the server, after the proof.
    {
        auto divergent = binding();
        divergent.bridge_epoch = "synthetic-epoch-2";
        FakeRandom server_random;
        FakeRandom bridge_random;
        bridge_random.seed = 90;
        BridgeHandshakeServer server{shared, binding(), known_bridge_capabilities};
        BridgeHandshakeClient client{shared, std::move(divergent), known_bridge_capabilities};
        auto server_hello = server.hello(server_random);
        check(server_hello.has_value(), "server offers");
        if (server_hello) {
            auto attest = client.attest(*server_hello, bridge_random);
            check(attest.has_value(), "bridge attests with its own epoch");
            if (attest) {
                auto accept = server.accept(*attest);
                check(!accept && accept.error().reason == "identity_mismatch",
                      "a bridge from another epoch is refused");
            }
        }
    }

    // Different secrets: neither side accepts the other.
    {
        const FakeAuthenticator server_secret{21};
        const FakeAuthenticator bridge_secret{22};
        FakeRandom server_random;
        FakeRandom bridge_random;
        bridge_random.seed = 90;
        BridgeHandshakeServer server{server_secret, binding(), known_bridge_capabilities};
        BridgeHandshakeClient client{bridge_secret, binding(), known_bridge_capabilities};
        auto server_hello = server.hello(server_random);
        check(server_hello.has_value(), "server offers");
        if (server_hello) {
            auto attest = client.attest(*server_hello, bridge_random);
            check(attest.has_value(), "bridge attests");
            if (attest) {
                auto accept = server.accept(*attest);
                check(!accept && accept.error().reason == "invalid_tag",
                      "a bridge with another secret is refused");
            }
        }
    }
}

}  // namespace

int main() {
    test_secret();
    test_frame_format();
    test_frame_round_trip();
    test_frame_rejections();
    test_wire_handshake();
    test_mutual_handshake();
    test_client_rejections();
    test_constant_time_equal();
    test_transcript();
    test_handshake_success();
    test_handshake_rejections();
    test_binding_and_state();
    test_system_crypto();
    if (failures != 0) std::cerr << failures << " Santa Monica bridge test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
