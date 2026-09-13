#include "argos_mcp/infrastructure/santa_monica_bridge_channel.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_crypto.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_peer.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

using Clock = infra::LocalBridgeChannel::Clock;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

std::vector<std::byte> secret_material(const unsigned char value) {
    return std::vector<std::byte>(32, static_cast<std::byte>(value));
}

infra::PeerSnapshot synthetic_snapshot(const std::uint64_t generation = 1) {
    infra::PeerSnapshot snapshot;
    snapshot.boundary = {{infra::controlled_peer_profile(), "synthetic-process-1",
                          "synthetic-epoch-1", generation},
                         Consistency::validated_best_effort, true};
    snapshot.records = {
        TypeRecord{{1}, "Base", 8, std::nullopt},
        TypeRecord{{2}, "Player", 16, TypeKey{1}},
        FieldRecord{{2}, "Health", 8, 8, FieldKind::scalar, std::nullopt, std::nullopt},
        EnumRecord{{3}, "Flags"},
        EnumValueRecord{{3}, "Maximum", "18446744073709551615"},
        SliFunctionRecord{{4}, "Describe", "string()"},
    };
    return snapshot;
}

HandshakeBinding session_binding(const std::uint64_t request_id = 4242) {
    return infra::controlled_peer_binding("synthetic-process-1", "synthetic-epoch-1", request_id);
}

#if defined(_WIN32)

argos::domain::ProcessId current_pid() {
    return static_cast<argos::domain::ProcessId>(GetCurrentProcessId());
}

void test_channel_lifecycle() {
    auto random = infra::create_system_random();
    check(random.has_value(), "system CSPRNG builds");
    if (!random) return;

    auto channel = infra::LocalBridgeChannel::listen(**random);
    check(channel.has_value(), "channel listens");
    if (!channel) return;
    check((*channel)->endpoint().starts_with("\\\\.\\pipe\\argos-santamonica-"),
          "endpoint lives in the private namespace");

    auto second = infra::LocalBridgeChannel::listen(**random);
    check(second.has_value(), "a second channel gets its own endpoint");
    if (second) {
        check((*second)->endpoint() != (*channel)->endpoint(), "endpoints are not reused");
    }

    // No peer: the wait ends at the deadline instead of hanging.
    const auto started = Clock::now();
    auto accepted = (*channel)->accept(0, started + std::chrono::milliseconds{150}, {});
    check(!accepted && accepted.error().reason == "channel_connect_timeout",
          "accept without a peer ends at the deadline");
    check(Clock::now() - started < std::chrono::seconds{3}, "the deadline is honored promptly");

    auto missing = infra::LocalBridgeChannel::connect("\\\\.\\pipe\\argos-santamonica-absent");
    check(!missing && missing.error().code == DebugErrorCode::not_found,
          "connecting to an absent endpoint fails");

    check(!infra::LocalBridgeChannel::connect(""), "an empty endpoint is refused");
    check(!infra::LocalBridgeChannel::listen(**random, {.connect_timeout = std::chrono::milliseconds::zero()}),
          "invalid channel limits are refused");
}

void test_peer_identity() {
    auto random = infra::create_system_random();
    check(random.has_value(), "system CSPRNG builds");
    if (!random) return;
    {
        auto channel = infra::LocalBridgeChannel::listen(**random);
        check(channel.has_value(), "channel listens");
        if (!channel) return;
        const std::string endpoint = (*channel)->endpoint();
        std::jthread peer{[endpoint] {
            auto client = infra::LocalBridgeChannel::connect(endpoint);
            if (client) std::this_thread::sleep_for(std::chrono::milliseconds{200});
        }};
        auto accepted = (*channel)->accept(current_pid(), Clock::now() + std::chrono::seconds{3}, {});
        check(accepted.has_value(), "a local peer from the expected process is accepted");
    }
    {
        auto channel = infra::LocalBridgeChannel::listen(**random);
        check(channel.has_value(), "channel listens");
        if (!channel) return;
        const std::string endpoint = (*channel)->endpoint();
        std::jthread peer{[endpoint] {
            auto client = infra::LocalBridgeChannel::connect(endpoint);
            if (client) std::this_thread::sleep_for(std::chrono::milliseconds{200});
        }};
        auto accepted = (*channel)->accept(current_pid() + 1, Clock::now() + std::chrono::seconds{3}, {});
        check(!accepted && accepted.error().reason == "unexpected_peer_process",
              "a peer from another process is refused");
        check(!accepted && accepted.error().code == DebugErrorCode::unauthorized,
              "an unexpected peer is unauthorized");
    }
}

void test_read_deadline_and_cancellation() {
    auto random = infra::create_system_random();
    if (!random) return;
    {
        auto channel = infra::LocalBridgeChannel::listen(**random);
        if (!channel) return;
        const std::string endpoint = (*channel)->endpoint();
        std::jthread peer{[endpoint] {
            auto client = infra::LocalBridgeChannel::connect(endpoint);
            if (client) std::this_thread::sleep_for(std::chrono::milliseconds{500});
        }};
        check((*channel)->accept(0, Clock::now() + std::chrono::seconds{3}, {}).has_value(),
              "peer accepted");
        std::array<std::byte, 16> buffer{};
        auto read = (*channel)->read(buffer, Clock::now() + std::chrono::milliseconds{100}, {});
        check(!read && read.error().reason == "channel_read_timeout",
              "a silent peer does not block the server past the deadline");
    }
    {
        auto channel = infra::LocalBridgeChannel::listen(**random);
        if (!channel) return;
        const std::string endpoint = (*channel)->endpoint();
        std::jthread peer{[endpoint] {
            auto client = infra::LocalBridgeChannel::connect(endpoint);
            if (client) std::this_thread::sleep_for(std::chrono::milliseconds{500});
        }};
        check((*channel)->accept(0, Clock::now() + std::chrono::seconds{3}, {}).has_value(),
              "peer accepted");
        std::stop_source source;
        std::jthread canceller{[&source] {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            source.request_stop();
        }};
        std::array<std::byte, 16> buffer{};
        auto read = (*channel)->read(buffer, Clock::now() + std::chrono::seconds{5}, source.get_token());
        check(!read && read.error().code == DebugErrorCode::cancelled,
              "a pending read observes cancellation");
    }
}

void test_session_end_to_end() {
    auto random = infra::create_system_random();
    check(random.has_value(), "system CSPRNG builds");
    if (!random) return;
    auto channel = infra::LocalBridgeChannel::listen(**random);
    check(channel.has_value(), "channel listens");
    if (!channel) return;
    const std::string endpoint = (*channel)->endpoint();

    Result<void> peer_result{};
    std::jthread peer{[endpoint, &peer_result] {
        auto client = infra::LocalBridgeChannel::connect(endpoint);
        if (!client) {
            peer_result = std::unexpected(client.error());
            return;
        }
        auto secret = BridgeSecret::create(secret_material(0x5a));
        if (!secret) {
            peer_result = std::unexpected(secret.error());
            return;
        }
        peer_result = infra::serve_bridge_peer(**client, std::move(*secret), session_binding(),
                                               synthetic_snapshot(),
                                               Clock::now() + std::chrono::seconds{10}, {});
    }};

    check((*channel)->accept(current_pid(), Clock::now() + std::chrono::seconds{5}, {}).has_value(),
          "peer accepted");
    auto secret = BridgeSecret::create(secret_material(0x5a));
    check(secret.has_value(), "server secret builds");
    if (!secret) return;
    auto catalog = infra::read_bridge_snapshot(**channel, std::move(*secret), session_binding(),
                                               infra::controlled_peer_profile(), {},
                                               Clock::now() + std::chrono::seconds{10}, {});
    check(catalog.has_value(), "a full session publishes a catalog over the real channel");
    if (catalog) {
        check((*catalog)->records().size() == 6, "every streamed record is admitted");
        check((*catalog)->identity().process_instance == "synthetic-process-1",
              "the snapshot identity survives the channel");
        check((*catalog)->identity().profile == infra::controlled_peer_profile(),
              "the profile matches what the server expected");
        check((*catalog)->coverage_complete(), "declared coverage survives the channel");
    }
    peer.join();
    check(peer_result.has_value(), "the peer side completes without error");
}

void test_session_rejects_wrong_secret() {
    auto random = infra::create_system_random();
    if (!random) return;
    auto channel = infra::LocalBridgeChannel::listen(**random);
    check(channel.has_value(), "channel listens");
    if (!channel) return;
    const std::string endpoint = (*channel)->endpoint();

    Result<void> peer_result{};
    std::jthread peer{[endpoint, &peer_result] {
        auto client = infra::LocalBridgeChannel::connect(endpoint);
        if (!client) {
            peer_result = std::unexpected(client.error());
            return;
        }
        auto secret = BridgeSecret::create(secret_material(0x11));
        if (!secret) return;
        peer_result = infra::serve_bridge_peer(**client, std::move(*secret), session_binding(),
                                               synthetic_snapshot(),
                                               Clock::now() + std::chrono::seconds{10}, {});
    }};

    check((*channel)->accept(current_pid(), Clock::now() + std::chrono::seconds{5}, {}).has_value(),
          "peer accepted");
    auto secret = BridgeSecret::create(secret_material(0x5a));
    if (!secret) return;
    auto catalog = infra::read_bridge_snapshot(**channel, std::move(*secret), session_binding(),
                                               infra::controlled_peer_profile(), {},
                                               Clock::now() + std::chrono::seconds{10}, {});
    check(!catalog && catalog.error().reason == "invalid_tag",
          "a peer without the session secret publishes nothing");
    peer.join();
    check(!peer_result && peer_result.error().reason == "handshake_rejected",
          "the peer learns only that it was rejected");
}

void test_session_rejects_divergent_identity() {
    auto random = infra::create_system_random();
    if (!random) return;
    auto channel = infra::LocalBridgeChannel::listen(**random);
    check(channel.has_value(), "channel listens");
    if (!channel) return;
    const std::string endpoint = (*channel)->endpoint();

    std::jthread peer{[endpoint] {
        auto client = infra::LocalBridgeChannel::connect(endpoint);
        if (!client) return;
        auto secret = BridgeSecret::create(secret_material(0x5a));
        if (!secret) return;
        auto divergent = infra::controlled_peer_binding("synthetic-process-1", "synthetic-epoch-2", 4242);
        auto snapshot = synthetic_snapshot();
        snapshot.boundary.identity.bridge_epoch = "synthetic-epoch-2";
        const auto served = infra::serve_bridge_peer(**client, std::move(*secret), std::move(divergent),
                                                     snapshot, Clock::now() + std::chrono::seconds{10}, {});
        static_cast<void>(served);
    }};

    check((*channel)->accept(current_pid(), Clock::now() + std::chrono::seconds{5}, {}).has_value(),
          "peer accepted");
    auto secret = BridgeSecret::create(secret_material(0x5a));
    if (!secret) return;
    auto catalog = infra::read_bridge_snapshot(**channel, std::move(*secret), session_binding(),
                                               infra::controlled_peer_profile(), {},
                                               Clock::now() + std::chrono::seconds{10}, {});
    check(!catalog && catalog.error().reason == "identity_mismatch",
          "a peer from another epoch publishes nothing");
    peer.join();
}

#else

void test_channel_lifecycle() {
    auto random = infra::create_system_random();
    check(!random && random.error().code == DebugErrorCode::unsupported,
          "without a provider there is no channel");
}
void test_peer_identity() {}
void test_read_deadline_and_cancellation() {}
void test_session_end_to_end() {}
void test_session_rejects_wrong_secret() {}
void test_session_rejects_divergent_identity() {}

#endif

}  // namespace

int main() {
    test_channel_lifecycle();
    test_peer_identity();
    test_read_deadline_and_cancellation();
    test_session_end_to_end();
    test_session_rejects_wrong_secret();
    test_session_rejects_divergent_identity();
    if (failures != 0) std::cerr << failures << " Santa Monica channel test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
