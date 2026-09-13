// Controlled synthetic peer for the Santa Monica channel (ADR-0025).
//
// It speaks the real protocol -- handshake, capability negotiation and the
// snapshot stream -- over the real local channel, and streams metadata that is
// entirely made up. It never reads, launches, injects into or inspects a game,
// and it is not a bridge for any retail build. Its only purpose is to prove
// the channel end to end without a target.
//
// The server launches it, so it takes its non-secret identity on the command
// line and reads exactly 32 secret bytes from stdin before anything else.

#include "argos_mcp/domain/santa_monica_bridge.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_channel.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_peer.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#endif

namespace {

namespace infra = argos::infrastructure::santamonica;
namespace reflection = argos::domain::santamonica;

struct Options {
    std::string endpoint;
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t request_id{};
};

[[nodiscard]] bool parse(const int argc, char** argv, Options& options) {
    for (int index = 1; index + 1 < argc; index += 2) {
        const std::string_view key{argv[index]};
        const std::string_view value{argv[index + 1]};
        if (key == "--endpoint") {
            options.endpoint = value;
        } else if (key == "--process") {
            options.process_instance = value;
        } else if (key == "--epoch") {
            options.bridge_epoch = value;
        } else if (key == "--request") {
            const auto* first = value.data();
            const auto* last = first + value.size();
            const auto outcome = std::from_chars(first, last, options.request_id);
            if (outcome.ec != std::errc{} || outcome.ptr != last) return false;
        } else {
            return false;
        }
    }
    return !options.endpoint.empty() && options.request_id != 0 &&
           reflection::valid_identity_token(options.process_instance) &&
           reflection::valid_identity_token(options.bridge_epoch);
}

// The bootstrap channel is stdin, so the secret never appears in argv, in the
// environment or on disk.
[[nodiscard]] bool read_secret(const std::span<std::byte> destination) {
#if defined(_WIN32)
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input == nullptr || input == INVALID_HANDLE_VALUE) return false;
    std::size_t filled = 0;
    while (filled < destination.size()) {
        DWORD read = 0;
        if (!ReadFile(input, destination.data() + filled,
                      static_cast<DWORD>(destination.size() - filled), &read, nullptr)) {
            return false;
        }
        if (read == 0) return false;
        filled += read;
    }
    return true;
#else
    static_cast<void>(destination);
    return false;
#endif
}

// Synthetic metadata: a small, self-consistent graph that the domain catalog
// accepts. No layout here comes from any game.
[[nodiscard]] infra::PeerSnapshot synthetic_snapshot(const Options& options) {
    infra::PeerSnapshot snapshot;
    snapshot.boundary = {{infra::controlled_peer_profile(), options.process_instance,
                          options.bridge_epoch, 1},
                         reflection::Consistency::validated_best_effort, true};
    snapshot.records = {
        reflection::TypeRecord{{1}, "SyntheticBase", 16, std::nullopt},
        reflection::TypeRecord{{2}, "SyntheticActor", 64, reflection::TypeKey{1}},
        reflection::TypeRecord{{3}, "SyntheticInventory", 32, std::nullopt},
        reflection::FieldRecord{{1}, "Id", 0, 8, reflection::FieldKind::scalar, std::nullopt,
                                std::nullopt},
        reflection::FieldRecord{{2}, "Health", 16, 4, reflection::FieldKind::scalar, std::nullopt,
                                std::nullopt},
        reflection::FieldRecord{{2}, "State", 20, 4, reflection::FieldKind::enumeration, std::nullopt,
                                reflection::EnumKey{10}},
        reflection::FieldRecord{{2}, "Inventory", 24, 8, reflection::FieldKind::pointer,
                                reflection::TypeKey{3}, std::nullopt},
        reflection::FieldRecord{{3}, "Slots", 0, 8, reflection::FieldKind::array,
                                reflection::TypeKey{1}, std::nullopt},
        reflection::EnumRecord{{10}, "SyntheticState"},
        reflection::EnumValueRecord{{10}, "Idle", "0"},
        reflection::EnumValueRecord{{10}, "Active", "1"},
        reflection::EnumValueRecord{{10}, "Maximum", "18446744073709551615"},
        reflection::SliFunctionRecord{{20}, "DescribeActor", "string(SyntheticActor)"},
        reflection::SliFunctionRecord{{21}, "CountSlots", "u32(SyntheticInventory)"},
    };
    return snapshot;
}

}  // namespace

int main(int argc, char** argv) {
    Options options;
    if (!parse(argc, argv, options)) {
        std::cerr << "usage: argos_santa_monica_peer --endpoint <name> --process <token>"
                     " --epoch <token> --request <id>\n";
        return 2;
    }

    std::array<std::byte, 32> secret_bytes{};
    if (!read_secret(secret_bytes)) {
        reflection::secure_zero(secret_bytes);
        std::cerr << "controlled peer: bootstrap secret unavailable\n";
        return 3;
    }
    auto secret = reflection::BridgeSecret::create(secret_bytes);
    reflection::secure_zero(secret_bytes);
    if (!secret) {
        std::cerr << "controlled peer: invalid bootstrap secret\n";
        return 3;
    }

    auto channel = infra::LocalBridgeChannel::connect(options.endpoint);
    if (!channel) {
        std::cerr << "controlled peer: channel unavailable\n";
        return 4;
    }
    const auto binding = infra::controlled_peer_binding(options.process_instance,
                                                        options.bridge_epoch, options.request_id);
    const auto served = infra::serve_bridge_peer(
        **channel, std::move(*secret), binding, synthetic_snapshot(options),
        infra::LocalBridgeChannel::Clock::now() + std::chrono::seconds{30}, {});
    if (!served) {
        std::cerr << "controlled peer: session failed (" << served.error().reason << ")\n";
        return 5;
    }
    return 0;
}
