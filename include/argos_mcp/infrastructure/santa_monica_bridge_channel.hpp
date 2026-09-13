#pragma once

#include "argos_mcp/domain/santa_monica_bridge.hpp"
#include "argos_mcp/domain/types.hpp"
#include "argos_mcp/infrastructure/santa_monica_handshake_stream.hpp"
#include "argos_mcp/infrastructure/santa_monica_reflection_stream.hpp"

#include <chrono>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>

namespace argos::infrastructure::santamonica {

struct ChannelLimits {
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds io_timeout{5000};
};

// One local connection for one discovery (ADR-0025). The endpoint is created
// before any peer exists, carries a DACL restricted to the current user and
// rejects remote clients in the kernel. Destruction cancels pending I/O and
// closes the pipe; there is no second instance for the same endpoint.
class LocalBridgeChannel final {
public:
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] static domain::Result<std::unique_ptr<LocalBridgeChannel>> listen(
        domain::santamonica::RandomSource& random, ChannelLimits limits = {});
    [[nodiscard]] static domain::Result<std::unique_ptr<LocalBridgeChannel>> connect(
        std::string_view endpoint, ChannelLimits limits = {});

    LocalBridgeChannel(const LocalBridgeChannel&) = delete;
    LocalBridgeChannel& operator=(const LocalBridgeChannel&) = delete;
    ~LocalBridgeChannel();

    // Endpoint name. Not a secret: the DACL is what protects the channel.
    [[nodiscard]] const std::string& endpoint() const noexcept { return endpoint_; }

    // Waits for the peer and binds the connection to the expected process.
    // A zero pid accepts any local process owned by the same user.
    [[nodiscard]] domain::Result<void> accept(
        domain::ProcessId expected_pid, Clock::time_point deadline, std::stop_token cancellation);

    [[nodiscard]] domain::Result<std::size_t> read(
        std::span<std::byte> destination, Clock::time_point deadline, std::stop_token cancellation);
    [[nodiscard]] domain::Result<void> write(
        std::span<const std::byte> bytes, Clock::time_point deadline, std::stop_token cancellation);

    void close() noexcept;

    [[nodiscard]] const ChannelLimits& limits() const noexcept { return limits_; }

private:
    struct Native;
    LocalBridgeChannel(std::unique_ptr<Native> native, std::string endpoint, ChannelLimits limits);

    std::unique_ptr<Native> native_;
    std::string endpoint_;
    ChannelLimits limits_;
};

// Adapts the channel to the reflection snapshot port (ADR-0023). Unlike a
// self-contained stream, this one borrows a channel owned by the session that
// already completed the handshake; that owner closes it. It authenticates
// nothing on its own.
class ChannelReflectionStream final : public ReflectionByteStream {
public:
    explicit ChannelReflectionStream(LocalBridgeChannel& channel) noexcept : channel_(&channel) {}

    [[nodiscard]] domain::Result<std::size_t> read(
        std::span<std::byte> destination, Clock::time_point deadline,
        std::stop_token cancellation) override;

private:
    LocalBridgeChannel* channel_;
};

[[nodiscard]] domain::Result<void> send_handshake_frame(
    LocalBridgeChannel& channel, const HandshakeMessage& message, std::uint64_t request_id,
    std::uint64_t sequence, LocalBridgeChannel::Clock::time_point deadline,
    std::stop_token cancellation);

[[nodiscard]] domain::Result<HandshakeMessage> receive_handshake_frame(
    LocalBridgeChannel& channel, std::uint64_t request_id, std::uint64_t sequence,
    LocalBridgeChannel::Clock::time_point deadline, std::stop_token cancellation);

// Non-secret identity the controlled peer must bind to. It travels on the
// command line precisely because none of it is a secret; the session secret
// never does.
struct PeerLaunch {
    std::string_view endpoint;
    std::string_view process_instance;
    std::string_view bridge_epoch;
    std::uint64_t request_id{};
};

// Server-side launch of the operator-configured peer. The session secret is
// written to the child stdin and never appears in argv, environment or log.
// Destruction terminates the child if it is still running.
class BridgePeerProcess final {
public:
    [[nodiscard]] static domain::Result<std::unique_ptr<BridgePeerProcess>> spawn(
        std::string_view executable_path, const PeerLaunch& launch,
        std::span<const std::byte> secret);

    BridgePeerProcess(const BridgePeerProcess&) = delete;
    BridgePeerProcess& operator=(const BridgePeerProcess&) = delete;
    ~BridgePeerProcess();

    [[nodiscard]] domain::ProcessId pid() const noexcept { return pid_; }
    void terminate() noexcept;

private:
    struct Native;
    BridgePeerProcess(std::unique_ptr<Native> native, domain::ProcessId pid);

    std::unique_ptr<Native> native_;
    domain::ProcessId pid_{};
};

}  // namespace argos::infrastructure::santamonica
