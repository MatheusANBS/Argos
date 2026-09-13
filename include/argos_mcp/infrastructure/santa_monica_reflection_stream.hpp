#pragma once

#include "argos_mcp/domain/santa_monica_runtime.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <variant>
#include <vector>

namespace argos::infrastructure::santamonica {

namespace reflection = domain::santamonica;

inline constexpr std::size_t reflection_header_bytes = 32;
inline constexpr std::size_t max_reflection_frame_bytes = 1024U * 1024U;

struct SnapshotBegin { reflection::ReadBoundary boundary; };
struct SnapshotEnd { reflection::ReadBoundary boundary; };
using ReflectionMessage = std::variant<SnapshotBegin, reflection::ReflectionRecord, SnapshotEnd>;

// Portable, versioned wire encoding, never native struct/ABI serialization.
[[nodiscard]] domain::Result<std::vector<std::byte>> encode_reflection_frame(
    const ReflectionMessage& message, std::uint64_t request_id, std::uint64_t sequence);

class ReflectionByteStream {
public:
    using Clock = std::chrono::steady_clock;
    virtual ~ReflectionByteStream() = default;
    // Implementations own their I/O resources and close/cancel on destruction.
    // Short reads are allowed; zero means EOF. Must honor deadline/stop while
    // blocked. Authentication belongs to the native factory, NOT to this codec.
    [[nodiscard]] virtual domain::Result<std::size_t> read(
        std::span<std::byte> destination, Clock::time_point deadline,
        std::stop_token cancellation) = 0;
};

struct ReflectionStreamLimits {
    std::size_t max_wire_bytes{64U * 1024U * 1024U};
    std::chrono::milliseconds max_duration{5000};
};

// One discovery, one uniquely owned stream. A failure poisons the reader;
// completion closes the stream. No native transport is installed by this type.
class ReflectionStreamReader final : public reflection::SantaMonicaRuntimeReader {
public:
    using Clock = ReflectionByteStream::Clock;
    using ClockFn = std::function<Clock::time_point()>;

    ReflectionStreamReader(std::unique_ptr<ReflectionByteStream> stream,
                           std::uint64_t request_id,
                           ReflectionStreamLimits limits = {},
                           ClockFn clock = [] { return Clock::now(); });
    ReflectionStreamReader(const ReflectionStreamReader&) = delete;
    ReflectionStreamReader& operator=(const ReflectionStreamReader&) = delete;

    [[nodiscard]] domain::Result<reflection::ReadBoundary> begin(
        const reflection::ReflectionLimits& limits, std::stop_token cancellation) override;
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next(
        std::stop_token cancellation) override;
    [[nodiscard]] domain::Result<reflection::ReadBoundary> finish(std::stop_token cancellation) override;

private:
    enum class State { idle, reading, ended, finished, failed };
    [[nodiscard]] domain::Result<ReflectionMessage> receive(std::stop_token cancellation);
    [[nodiscard]] domain::Result<void> read_exact(std::span<std::byte> bytes, std::stop_token cancellation);
    [[nodiscard]] domain::DebugError poison(domain::DebugErrorCode code, const char* reason);

    std::unique_ptr<ReflectionByteStream> stream_;
    std::uint64_t request_id_;
    std::uint64_t next_sequence_{1};
    ReflectionStreamLimits limits_;
    reflection::ReflectionLimits reflection_limits_;
    ClockFn clock_;
    Clock::time_point deadline_{};
    State state_{State::idle};
    std::size_t wire_bytes_{};
    std::size_t record_count_{};
    // Reused decode buffer, bounded by one frame; never holds two frames.
    std::vector<std::byte> payload_;
    std::optional<reflection::ReadBoundary> end_;
};

}  // namespace argos::infrastructure::santamonica
