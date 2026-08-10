#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace argos::infrastructure {

// Bounded FIFO byte buffer for captured child-process output. Not
// thread-safe by itself: callers that append from a reader thread and read
// from a request thread must provide their own external synchronization
// (see WindowsLaunchedProcessSession, which guards one instance per stream
// with its own mutex).
class OutputRingBuffer final {
public:
    explicit OutputRingBuffer(std::size_t capacity_bytes) noexcept : capacity_(capacity_bytes) {}

    void append(std::string_view text);

    struct ReadResult {
        std::string text;
        std::uint64_t next_position{};
    };

    // Returns up to max_bytes starting at since_position. If since_position
    // refers to data already evicted by the capacity bound, it is clamped
    // forward to the oldest data still retained.
    [[nodiscard]] ReadResult read(std::uint64_t since_position, std::size_t max_bytes) const;

    [[nodiscard]] std::uint64_t produced() const noexcept { return produced_; }
    [[nodiscard]] std::size_t retained() const noexcept { return size_; }

private:
    std::size_t capacity_{};
    // Fixed-size circular storage after the first append. `head_` points to
    // the oldest retained byte and `size_` is the initialized byte count.
    // This avoids string::erase(0, n), which shifted the entire capture buffer
    // on every append once the capacity had been reached.
    std::string storage_;
    std::size_t head_{};
    std::size_t size_{};
    std::uint64_t produced_{};
};

}  // namespace argos::infrastructure
