#include "argos_mcp/infrastructure/output_ring_buffer.hpp"

#include <algorithm>

namespace argos::infrastructure {

void OutputRingBuffer::append(const std::string_view text) {
    if (text.empty() || capacity_ == 0U) {
        return;
    }
    buffer_.append(text);
    produced_ += text.size();
    if (buffer_.size() > capacity_) {
        buffer_.erase(0, buffer_.size() - capacity_);
    }
}

OutputRingBuffer::ReadResult OutputRingBuffer::read(
    const std::uint64_t since_position,
    const std::size_t max_bytes
) const {
    const std::uint64_t dropped = produced_ - buffer_.size();
    const std::uint64_t start = std::max(since_position, dropped);
    if (start >= produced_ || max_bytes == 0U) {
        return ReadResult{{}, start};
    }
    const auto offset_in_buffer = static_cast<std::size_t>(start - dropped);
    const auto available = buffer_.size() - offset_in_buffer;
    const auto take = std::min(available, max_bytes);
    return ReadResult{buffer_.substr(offset_in_buffer, take), start + take};
}

}  // namespace argos::infrastructure
