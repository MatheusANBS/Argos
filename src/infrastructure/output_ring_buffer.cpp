#include "argos_mcp/infrastructure/output_ring_buffer.hpp"

#include <algorithm>
#include <utility>

namespace argos::infrastructure {

void OutputRingBuffer::append(const std::string_view text) {
    if (text.empty() || capacity_ == 0U) {
        return;
    }
    produced_ += text.size();

    if (storage_.size() != capacity_) {
        storage_.resize(capacity_);
    }

    // If the append alone is larger than the ring, only its tail can remain.
    if (text.size() >= capacity_) {
        const auto retained = text.substr(text.size() - capacity_);
        std::copy(retained.begin(), retained.end(), storage_.begin());
        head_ = 0U;
        size_ = capacity_;
        return;
    }

    const auto tail = (head_ + size_) % capacity_;
    const auto first = std::min(text.size(), capacity_ - tail);
    std::copy_n(text.begin(), first, storage_.begin() + static_cast<std::ptrdiff_t>(tail));
    const auto second = text.size() - first;
    if (second != 0U) {
        std::copy_n(
            text.begin() + static_cast<std::ptrdiff_t>(first), second, storage_.begin()
        );
    }

    const auto free = capacity_ - size_;
    if (text.size() <= free) {
        size_ += text.size();
        return;
    }
    const auto evicted = text.size() - free;
    head_ = (head_ + evicted) % capacity_;
    size_ = capacity_;
}

OutputRingBuffer::ReadResult OutputRingBuffer::read(
    const std::uint64_t since_position,
    const std::size_t max_bytes
) const {
    const std::uint64_t dropped = produced_ - size_;
    const std::uint64_t start = std::max(since_position, dropped);
    if (start >= produced_ || max_bytes == 0U) {
        return ReadResult{{}, start};
    }
    const auto offset_in_buffer = static_cast<std::size_t>(start - dropped);
    const auto available = size_ - offset_in_buffer;
    const auto take = std::min(available, max_bytes);
    const auto physical_start = (head_ + offset_in_buffer) % capacity_;
    const auto first = std::min(take, capacity_ - physical_start);
    std::string output;
    output.reserve(take);
    output.append(storage_, physical_start, first);
    if (first != take) {
        output.append(storage_, 0U, take - first);
    }
    return ReadResult{std::move(output), start + take};
}

}  // namespace argos::infrastructure
