#pragma once

// Byte primitives shared by the Santa Monica codecs (ADR-0023, ADR-0024).
// Internal to argos_infrastructure: not part of the public include tree, not
// a protocol by itself, and free of domain, OS and transport concepts.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace argos::infrastructure::wire {

// Every integer is written byte by byte in little-endian order, so no struct
// layout, padding, endianness or ABI of this compiler reaches the wire.
class Writer {
public:
    void u8(const std::uint8_t value) { bytes_.push_back(static_cast<std::byte>(value)); }
    void u16(const std::uint16_t value) { integer(value, 2); }
    void u32(const std::uint32_t value) { integer(value, 4); }
    void u64(const std::uint64_t value) { integer(value, 8); }
    void boolean(const bool value) { u8(value ? std::uint8_t{1} : std::uint8_t{0}); }
    void raw(const std::span<const std::byte> value) {
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    [[nodiscard]] bool string(const std::string& value, const std::size_t limit) {
        const std::string_view view{value};
        const auto legible = !view.empty() && view.size() <= limit &&
            std::ranges::all_of(view, [](const char c) { return c >= ' ' && c <= '~'; });
        if (!legible) return false;
        u32(static_cast<std::uint32_t>(view.size()));
        for (const char c : view) {
            bytes_.push_back(static_cast<std::byte>(static_cast<unsigned char>(c)));
        }
        return true;
    }
    [[nodiscard]] std::size_t size() const noexcept { return bytes_.size(); }
    [[nodiscard]] std::vector<std::byte> take() noexcept { return std::move(bytes_); }

private:
    void integer(const std::uint64_t value, const std::size_t width) {
        for (std::size_t index = 0; index < width; ++index) {
            bytes_.push_back(
                static_cast<std::byte>(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU)));
        }
    }
    std::vector<std::byte> bytes_;
};

// Bounds-checked cursor. Every length is validated against the remaining bytes
// and the caller's ceiling before any destination is sized.
class Cursor {
public:
    explicit Cursor(const std::span<const std::byte> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool u8(std::uint8_t& out) {
        std::uint64_t value{};
        if (!integer(1, value)) return false;
        out = static_cast<std::uint8_t>(value);
        return true;
    }
    [[nodiscard]] bool u16(std::uint16_t& out) {
        std::uint64_t value{};
        if (!integer(2, value)) return false;
        out = static_cast<std::uint16_t>(value);
        return true;
    }
    [[nodiscard]] bool u32(std::uint32_t& out) {
        std::uint64_t value{};
        if (!integer(4, value)) return false;
        out = static_cast<std::uint32_t>(value);
        return true;
    }
    [[nodiscard]] bool u64(std::uint64_t& out) { return integer(8, out); }
    [[nodiscard]] bool boolean(bool& out) {
        std::uint8_t value{};
        if (!u8(value)) return false;
        if (value > 1) return reject("invalid_bool");
        out = value == 1;
        return true;
    }
    [[nodiscard]] bool bytes(const std::span<std::byte> destination) {
        if (destination.size() > remaining()) return reject("truncated_payload");
        std::ranges::copy(bytes_.subspan(offset_, destination.size()), destination.begin());
        offset_ += destination.size();
        return true;
    }
    [[nodiscard]] bool string(std::string& out, const std::size_t limit) {
        std::uint32_t length{};
        if (!u32(length)) return false;
        if (length == 0 || length > limit) return reject("invalid_string_length");
        if (length > remaining()) return reject("truncated_payload");
        const auto view = bytes_.subspan(offset_, length);
        const auto legible = std::ranges::all_of(view, [](const std::byte value) {
            const auto code = static_cast<unsigned char>(value);
            return code >= 0x20U && code <= 0x7EU;
        });
        if (!legible) return reject("invalid_string_byte");
        out.resize(length);
        std::ranges::transform(view, out.begin(),
                               [](const std::byte value) { return static_cast<char>(value); });
        offset_ += length;
        return true;
    }
    [[nodiscard]] bool exhausted() {
        return offset_ == bytes_.size() ? true : reject("trailing_payload_bytes");
    }
    // Keeps the first cause observed, so a later check cannot relabel it.
    [[nodiscard]] bool reject(const char* reason) {
        if (reason_ == nullptr) reason_ = reason;
        return false;
    }
    [[nodiscard]] const char* reason() const noexcept {
        return reason_ != nullptr ? reason_ : "malformed_payload";
    }

private:
    [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - offset_; }
    [[nodiscard]] bool integer(const std::size_t width, std::uint64_t& out) {
        if (width > remaining()) return reject("truncated_payload");
        std::uint64_t value{};
        for (std::size_t index = 0; index < width; ++index) {
            value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes_[offset_ + index]))
                << (8U * index);
        }
        offset_ += width;
        out = value;
        return true;
    }

    std::span<const std::byte> bytes_;
    std::size_t offset_{};
    const char* reason_{nullptr};
};

}  // namespace argos::infrastructure::wire
