#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain {

using Address = std::uint64_t;
using ProcessId = std::uint32_t;

class SessionId final {
public:
    static std::expected<SessionId, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const SessionId&) const = default;

private:
    explicit SessionId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

class ScanSessionId final {
public:
    static std::expected<ScanSessionId, std::string> create(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] bool operator==(const ScanSessionId&) const = default;

private:
    explicit ScanSessionId(std::string value) : value_(std::move(value)) {}
    std::string value_;
};

enum class AccessMode {
    read_only,
    read_write,
};

enum class ScanValueType {
    u8, u16, u32, u64,
    i8, i16, i32, i64,
    f32, f64,
};

enum class ScanComparison {
    exact,
    unknown,
    in_range,
    changed,
    unchanged,
    increased,
    decreased,
    increased_by,
    decreased_by,
};

enum class DebugErrorCode {
    invalid_argument,
    unauthorized,
    not_found,
    access_denied,
    unsupported,
    io_error,
    limit_exceeded,
    invalid_state,
    cancelled,
    parse_error,
};

struct DebugError {
    DebugErrorCode code{};
    std::string safe_message;
};

template <typename T>
using Result = std::expected<T, DebugError>;

struct ProcessInfo {
    ProcessId pid{};
    std::string name;
    std::optional<std::string> executable;
    bool same_user{false};
};

struct MemoryRegion {
    Address start{};
    Address end{};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool private_mapping{false};
    std::string name;

    [[nodiscard]] std::uint64_t size() const noexcept { return end >= start ? end - start : 0U; }
};

struct ModuleInfo {
    std::string name;
    std::string path;
    Address base{};
    std::uint64_t size{};
};

struct ScanMatch {
    Address address{};
};

struct SessionInfo {
    SessionId id;
    ProcessId pid{};
    std::string process_name;
    AccessMode access{AccessMode::read_only};
};

struct ScanSessionInfo {
    ScanSessionId id;
    SessionId owner;
    ScanValueType value_type{};
    std::size_t candidate_count{};
    std::uint32_t generation{};
};

[[nodiscard]] std::string_view to_string(AccessMode mode) noexcept;
[[nodiscard]] std::string_view to_string(DebugErrorCode code) noexcept;
[[nodiscard]] std::string_view to_string(ScanValueType type) noexcept;
[[nodiscard]] std::size_t scan_value_size(ScanValueType type) noexcept;
[[nodiscard]] std::optional<ScanValueType> scan_value_type_from_string(std::string_view text) noexcept;
[[nodiscard]] std::optional<ScanComparison> scan_comparison_from_string(std::string_view text) noexcept;

}  // namespace argos::domain
