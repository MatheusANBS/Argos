#include "argos_mcp/infrastructure/santa_monica_reflection_stream.hpp"

#include "detail/wire_bytes.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;

constexpr std::uint16_t wire_version = 1;
constexpr std::size_t max_payload_bytes = max_reflection_frame_bytes - reflection_header_bytes;
// Identities follow the domain identifier ceiling; metadata follows the
// negotiated reflection limit, itself capped by the domain catalog.
constexpr std::size_t max_identity_bytes = 128;
constexpr std::size_t max_metadata_bytes = 4096;
constexpr std::size_t max_record_budget = 100000;
constexpr std::size_t max_stream_bytes = 64U * 1024U * 1024U;
constexpr std::chrono::milliseconds max_stream_duration{5000};
constexpr std::uint32_t max_module_count = 64;
constexpr std::array<std::byte, 4> frame_magic{
    std::byte{'S'}, std::byte{'M'}, std::byte{'R'}, std::byte{'F'}};

enum class FrameKind : std::uint16_t { begin = 1, record = 2, end = 3 };

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica reflection stream failed", reason};
}

// Closed mappings. A value produced by a cast outside the enumeration yields
// nullopt instead of an unchecked byte on the wire.
[[nodiscard]] std::optional<std::uint8_t> encode_consistency(const reflection::Consistency value) {
    switch (value) {
        case reflection::Consistency::validated_best_effort: return std::uint8_t{0};
        case reflection::Consistency::stable: return std::uint8_t{1};
        case reflection::Consistency::unstable: return std::uint8_t{2};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<reflection::Consistency> decode_consistency(const std::uint8_t value) {
    switch (value) {
        case 0: return reflection::Consistency::validated_best_effort;
        case 1: return reflection::Consistency::stable;
        case 2: return reflection::Consistency::unstable;
        default: return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::uint8_t> encode_source(const reflection::SnapshotSource value) {
    switch (value) {
        case reflection::SnapshotSource::bridge: return std::uint8_t{0};
        case reflection::SnapshotSource::native_reader: return std::uint8_t{1};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<reflection::SnapshotSource> decode_source(const std::uint8_t value) {
    switch (value) {
        case 0: return reflection::SnapshotSource::bridge;
        case 1: return reflection::SnapshotSource::native_reader;
        default: return std::nullopt;
    }
}

[[nodiscard]] std::optional<std::uint8_t> encode_field_kind(const reflection::FieldKind value) {
    switch (value) {
        case reflection::FieldKind::scalar: return std::uint8_t{0};
        case reflection::FieldKind::object: return std::uint8_t{1};
        case reflection::FieldKind::pointer: return std::uint8_t{2};
        case reflection::FieldKind::array: return std::uint8_t{3};
        case reflection::FieldKind::map: return std::uint8_t{4};
        case reflection::FieldKind::enumeration: return std::uint8_t{5};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<reflection::FieldKind> decode_field_kind(const std::uint8_t value) {
    switch (value) {
        case 0: return reflection::FieldKind::scalar;
        case 1: return reflection::FieldKind::object;
        case 2: return reflection::FieldKind::pointer;
        case 3: return reflection::FieldKind::array;
        case 4: return reflection::FieldKind::map;
        case 5: return reflection::FieldKind::enumeration;
        default: return std::nullopt;
    }
}

using wire::Cursor;
using wire::Writer;

template <typename Key>
void write_optional_key(Writer& out, const std::optional<Key>& value) {
    out.boolean(value.has_value());
    if (value) out.u64(value->value);
}

template <typename Key>
[[nodiscard]] bool read_optional_key(Cursor& in, std::optional<Key>& out) {
    bool present{};
    if (!in.boolean(present)) return false;
    if (!present) {
        out.reset();
        return true;
    }
    std::uint64_t value{};
    if (!in.u64(value)) return false;
    out = Key{value};
    return true;
}

[[nodiscard]] bool write_boundary(Writer& out, const reflection::ReadBoundary& boundary) {
    const auto& profile = boundary.identity.profile;
    if (profile.modules.empty() || profile.modules.size() > max_module_count) return false;
    if (profile.architecture != reflection::Architecture::x64) return false;
    const auto consistency = encode_consistency(boundary.consistency);
    if (!consistency) return false;
    const auto source = encode_source(profile.source);
    if (!source) return false;
    out.u32(profile.schema_version);
    if (!out.string(profile.profile_id, max_identity_bytes)) return false;
    out.raw(profile.profile_digest.bytes);
    out.raw(profile.bridge_digest.bytes);
    out.u32(profile.bridge_version);
    out.u32(profile.protocol_version);
    out.u32(static_cast<std::uint32_t>(profile.modules.size()));
    for (const auto& module : profile.modules) {
        if (!out.string(module.name, max_identity_bytes)) return false;
        out.u64(module.image_size);
        out.raw(module.file_digest.bytes);
    }
    out.u8(1);
    out.u8(*source);
    if (!out.string(boundary.identity.process_instance, max_identity_bytes)) return false;
    if (!out.string(boundary.identity.bridge_epoch, max_identity_bytes)) return false;
    out.u64(boundary.identity.generation);
    out.u8(*consistency);
    out.boolean(boundary.coverage_complete);
    return true;
}

[[nodiscard]] bool write_record(Writer& out, const reflection::ReflectionRecord& record) {
    return std::visit([&out](const auto& value) -> bool {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, reflection::TypeRecord>) {
            out.u8(1);
            out.u64(value.id.value);
            if (!out.string(value.name, max_metadata_bytes)) return false;
            out.u64(value.size);
            write_optional_key(out, value.base);
        } else if constexpr (std::is_same_v<T, reflection::FieldRecord>) {
            const auto kind = encode_field_kind(value.kind);
            if (!kind) return false;
            out.u8(2);
            out.u64(value.owner.value);
            if (!out.string(value.name, max_metadata_bytes)) return false;
            out.u64(value.offset);
            out.u64(value.size);
            out.u8(*kind);
            write_optional_key(out, value.referenced_type);
            write_optional_key(out, value.referenced_enum);
        } else if constexpr (std::is_same_v<T, reflection::EnumRecord>) {
            out.u8(3);
            out.u64(value.id.value);
            if (!out.string(value.name, max_metadata_bytes)) return false;
        } else if constexpr (std::is_same_v<T, reflection::EnumValueRecord>) {
            out.u8(4);
            out.u64(value.owner.value);
            if (!out.string(value.name, max_metadata_bytes)) return false;
            if (!out.string(value.value, max_metadata_bytes)) return false;
        } else {
            static_assert(std::is_same_v<T, reflection::SliFunctionRecord>);
            out.u8(5);
            out.u64(value.id.value);
            if (!out.string(value.name, max_metadata_bytes)) return false;
            if (!out.string(value.signature, max_metadata_bytes)) return false;
        }
        return true;
    }, record);
}

[[nodiscard]] bool read_boundary(
    Cursor& in, reflection::ReadBoundary& out, const std::size_t identity_limit) {
    auto& profile = out.identity.profile;
    std::uint32_t modules{};
    if (!in.u32(profile.schema_version) || !in.string(profile.profile_id, identity_limit) ||
        !in.bytes(profile.profile_digest.bytes) || !in.bytes(profile.bridge_digest.bytes) ||
        !in.u32(profile.bridge_version) || !in.u32(profile.protocol_version) || !in.u32(modules)) {
        return false;
    }
    if (modules == 0 || modules > max_module_count) return in.reject("invalid_module_count");
    profile.modules.resize(modules);
    for (auto& module : profile.modules) {
        if (!in.string(module.name, identity_limit) || !in.u64(module.image_size) ||
            !in.bytes(module.file_digest.bytes)) {
            return false;
        }
    }
    std::uint8_t architecture{};
    if (!in.u8(architecture) || architecture != 1) return in.reject("invalid_architecture");
    profile.architecture = reflection::Architecture::x64;
    std::uint8_t source{};
    if (!in.u8(source)) return false;
    const auto decoded_source = decode_source(source);
    if (!decoded_source) return in.reject("invalid_snapshot_source");
    profile.source = *decoded_source;
    std::uint8_t consistency{};
    if (!in.string(out.identity.process_instance, identity_limit) ||
        !in.string(out.identity.bridge_epoch, identity_limit) || !in.u64(out.identity.generation) ||
        !in.u8(consistency)) {
        return false;
    }
    const auto decoded = decode_consistency(consistency);
    if (!decoded) return in.reject("invalid_consistency");
    out.consistency = *decoded;
    return in.boolean(out.coverage_complete);
}

[[nodiscard]] bool read_record(
    Cursor& in, reflection::ReflectionRecord& out, const std::size_t metadata_limit) {
    std::uint8_t tag{};
    if (!in.u8(tag)) return false;
    switch (tag) {
        case 1: {
            reflection::TypeRecord record;
            if (!in.u64(record.id.value) || !in.string(record.name, metadata_limit) ||
                !in.u64(record.size) || !read_optional_key(in, record.base)) {
                return false;
            }
            out = std::move(record);
            return true;
        }
        case 2: {
            reflection::FieldRecord record;
            std::uint8_t kind{};
            if (!in.u64(record.owner.value) || !in.string(record.name, metadata_limit) ||
                !in.u64(record.offset) || !in.u64(record.size) || !in.u8(kind)) {
                return false;
            }
            const auto decoded = decode_field_kind(kind);
            if (!decoded) return in.reject("invalid_field_kind");
            record.kind = *decoded;
            if (!read_optional_key(in, record.referenced_type) || !read_optional_key(in, record.referenced_enum)) {
                return false;
            }
            out = std::move(record);
            return true;
        }
        case 3: {
            reflection::EnumRecord record;
            if (!in.u64(record.id.value) || !in.string(record.name, metadata_limit)) return false;
            out = std::move(record);
            return true;
        }
        case 4: {
            reflection::EnumValueRecord record;
            if (!in.u64(record.owner.value) || !in.string(record.name, metadata_limit) ||
                !in.string(record.value, metadata_limit)) {
                return false;
            }
            out = std::move(record);
            return true;
        }
        case 5: {
            reflection::SliFunctionRecord record;
            if (!in.u64(record.id.value) || !in.string(record.name, metadata_limit) ||
                !in.string(record.signature, metadata_limit)) {
                return false;
            }
            out = std::move(record);
            return true;
        }
        default:
            return in.reject("invalid_record_tag");
    }
}

}  // namespace

Result<std::vector<std::byte>> encode_reflection_frame(
    const ReflectionMessage& message, const std::uint64_t request_id, const std::uint64_t sequence) {
    if (request_id == 0) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_request_id"));
    }
    if (sequence == 0) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_sequence"));
    }
    try {
        Writer payload;
        const auto kind = std::visit([&payload](const auto& value) -> std::optional<FrameKind> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, SnapshotBegin>) {
                return write_boundary(payload, value.boundary) ? std::optional{FrameKind::begin}
                                                               : std::nullopt;
            } else if constexpr (std::is_same_v<T, SnapshotEnd>) {
                return write_boundary(payload, value.boundary) ? std::optional{FrameKind::end}
                                                               : std::nullopt;
            } else {
                return write_record(payload, value) ? std::optional{FrameKind::record} : std::nullopt;
            }
        }, message);
        if (!kind) return std::unexpected(fail(DebugErrorCode::invalid_argument, "unencodable_message"));
        if (payload.size() > max_payload_bytes) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "frame_too_large"));
        }
        Writer frame;
        for (const auto byte : frame_magic) frame.u8(static_cast<std::uint8_t>(byte));
        frame.u16(wire_version);
        frame.u16(static_cast<std::uint16_t>(reflection_header_bytes));
        frame.u16(static_cast<std::uint16_t>(*kind));
        frame.u16(0);
        frame.u32(static_cast<std::uint32_t>(payload.size()));
        frame.u64(request_id);
        frame.u64(sequence);
        auto bytes = frame.take();
        const auto body = payload.take();
        bytes.insert(bytes.end(), body.begin(), body.end());
        return bytes;
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

ReflectionStreamReader::ReflectionStreamReader(
    std::unique_ptr<ReflectionByteStream> stream, const std::uint64_t request_id,
    ReflectionStreamLimits limits, ClockFn clock)
    : stream_(std::move(stream)), request_id_(request_id), limits_(limits), clock_(std::move(clock)) {}

domain::Result<reflection::ReadBoundary> ReflectionStreamReader::begin(
    const reflection::ReflectionLimits& limits, std::stop_token cancellation) {
    if (state_ != State::idle) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "stream_state"));
    }
    if (!stream_ || !clock_ || request_id_ == 0) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "invalid_stream_request"));
    }
    // Configuration may only lower the ceilings fixed by ADR-0023.
    if (limits_.max_wire_bytes == 0 || limits_.max_wire_bytes > max_stream_bytes ||
        limits_.max_duration <= std::chrono::milliseconds::zero() ||
        limits_.max_duration > max_stream_duration) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "invalid_stream_limits"));
    }
    if (limits.max_records == 0 || limits.max_records > max_record_budget ||
        limits.max_string_bytes == 0 || limits.max_string_bytes > max_metadata_bytes) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "invalid_reflection_limits"));
    }
    reflection_limits_ = limits;
    deadline_ = clock_() + limits_.max_duration;
    state_ = State::reading;
    auto message = receive(cancellation);
    if (!message) return std::unexpected(message.error());
    auto* opening = std::get_if<SnapshotBegin>(&*message);
    if (opening == nullptr) {
        return std::unexpected(poison(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }
    return std::move(opening->boundary);
}

domain::Result<std::optional<reflection::ReflectionRecord>> ReflectionStreamReader::next(
    std::stop_token cancellation) {
    if (state_ != State::reading) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "stream_state"));
    }
    auto message = receive(cancellation);
    if (!message) return std::unexpected(message.error());
    if (auto* record = std::get_if<reflection::ReflectionRecord>(&*message)) {
        if (record_count_ >= reflection_limits_.max_records) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "record_budget"));
        }
        ++record_count_;
        return std::optional<reflection::ReflectionRecord>{std::move(*record)};
    }
    auto* closing = std::get_if<SnapshotEnd>(&*message);
    if (closing == nullptr) {
        return std::unexpected(poison(DebugErrorCode::parse_error, "unexpected_frame_kind"));
    }
    end_ = std::move(closing->boundary);
    state_ = State::ended;
    // The transfer is over: later bytes never belong to it and are not read.
    stream_.reset();
    return std::optional<reflection::ReflectionRecord>{};
}

domain::Result<reflection::ReadBoundary> ReflectionStreamReader::finish(std::stop_token cancellation) {
    if (state_ != State::ended || !end_) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "stream_state"));
    }
    if (cancellation.stop_requested()) {
        return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
    }
    state_ = State::finished;
    return *end_;
}

domain::Result<ReflectionMessage> ReflectionStreamReader::receive(std::stop_token cancellation) {
    try {
        if (reflection_header_bytes > limits_.max_wire_bytes - wire_bytes_) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "wire_budget"));
        }
        std::array<std::byte, reflection_header_bytes> header{};
        if (auto read = read_exact(header, cancellation); !read) {
            return std::unexpected(read.error());
        }
        wire_bytes_ += reflection_header_bytes;

        Cursor head{header};
        std::uint8_t magic_byte{};
        for (const auto expected : frame_magic) {
            if (!head.u8(magic_byte) || static_cast<std::byte>(magic_byte) != expected) {
                return std::unexpected(poison(DebugErrorCode::parse_error, "invalid_magic"));
            }
        }
        std::uint16_t version{};
        std::uint16_t header_bytes{};
        std::uint16_t kind{};
        std::uint16_t reserved{};
        std::uint32_t payload_bytes{};
        std::uint64_t request{};
        std::uint64_t sequence{};
        // A full 32-byte header is already in hand, so these reads cannot truncate.
        if (!head.u16(version) || !head.u16(header_bytes) || !head.u16(kind) || !head.u16(reserved) ||
            !head.u32(payload_bytes) || !head.u64(request) || !head.u64(sequence) || !head.exhausted()) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "malformed_header"));
        }
        if (version != wire_version) {
            return std::unexpected(poison(DebugErrorCode::unsupported, "unsupported_frame_version"));
        }
        if (header_bytes != reflection_header_bytes) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "invalid_header_length"));
        }
        if (reserved != 0) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "invalid_reserved_field"));
        }
        if (kind != static_cast<std::uint16_t>(FrameKind::begin) &&
            kind != static_cast<std::uint16_t>(FrameKind::record) &&
            kind != static_cast<std::uint16_t>(FrameKind::end)) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "invalid_frame_kind"));
        }
        if (request != request_id_) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "unexpected_request_id"));
        }
        if (sequence != next_sequence_) {
            return std::unexpected(poison(DebugErrorCode::parse_error, "unexpected_sequence"));
        }
        if (payload_bytes > max_payload_bytes) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "frame_too_large"));
        }
        if (payload_bytes > limits_.max_wire_bytes - wire_bytes_) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "wire_budget"));
        }

        payload_.assign(payload_bytes, std::byte{});
        if (auto read = read_exact(payload_, cancellation); !read) {
            return std::unexpected(read.error());
        }
        wire_bytes_ += payload_bytes;
        ++next_sequence_;

        Cursor body{payload_};
        ReflectionMessage message;
        if (kind == static_cast<std::uint16_t>(FrameKind::record)) {
            reflection::ReflectionRecord record;
            if (!read_record(body, record, reflection_limits_.max_string_bytes)) {
                return std::unexpected(poison(DebugErrorCode::parse_error, body.reason()));
            }
            message = std::move(record);
        } else {
            reflection::ReadBoundary boundary;
            if (!read_boundary(body, boundary, max_identity_bytes)) {
                return std::unexpected(poison(DebugErrorCode::parse_error, body.reason()));
            }
            if (kind == static_cast<std::uint16_t>(FrameKind::begin)) {
                message = SnapshotBegin{std::move(boundary)};
            } else {
                message = SnapshotEnd{std::move(boundary)};
            }
        }
        if (!body.exhausted()) {
            return std::unexpected(poison(DebugErrorCode::parse_error, body.reason()));
        }
        return message;
    } catch (const std::bad_alloc&) {
        return std::unexpected(poison(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(poison(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

domain::Result<void> ReflectionStreamReader::read_exact(
    const std::span<std::byte> bytes, std::stop_token cancellation) {
    auto pending = bytes;
    while (!pending.empty()) {
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        if (clock_() > deadline_) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "stream_deadline"));
        }
        auto read = stream_->read(pending, deadline_, cancellation);
        if (!read) {
            // Transport diagnostics may carry native detail; keep the class only.
            const auto cancelled = read.error().code == DebugErrorCode::cancelled;
            return std::unexpected(poison(
                cancelled ? DebugErrorCode::cancelled : DebugErrorCode::io_error,
                cancelled ? "operation_cancelled" : "stream_read_failed"));
        }
        if (*read == 0) {
            return std::unexpected(poison(DebugErrorCode::io_error, "unexpected_eof"));
        }
        if (*read > pending.size()) {
            return std::unexpected(poison(DebugErrorCode::io_error, "stream_contract_violation"));
        }
        pending = pending.subspan(*read);
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        if (clock_() > deadline_) {
            return std::unexpected(poison(DebugErrorCode::limit_exceeded, "stream_deadline"));
        }
    }
    return {};
}

DebugError ReflectionStreamReader::poison(const DebugErrorCode code, const char* reason) {
    state_ = State::failed;
    end_.reset();
    // Closing here releases the transport even if the owner keeps the reader.
    stream_.reset();
    return fail(code, reason);
}

}  // namespace argos::infrastructure::santamonica
