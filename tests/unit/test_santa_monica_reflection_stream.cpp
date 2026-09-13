#include "argos_mcp/infrastructure/santa_monica_reflection_stream.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
using namespace argos::infrastructure::santamonica;

using Clock = ReflectionByteStream::Clock;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// ---------------------------------------------------------------------------
// Fixtures. Entirely synthetic metadata: no game layout, signature or bytes.
// ---------------------------------------------------------------------------

Sha256Digest digest(const unsigned char value) {
    Sha256Digest result;
    result.bytes.fill(static_cast<std::byte>(value));
    return result;
}

ProfileIdentity profile() {
    return {1, "synthetic-x64", digest(1), digest(2), 1, 1, {{"synthetic.exe", 4096, digest(3)}}};
}

ReadBoundary boundary() {
    return {{profile(), "synthetic-process-1", "synthetic-epoch-1", 1},
            Consistency::validated_best_effort, true};
}

std::vector<ReflectionRecord> fixture_records() {
    return {
        TypeRecord{{1}, "Base", 8, std::nullopt},
        TypeRecord{{2}, "Player", 16, TypeKey{1}},
        FieldRecord{{2}, "Health", 8, 8, FieldKind::scalar, std::nullopt, std::nullopt},
        EnumRecord{{3}, "Flags"},
        EnumValueRecord{{3}, "Maximum", "18446744073709551615"},
        SliFunctionRecord{{4}, "Describe", "string()"},
    };
}

constexpr std::uint64_t fixture_request = 7;

// ---------------------------------------------------------------------------
// Byte builders written independently of the production codec, so a symmetric
// encoder/decoder mistake cannot make a malformed format look correct.
// ---------------------------------------------------------------------------

class Bytes {
public:
    void u8(const std::uint8_t value) { data.push_back(static_cast<std::byte>(value)); }
    void u16(const std::uint16_t value) { integer(value, 2); }
    void u32(const std::uint32_t value) { integer(value, 4); }
    void u64(const std::uint64_t value) { integer(value, 8); }
    void raw(const std::string_view value) {
        for (const char c : value) u8(static_cast<std::uint8_t>(c));
    }
    void str(const std::string_view value) {
        u32(static_cast<std::uint32_t>(value.size()));
        raw(value);
    }
    void digest_of(const std::uint8_t fill) {
        for (int index = 0; index < 32; ++index) u8(fill);
    }
    void append(const std::vector<std::byte>& other) {
        data.insert(data.end(), other.begin(), other.end());
    }
    std::vector<std::byte> data;

private:
    void integer(const std::uint64_t value, const std::size_t width) {
        for (std::size_t index = 0; index < width; ++index) {
            u8(static_cast<std::uint8_t>((value >> (8U * index)) & 0xFFU));
        }
    }
};

struct FrameOptions {
    std::string_view magic{"SMRF"};
    std::uint16_t version{1};
    std::uint16_t header_bytes{32};
    std::uint16_t kind{1};
    std::uint16_t reserved{0};
    std::optional<std::uint32_t> declared_payload;
    std::uint64_t request{fixture_request};
    std::uint64_t sequence{1};
};

std::vector<std::byte> frame(const std::vector<std::byte>& payload, const FrameOptions& options = {}) {
    Bytes out;
    out.raw(options.magic);
    out.u16(options.version);
    out.u16(options.header_bytes);
    out.u16(options.kind);
    out.u16(options.reserved);
    out.u32(options.declared_payload.value_or(static_cast<std::uint32_t>(payload.size())));
    out.u64(options.request);
    out.u64(options.sequence);
    out.append(payload);
    return out.data;
}

struct BoundaryOptions {
    std::string profile_id{"synthetic-x64"};
    std::string module_name{"synthetic.exe"};
    std::uint32_t declared_modules{1};
    std::uint32_t written_modules{1};
    std::uint8_t architecture{1};
    std::uint8_t source{0};
    std::string process{"synthetic-process-1"};
    std::string epoch{"synthetic-epoch-1"};
    std::uint64_t generation{1};
    std::uint8_t consistency{0};
    std::uint8_t coverage{1};
};

std::vector<std::byte> boundary_payload(const BoundaryOptions& options = {}) {
    Bytes out;
    out.u32(1);
    out.str(options.profile_id);
    out.digest_of(1);
    out.digest_of(2);
    out.u32(1);
    out.u32(1);
    out.u32(options.declared_modules);
    for (std::uint32_t index = 0; index < options.written_modules; ++index) {
        out.str(options.module_name);
        out.u64(4096);
        out.digest_of(3);
    }
    out.u8(options.architecture);
    out.u8(options.source);
    out.str(options.process);
    out.str(options.epoch);
    out.u64(options.generation);
    out.u8(options.consistency);
    out.u8(options.coverage);
    return out.data;
}

// ---------------------------------------------------------------------------
// Transport double.
// ---------------------------------------------------------------------------

struct StreamState {
    bool alive{false};
    std::size_t reads{};
    std::size_t chunk{static_cast<std::size_t>(-1)};
    std::size_t fail_after{};  // 0 disables the injected transport failure.
    bool overread{false};
    std::function<void()> on_read;
};

class MemoryStream final : public ReflectionByteStream {
public:
    MemoryStream(std::vector<std::byte> bytes, StreamState& state)
        : bytes_(std::move(bytes)), state_(state) {
        state_.alive = true;
    }
    ~MemoryStream() override { state_.alive = false; }

    Result<std::size_t> read(const std::span<std::byte> destination, Clock::time_point,
                             std::stop_token) override {
        ++state_.reads;
        if (state_.on_read) state_.on_read();
        if (state_.fail_after != 0 && state_.reads > state_.fail_after) {
            return std::unexpected(DebugError{DebugErrorCode::io_error,
                                              "private-path native bytes 0x1234", "private-native-reason"});
        }
        if (state_.overread) return destination.size() + 1;
        const auto available = std::min({state_.chunk, destination.size(), bytes_.size() - offset_});
        if (available == 0) return std::size_t{0};
        std::copy_n(std::next(bytes_.begin(), static_cast<std::ptrdiff_t>(offset_)), available,
                    destination.begin());
        offset_ += available;
        return available;
    }

private:
    std::vector<std::byte> bytes_;
    std::size_t offset_{};
    StreamState& state_;
};

struct Transfer {
    bool ok{false};
    DebugError error;
    ReadBoundary first;
    ReadBoundary last;
    std::vector<ReflectionRecord> records;
};

Transfer consume(ReflectionStreamReader& reader, const ReflectionLimits& limits = {},
                 const std::stop_token cancellation = {}) {
    Transfer out;
    auto start = reader.begin(limits, cancellation);
    if (!start) {
        out.error = start.error();
        return out;
    }
    out.first = std::move(*start);
    while (true) {
        auto next = reader.next(cancellation);
        if (!next) {
            out.error = next.error();
            return out;
        }
        if (!*next) break;
        out.records.push_back(std::move(**next));
    }
    auto end = reader.finish(cancellation);
    if (!end) {
        out.error = end.error();
        return out;
    }
    out.last = std::move(*end);
    out.ok = true;
    return out;
}

std::unique_ptr<ReflectionStreamReader> make_reader(
    std::vector<std::byte> bytes, StreamState& state, const std::uint64_t request = fixture_request,
    const ReflectionStreamLimits limits = {},
    ReflectionStreamReader::ClockFn clock = [] { return Clock::now(); }) {
    return std::make_unique<ReflectionStreamReader>(
        std::make_unique<MemoryStream>(std::move(bytes), state), request, limits, std::move(clock));
}

std::vector<std::byte> encoded_stream(const std::uint64_t request = fixture_request) {
    std::vector<std::byte> bytes;
    std::uint64_t sequence = 1;
    const auto push = [&](const ReflectionMessage& message) {
        auto encoded = encode_reflection_frame(message, request, sequence++);
        check(encoded.has_value(), "fixture frame encodes");
        if (encoded) bytes.insert(bytes.end(), encoded->begin(), encoded->end());
    };
    push(SnapshotBegin{boundary()});
    for (const auto& record : fixture_records()) push(record);
    push(SnapshotEnd{boundary()});
    return bytes;
}

// Runs a stream expected to fail and returns the first error observed.
DebugError failure_of(std::vector<std::byte> bytes, const char* label,
                      const ReflectionLimits& limits = {}) {
    StreamState state;
    auto reader = make_reader(std::move(bytes), state);
    const auto transfer = consume(*reader, limits);
    check(!transfer.ok, label);
    check(!state.alive, "failed transfer closes its stream");
    return transfer.error;
}

void expect_failure(std::vector<std::byte> bytes, const char* reason,
                    const DebugErrorCode code = DebugErrorCode::parse_error,
                    const ReflectionLimits& limits = {}) {
    const auto error = failure_of(std::move(bytes), reason, limits);
    check(error.reason == reason, reason);
    check(error.code == code, "rejection uses the documented error code");
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

void test_wire_format() {
    auto begin = encode_reflection_frame(SnapshotBegin{boundary()}, fixture_request, 1);
    check(begin.has_value(), "begin frame encodes");
    if (begin) {
        check(*begin == frame(boundary_payload(), {}), "begin frame matches the documented bytes");
        check(begin->size() >= reflection_header_bytes, "frame carries a full header");
        const auto header = std::span{*begin}.first(reflection_header_bytes);
        check(header[0] == std::byte{'S'} && header[1] == std::byte{'M'} &&
              header[2] == std::byte{'R'} && header[3] == std::byte{'F'}, "magic is SMRF");
        check(header[4] == std::byte{1} && header[5] == std::byte{0}, "version 1 little-endian");
        check(header[6] == std::byte{32} && header[7] == std::byte{0}, "header length is 32");
        check(header[8] == std::byte{1} && header[9] == std::byte{0}, "begin kind is 1");
        check(header[10] == std::byte{0} && header[11] == std::byte{0}, "reserved is zero");
        const auto payload = begin->size() - reflection_header_bytes;
        check(static_cast<std::size_t>(header[12]) == (payload & 0xFFU), "payload length is encoded");
        check(header[16] == std::byte{fixture_request}, "request id is encoded");
        check(header[24] == std::byte{1}, "sequence starts at one");
    }

    auto end = encode_reflection_frame(SnapshotEnd{boundary()}, fixture_request, 9);
    check(end.has_value(), "end frame encodes");
    if (end) {
        check(*end == frame(boundary_payload(), {.kind = 3, .sequence = 9}),
              "end frame matches the documented bytes");
    }

    const auto records = fixture_records();
    Bytes type_payload;
    type_payload.u8(1);
    type_payload.u64(2);
    type_payload.str("Player");
    type_payload.u64(16);
    type_payload.u8(1);
    type_payload.u64(1);
    auto encoded_type = encode_reflection_frame(records[1], fixture_request, 2);
    check(encoded_type.has_value() &&
          *encoded_type == frame(type_payload.data, {.kind = 2, .sequence = 2}),
          "type record matches the documented bytes");

    Bytes field_payload;
    field_payload.u8(2);
    field_payload.u64(2);
    field_payload.str("Health");
    field_payload.u64(8);
    field_payload.u64(8);
    field_payload.u8(0);
    field_payload.u8(0);
    field_payload.u8(0);
    auto encoded_field = encode_reflection_frame(records[2], fixture_request, 3);
    check(encoded_field.has_value() &&
          *encoded_field == frame(field_payload.data, {.kind = 2, .sequence = 3}),
          "field record matches the documented bytes");

    Bytes enum_payload;
    enum_payload.u8(3);
    enum_payload.u64(3);
    enum_payload.str("Flags");
    auto encoded_enum = encode_reflection_frame(records[3], fixture_request, 4);
    check(encoded_enum.has_value() &&
          *encoded_enum == frame(enum_payload.data, {.kind = 2, .sequence = 4}),
          "enum record matches the documented bytes");

    Bytes value_payload;
    value_payload.u8(4);
    value_payload.u64(3);
    value_payload.str("Maximum");
    value_payload.str("18446744073709551615");
    auto encoded_value = encode_reflection_frame(records[4], fixture_request, 5);
    check(encoded_value.has_value() &&
          *encoded_value == frame(value_payload.data, {.kind = 2, .sequence = 5}),
          "enum value record matches the documented bytes");

    Bytes function_payload;
    function_payload.u8(5);
    function_payload.u64(4);
    function_payload.str("Describe");
    function_payload.str("string()");
    auto encoded_function = encode_reflection_frame(records[5], fixture_request, 6);
    check(encoded_function.has_value() &&
          *encoded_function == frame(function_payload.data, {.kind = 2, .sequence = 6}),
          "SLI record matches the documented bytes");
}

void test_encoder_rejections() {
    check(!encode_reflection_frame(SnapshotBegin{boundary()}, 0, 1), "zero request id refused");
    check(!encode_reflection_frame(SnapshotBegin{boundary()}, fixture_request, 0), "zero sequence refused");

    auto empty_modules = boundary();
    empty_modules.identity.profile.modules.clear();
    check(!encode_reflection_frame(SnapshotBegin{empty_modules}, fixture_request, 1),
          "boundary without modules refused");

    auto many_modules = boundary();
    many_modules.identity.profile.modules.assign(65, {"synthetic.exe", 4096, digest(3)});
    check(!encode_reflection_frame(SnapshotBegin{many_modules}, fixture_request, 1),
          "boundary above the module ceiling refused");

    auto bad_architecture = boundary();
    bad_architecture.identity.profile.architecture = static_cast<Architecture>(99);
    check(!encode_reflection_frame(SnapshotBegin{bad_architecture}, fixture_request, 1),
          "unknown architecture refused");

    auto bad_consistency = boundary();
    bad_consistency.consistency = static_cast<Consistency>(99);
    check(!encode_reflection_frame(SnapshotBegin{bad_consistency}, fixture_request, 1),
          "unknown consistency refused");

    auto long_identity = boundary();
    long_identity.identity.process_instance = std::string(129, 'a');
    check(!encode_reflection_frame(SnapshotBegin{long_identity}, fixture_request, 1),
          "identity above 128 bytes refused");

    check(!encode_reflection_frame(ReflectionRecord{TypeRecord{{1}, "", 8, std::nullopt}},
                                   fixture_request, 1), "empty name refused");
    check(!encode_reflection_frame(
              ReflectionRecord{TypeRecord{{1}, std::string(4097, 'a'), 8, std::nullopt}},
              fixture_request, 1), "metadata above 4096 bytes refused");
    check(!encode_reflection_frame(ReflectionRecord{TypeRecord{{1}, std::string("Base\0", 5), 8, std::nullopt}},
                                   fixture_request, 1), "embedded NUL refused");
    check(!encode_reflection_frame(
              ReflectionRecord{FieldRecord{{2}, "Health", 8, 8, static_cast<FieldKind>(42),
                                           std::nullopt, std::nullopt}}, fixture_request, 1),
          "unknown field kind refused");
}

void test_round_trip() {
    for (const std::size_t chunk : {static_cast<std::size_t>(-1), std::size_t{1}, std::size_t{7}}) {
        StreamState state;
        state.chunk = chunk;
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader);
        check(transfer.ok, "valid stream decodes under arbitrary fragmentation");
        if (!transfer.ok) continue;
        check(!state.alive, "completed transfer closes its stream");
        check(transfer.first.identity == boundary().identity, "identity round-trips");
        check(transfer.first.consistency == Consistency::validated_best_effort, "consistency round-trips");
        check(transfer.first.coverage_complete, "coverage round-trips");
        check(transfer.last.identity == boundary().identity, "closing identity round-trips");
        check(transfer.records.size() == 6, "every record arrives exactly once");
        if (transfer.records.size() != 6) continue;

        const auto& base = std::get<TypeRecord>(transfer.records[0]);
        check(base.id.value == 1 && base.name == "Base" && base.size == 8 && !base.base,
              "type without base round-trips");
        const auto& player = std::get<TypeRecord>(transfer.records[1]);
        check(player.base && player.base->value == 1, "optional base round-trips");
        const auto& field = std::get<FieldRecord>(transfer.records[2]);
        check(field.owner.value == 2 && field.name == "Health" && field.offset == 8 && field.size == 8 &&
              field.kind == FieldKind::scalar && !field.referenced_type && !field.referenced_enum,
              "field round-trips");
        const auto& flags = std::get<EnumRecord>(transfer.records[3]);
        check(flags.id.value == 3 && flags.name == "Flags", "enum round-trips");
        const auto& maximum = std::get<EnumValueRecord>(transfer.records[4]);
        check(maximum.owner.value == 3 && maximum.value == "18446744073709551615",
              "64-bit enum value keeps its exact decimal spelling");
        const auto& describe = std::get<SliFunctionRecord>(transfer.records[5]);
        check(describe.id.value == 4 && describe.signature == "string()", "SLI record round-trips");
    }

    // Every field kind and reference shape survives the wire.
    const std::vector<ReflectionRecord> shapes{
        FieldRecord{{1}, "Object", 0, 16, FieldKind::object, TypeKey{2}, std::nullopt},
        FieldRecord{{1}, "Pointer", 16, 8, FieldKind::pointer, TypeKey{2}, std::nullopt},
        FieldRecord{{1}, "Array", 24, 8, FieldKind::array, TypeKey{2}, std::nullopt},
        FieldRecord{{1}, "Map", 32, 8, FieldKind::map, TypeKey{2}, std::nullopt},
        FieldRecord{{1}, "Enumeration", 40, 4, FieldKind::enumeration, std::nullopt, EnumKey{3}},
    };
    for (const auto& shape : shapes) {
        auto encoded = encode_reflection_frame(shape, fixture_request, 2);
        check(encoded.has_value(), "field shape encodes");
        if (!encoded) continue;
        std::vector<std::byte> bytes;
        auto opening = encode_reflection_frame(SnapshotBegin{boundary()}, fixture_request, 1);
        auto closing = encode_reflection_frame(SnapshotEnd{boundary()}, fixture_request, 3);
        check(opening && closing, "boundary frames encode");
        if (!opening || !closing) continue;
        bytes.insert(bytes.end(), opening->begin(), opening->end());
        bytes.insert(bytes.end(), encoded->begin(), encoded->end());
        bytes.insert(bytes.end(), closing->begin(), closing->end());
        StreamState state;
        auto reader = make_reader(std::move(bytes), state);
        const auto transfer = consume(*reader);
        check(transfer.ok && transfer.records.size() == 1, "field shape decodes");
        if (!transfer.ok || transfer.records.size() != 1) continue;
        const auto& decoded = std::get<FieldRecord>(transfer.records[0]);
        const auto& original = std::get<FieldRecord>(shape);
        check(decoded.kind == original.kind && decoded.offset == original.offset &&
              decoded.size == original.size &&
              decoded.referenced_type.has_value() == original.referenced_type.has_value() &&
              decoded.referenced_enum.has_value() == original.referenced_enum.has_value(),
              "field kind and references round-trip");
    }
}

void test_catalog_integration() {
    StreamState state;
    auto reader = make_reader(encoded_stream(), state);
    auto catalog = ReflectionCatalog::read(*reader, profile());
    check(catalog.has_value(), "streamed snapshot is admitted by the domain catalog");
    if (catalog) {
        check((*catalog)->records().size() == 6, "catalog keeps every streamed record");
        check((*catalog)->identity() == boundary().identity, "catalog keeps the streamed identity");
        check((*catalog)->coverage_complete(), "catalog keeps the declared coverage");
    }
    check(!state.alive, "catalog read closes the stream");

    // Structural decoding never bypasses domain validation.
    std::vector<std::byte> bytes;
    std::uint64_t sequence = 1;
    const auto push = [&](const ReflectionMessage& message) {
        auto encoded = encode_reflection_frame(message, fixture_request, sequence++);
        if (encoded) bytes.insert(bytes.end(), encoded->begin(), encoded->end());
    };
    push(SnapshotBegin{boundary()});
    push(ReflectionRecord{TypeRecord{{1}, "Base", 8, std::nullopt}});
    push(ReflectionRecord{FieldRecord{{1}, "Overflow", 4, 8, FieldKind::scalar, std::nullopt, std::nullopt}});
    push(SnapshotEnd{boundary()});
    StreamState invalid_state;
    auto invalid_reader = make_reader(bytes, invalid_state);
    auto invalid = ReflectionCatalog::read(*invalid_reader, profile());
    check(!invalid && invalid.error().reason == "field_out_of_bounds",
          "well-formed frames still face domain bounds validation");

    StreamState mismatch_state;
    auto mismatch_reader = make_reader(encoded_stream(), mismatch_state);
    auto other = profile();
    other.profile_id = "synthetic-other";
    auto mismatch = ReflectionCatalog::read(*mismatch_reader, other);
    check(!mismatch && mismatch.error().reason == "profile_mismatch",
          "streamed identity cannot substitute the expected profile");
}

void test_header_rejections() {
    const auto suffix = [](const FrameOptions& options) {
        auto bytes = frame(boundary_payload(), options);
        auto rest = encoded_stream();
        rest.erase(rest.begin(),
                   std::next(rest.begin(), static_cast<std::ptrdiff_t>(
                                               reflection_header_bytes + boundary_payload().size())));
        bytes.insert(bytes.end(), rest.begin(), rest.end());
        return bytes;
    };

    expect_failure(suffix({.magic = "SMRG"}), "invalid_magic");
    expect_failure(suffix({.version = 2}), "unsupported_frame_version", DebugErrorCode::unsupported);
    expect_failure(suffix({.header_bytes = 33}), "invalid_header_length");
    expect_failure(suffix({.kind = 4}), "invalid_frame_kind");
    expect_failure(suffix({.reserved = 1}), "invalid_reserved_field");
    expect_failure(suffix({.request = fixture_request + 1}), "unexpected_request_id");
    expect_failure(suffix({.sequence = 2}), "unexpected_sequence");
    expect_failure(suffix({.declared_payload = 0xFFFFFFFFU}), "frame_too_large",
                   DebugErrorCode::limit_exceeded);

    // A record frame where the begin frame belongs.
    auto record_first = encoded_stream();
    record_first.erase(record_first.begin(),
                       std::next(record_first.begin(), static_cast<std::ptrdiff_t>(
                                                           reflection_header_bytes + boundary_payload().size())));
    record_first[24] = std::byte{1};
    expect_failure(record_first, "unexpected_frame_kind");

    // Replaying the opening frame in the middle of the transfer.
    auto replayed = encoded_stream();
    auto opening = encode_reflection_frame(SnapshotBegin{boundary()}, fixture_request, 2);
    check(opening.has_value(), "replayed frame encodes");
    if (opening) {
        replayed.erase(std::next(replayed.begin(), static_cast<std::ptrdiff_t>(
                                                       reflection_header_bytes + boundary_payload().size())),
                       replayed.end());
        replayed.insert(replayed.end(), opening->begin(), opening->end());
        expect_failure(replayed, "unexpected_frame_kind");
    }
}

void test_payload_rejections() {
    const auto with_begin = [](const std::vector<std::byte>& payload, const std::uint16_t kind = 1,
                               const std::uint64_t sequence = 1) {
        if (sequence == 1) return frame(payload, {.kind = kind, .sequence = sequence});
        auto bytes = frame(boundary_payload(), {});
        const auto tail = frame(payload, {.kind = kind, .sequence = sequence});
        bytes.insert(bytes.end(), tail.begin(), tail.end());
        return bytes;
    };

    expect_failure(with_begin(boundary_payload({.architecture = 2})), "invalid_architecture");
    expect_failure(with_begin(boundary_payload({.source = 2})), "invalid_snapshot_source");
    expect_failure(with_begin(boundary_payload({.consistency = 3})), "invalid_consistency");
    expect_failure(with_begin(boundary_payload({.declared_modules = 0, .written_modules = 0})),
                   "invalid_module_count");
    expect_failure(with_begin(boundary_payload({.declared_modules = 65, .written_modules = 65})),
                   "invalid_module_count");
    expect_failure(with_begin(boundary_payload({.coverage = 2})), "invalid_bool");
    expect_failure(with_begin(boundary_payload({.profile_id = std::string(129, 'a')})),
                   "invalid_string_length");
    expect_failure(with_begin(boundary_payload({.process = std::string("bad\x01name", 8)})),
                   "invalid_string_byte");

    auto trailing = boundary_payload();
    trailing.push_back(std::byte{0});
    expect_failure(with_begin(trailing), "trailing_payload_bytes");

    auto truncated = boundary_payload();
    truncated.pop_back();
    expect_failure(with_begin(truncated), "truncated_payload");

    Bytes unknown_tag;
    unknown_tag.u8(6);
    expect_failure(with_begin(unknown_tag.data, 2, 2), "invalid_record_tag");

    Bytes bad_kind;
    bad_kind.u8(2);
    bad_kind.u64(2);
    bad_kind.str("Health");
    bad_kind.u64(8);
    bad_kind.u64(8);
    bad_kind.u8(9);
    expect_failure(with_begin(bad_kind.data, 2, 2), "invalid_field_kind");

    Bytes empty_name;
    empty_name.u8(1);
    empty_name.u64(1);
    empty_name.u32(0);
    empty_name.u64(8);
    empty_name.u8(0);
    expect_failure(with_begin(empty_name.data, 2, 2), "invalid_string_length");

    // A declared length beyond the frame is refused before the body is sized.
    Bytes oversized_string;
    oversized_string.u8(1);
    oversized_string.u64(1);
    oversized_string.u32(0xFFFFFFFFU);
    expect_failure(with_begin(oversized_string.data, 2, 2), "invalid_string_length");

    Bytes beyond_frame;
    beyond_frame.u8(1);
    beyond_frame.u64(1);
    beyond_frame.u32(4000);
    beyond_frame.raw("Base");
    expect_failure(with_begin(beyond_frame.data, 2, 2), "truncated_payload");

    // The negotiated metadata ceiling, not only the absolute one, is enforced.
    Bytes long_name;
    long_name.u8(1);
    long_name.u64(1);
    long_name.str(std::string(64, 'a'));
    long_name.u64(8);
    long_name.u8(0);
    expect_failure(with_begin(long_name.data, 2, 2), "invalid_string_length", DebugErrorCode::parse_error,
                   {.max_records = 10, .max_string_bytes = 16});
}

void test_transport_failures() {
    auto bytes = encoded_stream();
    bytes.resize(bytes.size() - 4);
    expect_failure(bytes, "unexpected_eof", DebugErrorCode::io_error);

    auto header_only = encoded_stream();
    header_only.resize(reflection_header_bytes - 1);
    expect_failure(header_only, "unexpected_eof", DebugErrorCode::io_error);

    {
        StreamState state;
        state.fail_after = 1;
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader);
        check(!transfer.ok && transfer.error.reason == "stream_read_failed", "transport failure reported");
        check(transfer.error.safe_message.find("private") == std::string::npos &&
              transfer.error.safe_message.find("0x1234") == std::string::npos,
              "transport diagnostics never reach the caller");
        check(!state.alive, "transport failure closes the stream");
    }
    {
        StreamState state;
        state.overread = true;
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader);
        check(!transfer.ok && transfer.error.reason == "stream_contract_violation",
              "a stream reporting more bytes than requested is refused");
    }
    {
        StreamState state;
        std::stop_source source;
        state.chunk = 8;
        state.on_read = [&source] { source.request_stop(); };
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader, {}, source.get_token());
        check(!transfer.ok && transfer.error.code == DebugErrorCode::cancelled,
              "cancellation during I/O stops the transfer");
        check(!state.alive, "cancellation closes the stream");
    }
    {
        StreamState state;
        auto now = Clock::now();
        state.chunk = 8;
        state.on_read = [&now] { now += std::chrono::seconds(6); };
        auto reader = make_reader(encoded_stream(), state, fixture_request, {},
                                  [&now] { return now; });
        const auto transfer = consume(*reader);
        check(!transfer.ok && transfer.error.reason == "stream_deadline" &&
              transfer.error.code == DebugErrorCode::limit_exceeded,
              "the total deadline bounds the transfer");
        check(!state.alive, "deadline closes the stream");
    }
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state, fixture_request, {.max_wire_bytes = 64});
        const auto transfer = consume(*reader);
        check(!transfer.ok && transfer.error.reason == "wire_budget" &&
              transfer.error.code == DebugErrorCode::limit_exceeded,
              "the aggregate wire budget bounds the transfer");
    }
}

void test_state_and_limits() {
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state);
        auto early = reader->next({});
        check(!early && early.error().reason == "stream_state", "next before begin is refused");
        auto start = reader->begin({}, {});
        check(!start && start.error().reason == "stream_state", "a failed reader stays failed");
        check(!state.alive, "misuse closes the stream");
    }
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state);
        check(reader->begin({}, {}).has_value(), "first begin succeeds");
        auto again = reader->begin({}, {});
        check(!again && again.error().reason == "stream_state", "a second begin is refused");
    }
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state);
        check(reader->begin({}, {}).has_value(), "begin succeeds");
        auto early = reader->finish({});
        check(!early && early.error().reason == "stream_state", "finish before the end frame is refused");
    }
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader);
        check(transfer.ok, "complete transfer succeeds");
        auto after = reader->next({});
        check(!after && after.error().reason == "stream_state", "reading after the end is refused");
    }
    {
        StreamState state;
        std::stop_source source;
        auto reader = make_reader(encoded_stream(), state);
        check(reader->begin({}, {}).has_value(), "begin succeeds");
        for (int index = 0; index < 6; ++index) {
            check(reader->next({}).has_value(), "record arrives");
        }
        check(reader->next({}).has_value(), "end frame arrives");
        source.request_stop();
        auto finish = reader->finish(source.get_token());
        check(!finish && finish.error().code == DebugErrorCode::cancelled,
              "cancellation before finish is honored");
    }

    expect_failure(encoded_stream(), "record_budget", DebugErrorCode::limit_exceeded,
                   {.max_records = 3});

    const ReflectionLimits invalid_limits[]{
        {.max_records = 0}, {.max_records = 100001}, {.max_string_bytes = 0}, {.max_string_bytes = 4097}};
    for (const auto& limits : invalid_limits) {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state);
        auto start = reader->begin(limits, {});
        check(!start && start.error().reason == "invalid_reflection_limits",
              "reflection limits above the ceiling are refused");
        check(state.reads == 0, "invalid limits are refused before any read");
    }

    const ReflectionStreamLimits invalid_stream_limits[]{
        {.max_wire_bytes = 0},
        {.max_wire_bytes = 64U * 1024U * 1024U + 1},
        {.max_duration = std::chrono::milliseconds::zero()},
        {.max_duration = std::chrono::milliseconds{5001}}};
    for (const auto& limits : invalid_stream_limits) {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state, fixture_request, limits);
        auto start = reader->begin({}, {});
        check(!start && start.error().reason == "invalid_stream_limits",
              "stream limits above the ceiling are refused");
        check(state.reads == 0, "invalid stream limits are refused before any read");
    }
    {
        StreamState state;
        auto reader = make_reader(encoded_stream(), state, 0);
        auto start = reader->begin({}, {});
        check(!start && start.error().reason == "invalid_stream_request", "a zero request id is refused");
    }
    {
        ReflectionStreamReader reader{nullptr, fixture_request};
        auto start = reader.begin({}, {});
        check(!start && start.error().reason == "invalid_stream_request", "a missing stream is refused");
    }
    {
        StreamState state;
        std::stop_source source;
        source.request_stop();
        auto reader = make_reader(encoded_stream(), state);
        const auto transfer = consume(*reader, {}, source.get_token());
        check(!transfer.ok && transfer.error.code == DebugErrorCode::cancelled,
              "cancellation before the first read stops the transfer");
        check(state.reads == 0, "cancellation is checked before reading");
    }
}

}  // namespace

int main() {
    test_wire_format();
    test_encoder_rejections();
    test_round_trip();
    test_catalog_integration();
    test_header_rejections();
    test_payload_rejections();
    test_transport_failures();
    test_state_and_limits();
    if (failures != 0) std::cerr << failures << " Santa Monica stream test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
