#include "argos_mcp/infrastructure/santa_monica_native_reader.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;

constexpr std::size_t max_type_name_bytes = 128;
constexpr std::uint64_t max_table_span = 8ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t max_type_size = 1ULL << 20;
constexpr std::size_t record_buffer_bytes = 256;
constexpr std::uint32_t max_enum_values = 4096;

// How the engine spells a field's type in the two low bits plus kind bits of
// its flag byte. Named here so the mapping to a domain FieldKind is readable.
enum class AttributeKind : std::uint8_t {
    integral = 0,
    unsigned_integral = 1,
    floating_point = 2,
    char_array = 3,
    string_hash = 4,
    flags = 5,
    char_array_pointer = 6,
    pointer = 7,
    reference = 8,
    array = 9,
    hash_map = 10,
    class_instance = 11,
};

constexpr std::uint8_t max_attribute_kind = 11;

// One family only. A profile_id the server does not know is unsupported: there
// is no "generic" fallback that guesses a record shape.
constexpr NativeTypeTableLayout gow2018_layout{
    // type table
    80, 0x00, 0x08, 0x10, 0x18, 0x28, 0x20, 0x24,
    // attribute table
    32, 0x00, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C,
    // enum table
    32, 0x00, 0x0C, 0x10, 0x18,
    // sli function table
    32, 0x00, 0x08, 0x10};

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica native reader failed", reason};
}

[[nodiscard]] bool present(const reflection::Sha256Digest& digest) {
    return std::ranges::any_of(digest.bytes, [](const std::byte value) { return value != std::byte{}; });
}

[[nodiscard]] std::uint64_t load_unsigned(
    const std::span<const std::byte> bytes, const std::size_t offset, const std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value |= static_cast<std::uint64_t>(static_cast<unsigned char>(bytes[offset + index]))
            << (8U * index);
    }
    return value;
}

[[nodiscard]] std::uint64_t load_u64(const std::span<const std::byte> bytes, const std::size_t offset) {
    return load_unsigned(bytes, offset, 8);
}

[[nodiscard]] std::uint32_t load_u32(const std::span<const std::byte> bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(load_unsigned(bytes, offset, 4));
}

[[nodiscard]] std::uint16_t load_u16(const std::span<const std::byte> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(load_unsigned(bytes, offset, 2));
}

[[nodiscard]] std::uint8_t load_u8(const std::span<const std::byte> bytes, const std::size_t offset) {
    return static_cast<std::uint8_t>(static_cast<unsigned char>(bytes[offset]));
}

// Stable across discoveries of the same build, so a client can cache an id;
// it is a digest of the name, never an address.
[[nodiscard]] std::uint64_t name_id(const std::string_view name) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char c : name) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ULL;
    }
    return hash;
}

[[nodiscard]] bool printable(const std::string_view value, const std::size_t limit) {
    return !value.empty() && value.size() <= limit && std::ranges::all_of(value, [](const char c) {
        return c >= ' ' && c <= '~';
    });
}

[[nodiscard]] bool ascii_equal(const std::string_view left, const std::string_view right) {
    if (left.size() != right.size()) return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        auto lower = [](const char c) {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
        };
        if (lower(left[index]) != lower(right[index])) return false;
    }
    return true;
}

[[nodiscard]] reflection::FieldKind to_field_kind(const AttributeKind kind, const bool has_enum) {
    switch (kind) {
        case AttributeKind::integral:
        case AttributeKind::unsigned_integral:
            return has_enum ? reflection::FieldKind::enumeration : reflection::FieldKind::scalar;
        case AttributeKind::char_array_pointer:
        case AttributeKind::pointer:
        case AttributeKind::reference:
            return reflection::FieldKind::pointer;
        case AttributeKind::array:
            return reflection::FieldKind::array;
        case AttributeKind::hash_map:
            return reflection::FieldKind::map;
        case AttributeKind::class_instance:
            return reflection::FieldKind::object;
        case AttributeKind::floating_point:
        case AttributeKind::char_array:
        case AttributeKind::string_hash:
        case AttributeKind::flags:
            break;
    }
    return reflection::FieldKind::scalar;
}

// A range is "not published" when the profile leaves it empty; that is a valid
// profile, not an error. Anything else must sit inside the image.
[[nodiscard]] bool range_usable(
    const std::uint64_t begin, const std::uint64_t end, const std::uint64_t stride,
    const std::uint64_t module_size) {
    if (begin == 0 && end == 0) return true;
    if (begin == 0 || end <= begin || stride == 0) return false;
    if ((end - begin) % stride != 0) return false;
    if (end - begin > max_table_span) return false;
    return end <= module_size;
}

[[nodiscard]] bool range_published(const std::uint64_t begin, const std::uint64_t end) {
    return end > begin;
}

}  // namespace

const NativeTypeTableLayout* find_native_type_table_layout(const std::string_view profile_id) {
    return profile_id == "gow2018-reflection-x64-v2" ? &gow2018_layout : nullptr;
}

Result<reflection::ProfileIdentity> native_profile_identity(const NativeTypeTableRequest& request) {
    reflection::ProfileIdentity profile;
    profile.schema_version = 1;
    profile.profile_id = request.profile_id;
    profile.profile_digest = request.profile_digest;
    // No bridge exists on this path, and the domain refuses a native profile
    // that carries bridge identity anyway.
    profile.bridge_digest = {};
    profile.bridge_version = 0;
    profile.protocol_version = 1;
    profile.architecture = reflection::Architecture::x64;
    profile.source = reflection::SnapshotSource::native_reader;
    profile.modules.push_back(
        reflection::ModuleIdentity{request.module_name, request.module_size, request.module_digest});
    auto valid = reflection::validate_profile_identity(profile);
    if (!valid) return std::unexpected(valid.error());
    return profile;
}

NativeTypeTableReader::NativeTypeTableReader(
    const domain::RuntimeMemoryView& memory, NativeTypeTableRequest request)
    : memory_(memory), request_(std::move(request)) {}

DebugError NativeTypeTableReader::poison(const DebugErrorCode code, const char* reason) {
    state_ = State::failed;
    return fail(code, reason);
}

Result<void> NativeTypeTableReader::read_exact(
    const domain::Address address, const std::span<std::byte> destination,
    const std::stop_token cancellation) {
    if (!contains(address, destination.size())) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "read_outside_module"));
    }
    constexpr std::uint64_t max_read_bytes = 64ULL * 1024ULL * 1024ULL;
    if (destination.size() > max_read_bytes - read_bytes_) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "read_budget"));
    }
    read_bytes_ += destination.size();
    auto pending = destination;
    domain::Address cursor = address;
    while (!pending.empty()) {
        if (auto ready = check_work(cancellation); !ready) return ready;
        auto read = memory_.read(cursor, pending, cancellation);
        if (auto ready = check_work(cancellation); !ready) return ready;
        if (!read && read.error().code == DebugErrorCode::cancelled) {
            return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        if (!read) return std::unexpected(fail(DebugErrorCode::io_error, "native_read_failed"));
        if (*read == 0 || *read > pending.size()) {
            return std::unexpected(fail(DebugErrorCode::io_error, "native_read_failed"));
        }
        pending = pending.subspan(*read);
        cursor += *read;
    }
    return {};
}

bool NativeTypeTableReader::contains(const std::uint64_t address, const std::uint64_t size) const noexcept {
    return address >= module_base_ && address - module_base_ <= request_.module_size &&
        size <= request_.module_size - (address - module_base_);
}

Result<void> NativeTypeTableReader::check_work(const std::stop_token cancellation) {
    if (cancellation.stop_requested()) {
        return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
    }
    if (std::chrono::steady_clock::now() >= deadline_) {
        return std::unexpected(poison(DebugErrorCode::limit_exceeded, "native_deadline"));
    }
    return {};
}

Result<std::string> NativeTypeTableReader::read_name(
    const std::uint64_t rva, const std::stop_token cancellation) {
    if (rva < request_.names_begin_rva || rva >= request_.names_end_rva) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "name_out_of_range"));
    }
    const auto limit = std::min<std::uint64_t>(max_type_name_bytes + 1,
                                               request_.names_end_rva - rva);
    std::array<std::byte, max_type_name_bytes + 1> buffer{};
    const auto window = std::span{buffer}.first(static_cast<std::size_t>(limit));
    if (auto read = read_exact(module_base_ + rva, window, cancellation); !read) {
        return std::unexpected(read.error());
    }
    const auto terminator = std::ranges::find(window, std::byte{});
    if (terminator == window.end()) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "unterminated_name"));
    }
    std::string name;
    name.reserve(static_cast<std::size_t>(terminator - window.begin()));
    for (auto cursor = window.begin(); cursor != terminator; ++cursor) {
        name.push_back(static_cast<char>(*cursor));
    }
    return name;
}

Result<std::string> NativeTypeTableReader::read_name_via_pointer(
    const std::uint64_t pointer, const std::stop_token cancellation) {
    if (pointer < module_base_) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "name_out_of_range"));
    }
    return read_name(pointer - module_base_, cancellation);
}

Result<void> NativeTypeTableReader::charge_record() {
    if (emitted_ >= limits_.max_records) {
        return std::unexpected(poison(DebugErrorCode::limit_exceeded, "record_budget"));
    }
    ++emitted_;
    return {};
}

Result<void> NativeTypeTableReader::load_types(const std::stop_token cancellation) {
    const auto& layout = *layout_;
    const auto count = (request_.table_end_rva - request_.table_begin_rva) / layout.record_stride;
    types_.resize(static_cast<std::size_t>(count));

    std::array<std::byte, record_buffer_bytes> buffer{};
    const auto record = std::span{buffer}.first(layout.record_stride);
    for (std::size_t index = 0; index < types_.size(); ++index) {
        if (cancellation.stop_requested()) {
            return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto rva = request_.table_begin_rva + index * layout.record_stride;
        if (auto read = read_exact(module_base_ + rva, record, cancellation); !read) {
            return std::unexpected(read.error());
        }
        const auto tag_pointer = load_u64(record, layout.tag_offset);
        const auto size = load_u64(record, layout.size_offset);
        const auto align = load_u64(record, layout.align_offset);
        if (tag_pointer < module_base_) {
            ++skipped_;
            continue;
        }
        const auto tag_rva = tag_pointer - module_base_;
        if (tag_rva < request_.names_begin_rva || tag_rva >= request_.names_end_rva ||
            size == 0 || size > max_type_size || align == 0 || align > 128 ||
            (align & (align - 1)) != 0) {
            ++skipped_;
            continue;
        }
        auto name = read_name(tag_rva, cancellation);
        if (!name && name.error().code != DebugErrorCode::parse_error) return std::unexpected(name.error());
        if (!name || !printable(*name, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }
        if (name_id(*name) == 0) {
            ++skipped_;
            continue;
        }
        types_[index].name = std::move(*name);
        types_[index].size = size;
        types_[index].base_index = load_u16(record, layout.base_index_offset);
        types_[index].first_attribute = load_u32(record, layout.first_attribute_offset);
        types_[index].attribute_count = load_u32(record, layout.attribute_count_offset);
        if (range_published(request_.attribute_begin_rva, request_.attribute_end_rva)) {
            const auto attributes = (request_.attribute_end_rva - request_.attribute_begin_rva) / layout.attribute_stride;
            if (types_[index].first_attribute > attributes ||
                types_[index].attribute_count > attributes - types_[index].first_attribute) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_attribute_range"));
            }
        }
        types_[index].valid = true;
    }
    return {};
}

Result<void> NativeTypeTableReader::load_enums(const std::stop_token cancellation) {
    const auto& layout = *layout_;
    if (!range_published(request_.enum_begin_rva, request_.enum_end_rva)) return {};
    const auto count = (request_.enum_end_rva - request_.enum_begin_rva) / layout.enum_stride;
    enums_.resize(static_cast<std::size_t>(count));

    std::array<std::byte, record_buffer_bytes> buffer{};
    const auto record = std::span{buffer}.first(layout.enum_stride);
    for (std::size_t index = 0; index < enums_.size(); ++index) {
        if (cancellation.stop_requested()) {
            return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto rva = request_.enum_begin_rva + index * layout.enum_stride;
        if (auto read = read_exact(module_base_ + rva, record, cancellation); !read) {
            return std::unexpected(read.error());
        }
        auto name = read_name_via_pointer(load_u64(record, layout.enum_name_offset), cancellation);
        if (!name && name.error().code != DebugErrorCode::parse_error) return std::unexpected(name.error());
        if (!name || !printable(*name, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }
        const auto values = load_u32(record, layout.enum_count_offset);
        if (values > max_enum_values) {
            ++skipped_;
            continue;
        }
        enums_[index].name = std::move(*name);
        enums_[index].count = values;
        enums_[index].names_address = load_u64(record, layout.enum_names_offset);
        enums_[index].values_address = load_u64(record, layout.enum_values_offset);
        const auto array_bytes = static_cast<std::uint64_t>(values) * 8U;
        if (values != 0 && (!contains(enums_[index].names_address, array_bytes) ||
                            !contains(enums_[index].values_address, array_bytes))) {
            ++skipped_;
            continue;
        }
        enums_[index].valid = true;
    }
    return {};
}

Result<reflection::ReadBoundary> NativeTypeTableReader::begin(
    const reflection::ReflectionLimits& limits, const std::stop_token cancellation) {
    if (state_ != State::idle) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "reader_state"));
    }
    if (cancellation.stop_requested()) {
        return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
    }
    layout_ = find_native_type_table_layout(request_.profile_id);
    if (layout_ == nullptr) {
        return std::unexpected(poison(DebugErrorCode::unsupported, "unsupported_profile"));
    }
    if (limits.max_records == 0 || limits.max_records > 100000 ||
        limits.max_string_bytes == 0 || limits.max_string_bytes > 4096 ||
        limits.max_retained_bytes == 0 || limits.max_retained_bytes > 32U * 1024U * 1024U ||
        request_.max_duration.count() <= 0) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "invalid_reflection_limits"));
    }
    const auto& layout = *layout_;
    if (layout.record_stride == 0 || request_.table_end_rva <= request_.table_begin_rva ||
        (request_.table_end_rva - request_.table_begin_rva) % layout.record_stride != 0 ||
        request_.table_end_rva - request_.table_begin_rva > max_table_span ||
        request_.names_end_rva <= request_.names_begin_rva ||
        request_.module_size == 0 || request_.table_end_rva > request_.module_size ||
        request_.names_end_rva > request_.module_size ||
        !range_usable(request_.attribute_begin_rva, request_.attribute_end_rva,
                      layout.attribute_stride, request_.module_size) ||
        !range_usable(request_.enum_begin_rva, request_.enum_end_rva,
                      layout.enum_stride, request_.module_size) ||
        !range_usable(request_.sli_begin_rva, request_.sli_end_rva,
                      layout.sli_stride, request_.module_size) ||
        !present(request_.module_digest) || !present(request_.profile_digest)) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "invalid_build_profile"));
    }

    auto profile = native_profile_identity(request_);
    if (!profile) return std::unexpected(poison(profile.error().code, "invalid_build_profile"));

    auto snapshot = memory_.snapshot();
    if (!snapshot) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "address_space_unavailable"));
    }
    const domain::ModuleInfo* target = nullptr;
    for (const auto& module : (*snapshot)->modules.all()) {
        if (ascii_equal(module.name, request_.module_name)) {
            target = &module;
            break;
        }
    }
    if (target == nullptr) {
        return std::unexpected(poison(DebugErrorCode::not_found, "module_not_loaded"));
    }
    // The loaded image must match the profile's claim about the build before a
    // single RVA from that profile is trusted.
    if (target->size != request_.module_size) {
        return std::unexpected(poison(DebugErrorCode::unsupported, "profile_mismatch"));
    }
    module_base_ = target->base;
    if (request_.module_size > std::numeric_limits<std::uint64_t>::max() - module_base_) {
        return std::unexpected(poison(DebugErrorCode::invalid_argument, "module_address_overflow"));
    }
    limits_ = limits;
    deadline_ = std::chrono::steady_clock::now() + std::min(request_.max_duration, std::chrono::milliseconds{5000});
    const auto type_count = (request_.table_end_rva - request_.table_begin_rva) / layout.record_stride;
    const auto enum_count = (request_.enum_end_rva - request_.enum_begin_rva) / layout.enum_stride;
    // Bounds precede vector/string allocation. Index estimates include each
    // bounded name's storage in addition to the slot itself.
    if (type_count > index_absent || enum_count > index_absent ||
        type_count + enum_count > limits.max_records ||
        type_count * (sizeof(TypeSlot) + max_type_name_bytes + 1U) +
        enum_count * (sizeof(EnumSlot) + max_type_name_bytes + 1U) > limits.max_retained_bytes) {
        return std::unexpected(poison(DebugErrorCode::limit_exceeded, "index_budget"));
    }

    // Types and enums are resolved up front: a field record has to name the type
    // or enum it points at, and a base link has to name its target, so both
    // tables must be known before the first record leaves the reader.
    if (auto loaded = load_types(cancellation); !loaded) {
        return std::unexpected(poison(loaded.error().code, loaded.error().reason.c_str()));
    }
    if (auto loaded = load_enums(cancellation); !loaded) {
        return std::unexpected(poison(loaded.error().code, loaded.error().reason.c_str()));
    }

    phase_ = Phase::types;
    type_cursor_ = 0;
    attribute_cursor_ = request_.attribute_begin_rva;
    enum_cursor_ = 0;
    enum_value_cursor_ = 0;
    function_cursor_ = request_.sli_begin_rva;
    boundary_ = reflection::ReadBoundary{
        reflection::SnapshotIdentity{*profile, request_.process_instance, request_.bridge_epoch,
                                     request_.generation},
        // Structure and module identity are checked; the loaded image is not
        // attested, so this is never reported as stable.
        reflection::Consistency::validated_best_effort, false};
    state_ = State::reading;
    return boundary_;
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next_type(
    const std::stop_token) {
    while (type_cursor_ < types_.size()) {
        const auto index = type_cursor_++;
        const auto& slot = types_[index];
        if (!slot.valid) continue;

        std::optional<reflection::TypeKey> base;
        if (slot.base_index != index_absent) {
            if (slot.base_index >= types_.size() || !types_[slot.base_index].valid) {
                return std::unexpected(poison(DebugErrorCode::parse_error, "invalid_base_index"));
            }
            base = reflection::TypeKey{name_id(types_[slot.base_index].name)};
        }
        if (auto charged = charge_record(); !charged) {
            return std::unexpected(charged.error());
        }
        ++emitted_types_;
        return std::optional<reflection::ReflectionRecord>{reflection::TypeRecord{
            reflection::TypeKey{name_id(slot.name)}, slot.name, slot.size, base}};
    }
    return std::optional<reflection::ReflectionRecord>{};
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next_field(
    const std::stop_token cancellation) {
    const auto& layout = *layout_;
    if (!range_published(request_.attribute_begin_rva, request_.attribute_end_rva)) {
        return std::optional<reflection::ReflectionRecord>{};
    }
    std::array<std::byte, record_buffer_bytes> buffer{};
    const auto record = std::span{buffer}.first(layout.attribute_stride);

    while (attribute_cursor_ < request_.attribute_end_rva) {
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto rva = attribute_cursor_;
        attribute_cursor_ += layout.attribute_stride;
        if (auto read = read_exact(module_base_ + rva, record, cancellation); !read) {
            return std::unexpected(poison(read.error().code, read.error().reason.c_str()));
        }

        const auto owner_index = load_u16(record, layout.attribute_owner_offset);
        const auto guard = load_u16(record, layout.attribute_guard_offset);
        if (owner_index >= types_.size() || !types_[owner_index].valid) {
            ++skipped_;
            continue;
        }
        const auto& owner = types_[owner_index];
        const auto attribute_index = (rva - request_.attribute_begin_rva) / layout.attribute_stride;
        // Only direct declarations in the owner's own range. Inherited copies
        // and nested views are normal engine metadata, not distinct fields.
        if (guard != index_absent || attribute_index < owner.first_attribute ||
            attribute_index - owner.first_attribute >= owner.attribute_count) continue;
        const auto offset = load_u16(record, layout.attribute_offset_offset);
        // An attribute sitting past the end of its owner is the flattened view
        // of an instance member, addressed in the containing type's frame. The
        // real declaration is reported against the type that owns that frame.
        if (offset >= owner.size) {
            ++skipped_;
            continue;
        }
        auto name = read_name_via_pointer(load_u64(record, layout.attribute_name_offset), cancellation);
        if (!name && name.error().code != DebugErrorCode::parse_error) {
            return std::unexpected(poison(name.error().code, name.error().reason.c_str()));
        }
        if (!name || !printable(*name, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }

        const auto flags = load_u8(record, layout.attribute_flags_offset);
        const auto raw_kind = static_cast<std::uint8_t>(flags >> 2U);
        if (raw_kind > max_attribute_kind) {
            ++skipped_;
            continue;
        }
        const auto kind = static_cast<AttributeKind>(raw_kind);
        const auto custom = load_u16(record, layout.attribute_custom_offset);
        const auto enum_index = load_u16(record, layout.attribute_enum_offset);

        std::optional<reflection::EnumKey> referenced_enum;
        if (enum_index != index_absent &&
            (kind == AttributeKind::integral || kind == AttributeKind::unsigned_integral)) {
            if (enum_index >= enums_.size() || !enums_[enum_index].valid) {
                ++skipped_;
                continue;
            }
            // Enum names are not globally unique in this engine. The exact
            // build's table index supplies identity within the enum key space.
            referenced_enum = reflection::EnumKey{static_cast<std::uint64_t>(enum_index) + 1U};
        }
        std::optional<reflection::TypeKey> referenced_type;
        const auto names_a_type = kind == AttributeKind::pointer ||
            kind == AttributeKind::reference || kind == AttributeKind::class_instance;
        if (names_a_type) {
            if (custom >= types_.size() || !types_[custom].valid) {
                ++skipped_;
                continue;
            }
            referenced_type = reflection::TypeKey{name_id(types_[custom].name)};
        }

        std::uint64_t size = load_u16(record, layout.attribute_size_offset);
        // An instance member carries no size of its own; it is the size of the
        // type it embeds.
        if (kind == AttributeKind::class_instance && custom < types_.size() &&
            types_[custom].valid) {
            size = types_[custom].size;
        }

        if (size == 0 || size > owner.size - offset ||
            (to_field_kind(kind, referenced_enum.has_value()) == reflection::FieldKind::pointer && size != 8)) {
            ++skipped_;
            continue;
        }

        if (auto charged = charge_record(); !charged) {
            return std::unexpected(charged.error());
        }
        ++emitted_fields_;
        return std::optional<reflection::ReflectionRecord>{reflection::FieldRecord{
            reflection::TypeKey{name_id(owner.name)}, std::move(*name), offset, size,
            to_field_kind(kind, referenced_enum.has_value()), referenced_type, referenced_enum}};
    }
    return std::optional<reflection::ReflectionRecord>{};
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next_enum(
    const std::stop_token) {
    while (enum_cursor_ < enums_.size()) {
        const auto index = enum_cursor_++;
        if (!enums_[index].valid) continue;
        if (auto charged = charge_record(); !charged) {
            return std::unexpected(charged.error());
        }
        ++emitted_enums_;
        return std::optional<reflection::ReflectionRecord>{reflection::EnumRecord{
            reflection::EnumKey{static_cast<std::uint64_t>(index) + 1U}, enums_[index].name}};
    }
    return std::optional<reflection::ReflectionRecord>{};
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next_enum_value(
    const std::stop_token cancellation) {
    while (enum_cursor_ < enums_.size()) {
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto& slot = enums_[enum_cursor_];
        if (!slot.valid || enum_value_cursor_ >= slot.count) {
            ++enum_cursor_;
            enum_value_cursor_ = 0;
            continue;
        }
        const auto slot_index = enum_value_cursor_++;

        std::array<std::byte, 8> pointer_bytes{};
        const auto name_slot = slot.names_address + static_cast<std::uint64_t>(slot_index) * 8;
        if (auto read = read_exact(name_slot, pointer_bytes, cancellation); !read) {
            return std::unexpected(poison(read.error().code, read.error().reason.c_str()));
        }
        auto name = read_name_via_pointer(load_u64(pointer_bytes, 0), cancellation);
        if (!name && name.error().code != DebugErrorCode::parse_error) {
            return std::unexpected(poison(name.error().code, name.error().reason.c_str()));
        }
        if (!name || !printable(*name, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }

        std::uint64_t value = 0;
        if (slot.values_address != 0) {
            std::array<std::byte, 8> value_bytes{};
            const auto value_slot = slot.values_address + static_cast<std::uint64_t>(slot_index) * 8;
            if (auto read = read_exact(value_slot, value_bytes, cancellation); !read) {
                return std::unexpected(poison(read.error().code, read.error().reason.c_str()));
            }
            value = load_u64(value_bytes, 0);
        }

        if (auto charged = charge_record(); !charged) {
            return std::unexpected(charged.error());
        }
        return std::optional<reflection::ReflectionRecord>{reflection::EnumValueRecord{
            reflection::EnumKey{static_cast<std::uint64_t>(enum_cursor_) + 1U}, std::move(*name), std::to_string(value)}};
    }
    return std::optional<reflection::ReflectionRecord>{};
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next_function(
    const std::stop_token cancellation) {
    const auto& layout = *layout_;
    if (!range_published(request_.sli_begin_rva, request_.sli_end_rva)) {
        return std::optional<reflection::ReflectionRecord>{};
    }
    std::array<std::byte, record_buffer_bytes> buffer{};
    const auto record = std::span{buffer}.first(layout.sli_stride);

    while (function_cursor_ < request_.sli_end_rva) {
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto rva = function_cursor_;
        function_cursor_ += layout.sli_stride;
        if (auto read = read_exact(module_base_ + rva, record, cancellation); !read) {
            return std::unexpected(poison(read.error().code, read.error().reason.c_str()));
        }
        // The profile supplies the exact range: a bad callback invalidates a
        // slot, never silently truncates all subsequent declarations.
        if (!contains(load_u64(record, layout.sli_callback_offset), 1)) {
            ++skipped_;
            continue;
        }
        auto name = read_name_via_pointer(load_u64(record, layout.sli_name_offset), cancellation);
        if (!name && name.error().code != DebugErrorCode::parse_error) {
            return std::unexpected(poison(name.error().code, name.error().reason.c_str()));
        }
        if (!name || !printable(*name, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }
        auto signature = read_name_via_pointer(load_u64(record, layout.sli_signature_offset), cancellation);
        if (!signature && signature.error().code != DebugErrorCode::parse_error) {
            return std::unexpected(poison(signature.error().code, signature.error().reason.c_str()));
        }
        if (!signature || !printable(*signature, std::min(max_type_name_bytes, limits_.max_string_bytes))) {
            ++skipped_;
            continue;
        }

        if (auto charged = charge_record(); !charged) {
            return std::unexpected(charged.error());
        }
        ++emitted_functions_;
        return std::optional<reflection::ReflectionRecord>{reflection::SliFunctionRecord{
            reflection::FunctionKey{name_id(*name)}, std::move(*name), std::move(*signature)}};
    }
    return std::optional<reflection::ReflectionRecord>{};
}

Result<std::optional<reflection::ReflectionRecord>> NativeTypeTableReader::next(
    const std::stop_token cancellation) {
    if (state_ != State::reading) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "reader_state"));
    }
    while (phase_ != Phase::done) {
        if (auto ready = check_work(cancellation); !ready) return std::unexpected(ready.error());
        if (cancellation.stop_requested()) {
            return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        Result<std::optional<reflection::ReflectionRecord>> produced =
            std::optional<reflection::ReflectionRecord>{};
        switch (phase_) {
            case Phase::types:
                produced = next_type(cancellation);
                break;
            case Phase::fields:
                produced = next_field(cancellation);
                break;
            case Phase::enums:
                produced = next_enum(cancellation);
                break;
            case Phase::enum_values:
                produced = next_enum_value(cancellation);
                break;
            case Phase::functions:
                produced = next_function(cancellation);
                break;
            case Phase::done:
                break;
        }
        if (!produced) return std::unexpected(produced.error());
        if (produced->has_value()) return produced;

        switch (phase_) {
            case Phase::types:
                phase_ = Phase::fields;
                break;
            case Phase::fields:
                phase_ = Phase::enums;
                break;
            case Phase::enums:
                // Values replay the enum table, so the cursor restarts.
                phase_ = Phase::enum_values;
                enum_cursor_ = 0;
                enum_value_cursor_ = 0;
                break;
            case Phase::enum_values:
                phase_ = Phase::functions;
                break;
            case Phase::functions:
            case Phase::done:
                phase_ = Phase::done;
                break;
        }
    }
    state_ = State::ended;
    return std::optional<reflection::ReflectionRecord>{};
}

Result<reflection::ReadBoundary> NativeTypeTableReader::finish(const std::stop_token cancellation) {
    if (state_ != State::ended) {
        return std::unexpected(poison(DebugErrorCode::invalid_state, "reader_state"));
    }
    if (cancellation.stop_requested()) {
        return std::unexpected(poison(DebugErrorCode::cancelled, "operation_cancelled"));
    }
    if (auto ready = check_work(cancellation); !ready) return std::unexpected(ready.error());
    // Auxiliary collection tables and SLI properties are outside this reader.
    boundary_.coverage_complete = false;
    return boundary_;
}

}  // namespace argos::infrastructure::santamonica
