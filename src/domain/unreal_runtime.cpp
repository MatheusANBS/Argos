#include "argos_mcp/domain/unreal_runtime.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace argos::domain {
namespace {

[[nodiscard]] DebugError error(const DebugErrorCode code, std::string message) {
    return DebugError{code, std::move(message)};
}

[[nodiscard]] std::uint64_t mix(std::uint64_t seed, const std::uint64_t value) noexcept {
    seed ^= value + 0x9E3779B97F4A7C15ULL + (seed << 6U) + (seed >> 2U);
    return seed;
}

[[nodiscard]] std::uint64_t decode_le(const std::span<const std::byte> bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size() && index < 8U; ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[index])) << (index * 8U);
    }
    return value;
}

// Names come from a process that may be hostile or simply corrupt. They are
// forwarded to a JSON transport and to the operator's screen, so only printable
// ASCII survives: anything else becomes '?' rather than a control character or
// an invalid UTF-8 sequence in the protocol stream.
void append_sanitized(std::string& output, const std::uint32_t code_point) {
    const bool printable = code_point >= 0x20U && code_point < 0x7FU;
    output.push_back(printable ? static_cast<char>(code_point) : '?');
}

// The engine's own limits, used to reject a hostile count before it can size a
// read or an allocation.
constexpr std::uint32_t max_reasonable_elements = 64U * 1024U * 1024U;
constexpr std::uint32_t max_reasonable_chunks = 64U * 1024U;
constexpr std::size_t max_item_run_bytes = 64U * 1024U;

// A sweep decodes one UObject header and one property node at a time. Both are
// profile-sized records of a few dozen bytes, so they live on the stack: a heap
// allocation per live slot would dominate a million-slot sweep. Profiles are
// authored here, never supplied by a client, so the bound is a build-time fact.
constexpr std::size_t max_structure_bytes = 256U;

[[nodiscard]] UnrealRuntimeProfile make_ue5_fproperty_profile() {
    UnrealRuntimeProfile profile;
    profile.id = "ue5-fproperty-x64";
    profile.engine_family = "UnrealEngine5";
    profile.pointer_size = 8U;
    profile.fname = FNameLayout{8U, 0U, 4U};

    profile.object_array = ObjectArrayLayout{
        0x10U,        // FUObjectArray::ObjObjects.Objects
        0x20U,        // MaxElements
        0x24U,        // NumElements
        0x28U,        // MaxChunks
        0x2CU,        // NumChunks
        64U * 1024U,  // NumElementsPerChunk
        0x18U,        // sizeof(FUObjectItem)
        0x00U,        // FUObjectItem::Object
        0x08U,        // FUObjectItem::Flags
        0x10U         // FUObjectItem::SerialNumber
    };

    profile.name_pool = NamePoolLayout{};
    profile.name_pool.kind = NamePoolKind::block_pool;
    profile.name_pool.blocks_offset = 0x10U;  // FNameEntryAllocator::Blocks
    profile.name_pool.block_index_shift = 16U;
    profile.name_pool.block_offset_mask = 0xFFFFU;
    profile.name_pool.block_offset_stride = 2U;
    profile.name_pool.max_blocks = 8192U;
    profile.name_pool.header_size = 2U;
    profile.name_pool.wide_mask = 0x1U;
    profile.name_pool.length_shift = 6U;
    profile.name_pool.length_mask = 0x3FFU;

    profile.uobject = UObjectLayout{0x08U, 0x0CU, 0x10U, 0x18U, 0x20U, 0x28U};
    profile.ustruct = UStructLayout{0x40U, 0x48U, 0x50U, 0x58U, 0x60U};

    profile.property = PropertyLayout{};
    profile.property.kind = PropertyChainKind::field_chain;
    profile.property.class_offset = 0x08U;            // FField::ClassPrivate
    profile.property.next_offset = 0x20U;             // FField::Next
    profile.property.name_offset = 0x28U;             // FField::NamePrivate
    profile.property.array_dim_offset = 0x38U;
    profile.property.element_size_offset = 0x3CU;
    profile.property.flags_offset = 0x40U;
    profile.property.offset_internal_offset = 0x4CU;
    profile.property.min_size = 0x50U;
    profile.property.class_name_offset = 0x00U;       // FFieldClass::Name
    return profile;
}

[[nodiscard]] UnrealRuntimeProfile make_ue4_uproperty_profile() {
    UnrealRuntimeProfile profile;
    profile.id = "ue4-uproperty-x64";
    profile.engine_family = "UnrealEngine4";
    profile.pointer_size = 8U;
    profile.fname = FNameLayout{8U, 0U, 4U};

    profile.object_array = ObjectArrayLayout{
        0x10U, 0x20U, 0x24U, 0x28U, 0x2CU, 16U * 1024U, 0x18U, 0x00U, 0x08U, 0x10U
    };

    profile.name_pool = NamePoolLayout{};
    profile.name_pool.kind = NamePoolKind::legacy_chunked_array;
    profile.name_pool.blocks_offset = 0x00U;
    profile.name_pool.legacy_elements_per_chunk = 16384U;
    profile.name_pool.legacy_chunk_count = 128U;
    profile.name_pool.legacy_entry_index_offset = 0x00U;
    profile.name_pool.legacy_entry_name_offset = 0x10U;
    profile.name_pool.legacy_wide_mask = 0x1U;

    profile.uobject = UObjectLayout{0x08U, 0x0CU, 0x10U, 0x18U, 0x20U, 0x28U};
    // No FStructBaseChain in this family, so UStruct starts right after
    // UField::Next.
    profile.ustruct = UStructLayout{0x30U, 0x38U, 0U, 0x40U, 0x48U};

    profile.property = PropertyLayout{};
    profile.property.kind = PropertyChainKind::uobject_chain;
    profile.property.class_offset = 0x10U;      // UObject::ClassPrivate
    profile.property.next_offset = 0x28U;       // UField::Next
    profile.property.name_offset = 0x18U;       // UObject::NamePrivate
    profile.property.array_dim_offset = 0x30U;
    profile.property.element_size_offset = 0x34U;
    profile.property.flags_offset = 0x38U;
    profile.property.offset_internal_offset = 0x44U;
    profile.property.min_size = 0x48U;
    profile.property.class_name_offset = 0x18U;  // UClass is a UObject
    return profile;
}

[[nodiscard]] const std::vector<UnrealRuntimeProfile>& profile_registry() {
    static const std::vector<UnrealRuntimeProfile> profiles{
        make_ue5_fproperty_profile(),
        make_ue4_uproperty_profile()
    };
    return profiles;
}

}  // namespace

std::string_view to_string(const DiscoveryMode mode) noexcept {
    switch (mode) {
        case DiscoveryMode::explicit_roots: return "explicit";
        case DiscoveryMode::build_profile: return "profile";
        case DiscoveryMode::auto_discovery: return "auto";
    }
    return "explicit";
}

std::string_view to_string(const RootOrigin origin) noexcept {
    switch (origin) {
        case RootOrigin::explicit_rva: return "explicit_rva";
        case RootOrigin::explicit_address: return "explicit_address";
        case RootOrigin::build_profile: return "build_profile";
        case RootOrigin::signature_candidate: return "signature_candidate";
    }
    return "explicit_address";
}

std::string_view to_string(const RuntimeConfidence confidence) noexcept {
    switch (confidence) {
        case RuntimeConfidence::low: return "low";
        case RuntimeConfidence::medium: return "medium";
        case RuntimeConfidence::high: return "high";
    }
    return "low";
}

std::string_view to_string(const SnapshotStatus status) noexcept {
    switch (status) {
        case SnapshotStatus::stable: return "stable";
        case SnapshotStatus::unstable: return "unstable";
        case SnapshotStatus::stale: return "stale";
    }
    return "stable";
}

std::string_view to_string(const RuntimeEvidence evidence) noexcept {
    switch (evidence) {
        case RuntimeEvidence::module_fingerprint: return "module_fingerprint";
        case RuntimeEvidence::root_within_module: return "root_within_module";
        case RuntimeEvidence::object_array_invariants: return "object_array_invariants";
        case RuntimeEvidence::name_pool_invariants: return "name_pool_invariants";
        case RuntimeEvidence::class_sample_validated: return "class_sample_validated";
        case RuntimeEvidence::property_sample_validated: return "property_sample_validated";
        case RuntimeEvidence::signature_match: return "signature_match";
    }
    return "unknown";
}

std::string_view to_string(const RuntimeInvariant invariant) noexcept {
    switch (invariant) {
        case RuntimeInvariant::root_alignment: return "root_alignment";
        case RuntimeInvariant::root_region: return "root_region";
        case RuntimeInvariant::object_array_counts: return "object_array_counts";
        case RuntimeInvariant::object_array_chunks: return "object_array_chunks";
        case RuntimeInvariant::slot_sample: return "slot_sample";
        case RuntimeInvariant::name_pool_bounds: return "name_pool_bounds";
        case RuntimeInvariant::name_length: return "name_length";
        case RuntimeInvariant::class_name: return "class_name";
        case RuntimeInvariant::super_chain_acyclic: return "super_chain_acyclic";
        case RuntimeInvariant::property_chain_acyclic: return "property_chain_acyclic";
        case RuntimeInvariant::property_bounds: return "property_bounds";
    }
    return "unknown";
}

std::optional<DiscoveryMode> discovery_mode_from_string(const std::string_view text) noexcept {
    if (text == "explicit") return DiscoveryMode::explicit_roots;
    if (text == "profile") return DiscoveryMode::build_profile;
    if (text == "auto") return DiscoveryMode::auto_discovery;
    return std::nullopt;
}

std::span<const UnrealRuntimeProfile> builtin_unreal_profiles() noexcept {
    const auto& profiles = profile_registry();
    return {profiles.data(), profiles.size()};
}

const UnrealRuntimeProfile* find_unreal_profile(const std::string_view id) noexcept {
    for (const auto& profile : profile_registry()) {
        if (profile.id == id) {
            return &profile;
        }
    }
    return nullptr;
}

UnrealRuntimeReader::UnrealRuntimeReader(
    const RuntimeMemoryView& view,
    std::shared_ptr<const RuntimeAddressSpaceSnapshot> snapshot,
    const UnrealRuntimeProfile& profile,
    RuntimeLimits limits,
    UnrealRuntimeRoots roots
) : view_(view), snapshot_(std::move(snapshot)), profile_(profile),
    limits_(limits), roots_(roots) {}

bool UnrealRuntimeReader::readable_range(const Address address, const std::uint64_t size) const noexcept {
    if (size == 0U || snapshot_ == nullptr) {
        return false;
    }
    const auto end = checked_add(address, size);
    if (!end) {
        return false;
    }
    const auto* region = snapshot_->regions.find(address);
    // A range that spills into the next mapping is rejected rather than split:
    // adjacency in the map does not imply the target keeps one object there.
    return region != nullptr && region->readable && *end <= region->end;
}

bool UnrealRuntimeReader::aligned_pointer(const Address value) const noexcept {
    return value != 0U && (value % profile_.pointer_size) == 0U;
}

Result<void> UnrealRuntimeReader::read_exact(
    const Address address,
    const std::span<std::byte> destination,
    const std::stop_token cancellation
) const {
    if (cancellation.stop_requested()) {
        return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
    }
    if (!readable_range(address, destination.size())) {
        return std::unexpected(error(DebugErrorCode::io_error, "address is outside a readable region"));
    }
    auto read = view_.read(address, destination, cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    if (*read != destination.size()) {
        // A short read is evidence that the mapping changed under us, never a
        // reason to treat the missing tail as zero bytes.
        return std::unexpected(error(DebugErrorCode::io_error, "short_read"));
    }
    return {};
}

Result<std::uint32_t> UnrealRuntimeReader::read_u32(
    const Address address,
    const std::stop_token cancellation
) const {
    std::array<std::byte, 4> bytes{};
    auto read = read_exact(address, bytes, cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    return static_cast<std::uint32_t>(decode_le(bytes));
}

Result<std::uint64_t> UnrealRuntimeReader::read_u64(
    const Address address,
    const std::stop_token cancellation
) const {
    std::array<std::byte, 8> bytes{};
    auto read = read_exact(address, bytes, cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    return decode_le(bytes);
}

Result<Address> UnrealRuntimeReader::read_pointer(
    const Address address,
    const std::stop_token cancellation
) const {
    std::array<std::byte, 8> bytes{};
    auto read = read_exact(address, std::span<std::byte>{bytes}.first(profile_.pointer_size), cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    return static_cast<Address>(decode_le(std::span<const std::byte>{bytes}.first(profile_.pointer_size)));
}

Result<std::string> UnrealRuntimeReader::read_name(
    const std::uint32_t index,
    const std::stop_token cancellation
) const {
    const auto& layout = profile_.name_pool;
    std::string name;

    if (layout.kind == NamePoolKind::block_pool) {
        const std::uint32_t block = index >> layout.block_index_shift;
        const std::uint64_t offset =
            static_cast<std::uint64_t>(index & layout.block_offset_mask) * layout.block_offset_stride;
        if (block >= layout.max_blocks) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "name index outside the pool"));
        }
        const auto slot = checked_add(
            roots_.fname_pool,
            static_cast<std::uint64_t>(layout.blocks_offset) +
                static_cast<std::uint64_t>(block) * profile_.pointer_size
        );
        if (!slot) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "name pool address overflow"));
        }
        auto block_base = read_pointer(*slot, cancellation);
        if (!block_base) {
            return std::unexpected(block_base.error());
        }
        if (!aligned_pointer(*block_base)) {
            return std::unexpected(error(DebugErrorCode::io_error, "name block pointer is not usable"));
        }
        const auto entry = checked_add(*block_base, offset);
        if (!entry) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "name entry address overflow"));
        }

        std::array<std::byte, 4> header_bytes{};
        auto header_read = read_exact(
            *entry, std::span<std::byte>{header_bytes}.first(layout.header_size), cancellation
        );
        if (!header_read) {
            return std::unexpected(header_read.error());
        }
        const auto header = static_cast<std::uint32_t>(
            decode_le(std::span<const std::byte>{header_bytes}.first(layout.header_size))
        );
        const bool wide = (header & layout.wide_mask) != 0U;
        const std::uint32_t length = (header >> layout.length_shift) & layout.length_mask;
        const std::uint64_t byte_count = static_cast<std::uint64_t>(length) * (wide ? 2U : 1U);
        if (byte_count > limits_.max_name_bytes) {
            return std::unexpected(error(DebugErrorCode::limit_exceeded, "name exceeds the configured length limit"));
        }
        if (length == 0U) {
            return name;
        }
        const auto text_address = checked_add(*entry, layout.header_size);
        if (!text_address) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "name text address overflow"));
        }
        std::vector<std::byte> text(static_cast<std::size_t>(byte_count));
        auto text_read = read_exact(*text_address, text, cancellation);
        if (!text_read) {
            return std::unexpected(text_read.error());
        }
        name.reserve(length);
        for (std::uint32_t character = 0; character < length; ++character) {
            const auto code = wide
                ? static_cast<std::uint32_t>(decode_le(
                      std::span<const std::byte>{text}.subspan(static_cast<std::size_t>(character) * 2U, 2U)))
                : static_cast<std::uint32_t>(std::to_integer<unsigned int>(text[character]));
            append_sanitized(name, code);
        }
        return name;
    }

    // Legacy chunked array: a table of chunk pointers, each chunk a table of
    // FNameEntry pointers.
    const std::uint32_t chunk = index / layout.legacy_elements_per_chunk;
    const std::uint32_t within = index % layout.legacy_elements_per_chunk;
    if (layout.legacy_chunk_count != 0U && chunk >= layout.legacy_chunk_count) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "name index outside the pool"));
    }
    const auto chunk_slot = checked_add(
        roots_.fname_pool,
        static_cast<std::uint64_t>(layout.blocks_offset) +
            static_cast<std::uint64_t>(chunk) * profile_.pointer_size
    );
    if (!chunk_slot) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "name pool address overflow"));
    }
    auto chunk_base = read_pointer(*chunk_slot, cancellation);
    if (!chunk_base || !aligned_pointer(*chunk_base)) {
        return std::unexpected(error(DebugErrorCode::io_error, "name chunk pointer is not usable"));
    }
    const auto entry_slot = checked_add(
        *chunk_base, static_cast<std::uint64_t>(within) * profile_.pointer_size
    );
    if (!entry_slot) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "name entry address overflow"));
    }
    auto entry = read_pointer(*entry_slot, cancellation);
    if (!entry || !aligned_pointer(*entry)) {
        return std::unexpected(error(DebugErrorCode::io_error, "name entry pointer is not usable"));
    }
    auto index_field = read_u32(
        checked_add(*entry, layout.legacy_entry_index_offset).value_or(0U), cancellation
    );
    if (!index_field) {
        return std::unexpected(index_field.error());
    }
    const bool wide = (*index_field & layout.legacy_wide_mask) != 0U;
    const auto text_address = checked_add(*entry, layout.legacy_entry_name_offset);
    if (!text_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "name text address overflow"));
    }

    // NUL-terminated in this family, so the length limit is what stops the read
    // rather than a stored length.
    const std::size_t unit = wide ? 2U : 1U;
    name.reserve(32U);
    for (std::size_t position = 0; position * unit < limits_.max_name_bytes; ++position) {
        std::array<std::byte, 2> unit_bytes{};
        const auto unit_address = checked_add(*text_address, position * unit);
        if (!unit_address) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "name text address overflow"));
        }
        auto unit_read = read_exact(*unit_address, std::span<std::byte>{unit_bytes}.first(unit), cancellation);
        if (!unit_read) {
            return std::unexpected(unit_read.error());
        }
        const auto code = static_cast<std::uint32_t>(
            decode_le(std::span<const std::byte>{unit_bytes}.first(unit))
        );
        if (code == 0U) {
            return name;
        }
        append_sanitized(name, code);
    }
    return std::unexpected(error(DebugErrorCode::limit_exceeded, "name exceeds the configured length limit"));
}

Result<std::string> UnrealRuntimeReader::read_name_at(
    const Address address,
    const std::stop_token cancellation
) const {
    const auto index_address = checked_add(address, profile_.fname.index_offset);
    if (!index_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "name field address overflow"));
    }
    auto index = read_u32(*index_address, cancellation);
    if (!index) {
        return std::unexpected(index.error());
    }
    return read_name(*index, cancellation);
}

Result<ObjectArrayHeader> UnrealRuntimeReader::read_object_array_header(
    const std::stop_token cancellation
) const {
    const auto& layout = profile_.object_array;
    const auto chunks_address = checked_add(roots_.gu_object_array, layout.chunks_pointer_offset);
    if (!chunks_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "object array address overflow"));
    }
    auto chunks = read_pointer(*chunks_address, cancellation);
    if (!chunks) {
        return std::unexpected(chunks.error());
    }
    ObjectArrayHeader header;
    header.chunks = *chunks;

    const std::array<std::pair<std::uint32_t, std::uint32_t*>, 4> fields{{
        {layout.max_elements_offset, &header.max_elements},
        {layout.num_elements_offset, &header.num_elements},
        {layout.max_chunks_offset, &header.max_chunks},
        {layout.num_chunks_offset, &header.num_chunks}
    }};
    for (const auto& [offset, target] : fields) {
        const auto field_address = checked_add(roots_.gu_object_array, offset);
        if (!field_address) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "object array address overflow"));
        }
        auto value = read_u32(*field_address, cancellation);
        if (!value) {
            return std::unexpected(value.error());
        }
        *target = *value;
    }
    return header;
}

Result<Address> UnrealRuntimeReader::chunk_base(
    const ObjectArrayHeader& header,
    const std::uint64_t chunk,
    const std::stop_token cancellation
) const {
    if (chunk >= header.num_chunks) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "chunk index outside the array"));
    }
    const auto slot = checked_add(header.chunks, chunk * profile_.pointer_size);
    if (!slot) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "chunk table address overflow"));
    }
    auto base = read_pointer(*slot, cancellation);
    if (!base) {
        return std::unexpected(base.error());
    }
    if (!aligned_pointer(*base)) {
        return std::unexpected(error(DebugErrorCode::io_error, "chunk pointer is not usable"));
    }
    return *base;
}

Result<std::uint64_t> UnrealRuntimeReader::read_item_run(
    const ObjectArrayHeader& header,
    const std::uint64_t first_slot,
    const std::uint64_t slot_count,
    std::vector<std::byte>& buffer,
    const std::stop_token cancellation
) const {
    const auto& layout = profile_.object_array;
    if (slot_count == 0U) {
        buffer.clear();
        return 0U;
    }
    const std::uint64_t chunk = first_slot / layout.elements_per_chunk;
    const std::uint64_t within = first_slot % layout.elements_per_chunk;
    if (within + slot_count > layout.elements_per_chunk) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "item run crosses a chunk boundary"));
    }
    const std::uint64_t byte_count = slot_count * layout.item_size;
    if (byte_count > max_item_run_bytes) {
        return std::unexpected(error(DebugErrorCode::limit_exceeded, "item run exceeds the read limit"));
    }
    auto base = chunk_base(header, chunk, cancellation);
    if (!base) {
        return std::unexpected(base.error());
    }
    const auto run_address = checked_add(*base, within * layout.item_size);
    if (!run_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "item address overflow"));
    }
    buffer.assign(static_cast<std::size_t>(byte_count), std::byte{0});
    auto read = read_exact(*run_address, buffer, cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }

    std::uint64_t digest = 0xCBF29CE484222325ULL;
    for (std::uint64_t index = 0; index < slot_count; ++index) {
        const auto item = std::span<const std::byte>{buffer}.subspan(
            static_cast<std::size_t>(index * layout.item_size), layout.item_size
        );
        const auto object = decode_le(item.subspan(layout.item_object_offset, profile_.pointer_size));
        const auto serial = static_cast<std::uint32_t>(decode_le(item.subspan(layout.item_serial_offset, 4U)));
        digest = mix(digest, first_slot + index);
        digest = mix(digest, object);
        digest = mix(digest, serial);
    }
    return digest;
}

Result<std::optional<ObjectSlot>> UnrealRuntimeReader::decode_slot(
    const std::span<const std::byte> item_bytes,
    const std::uint64_t slot_index,
    const std::stop_token cancellation
) const {
    const auto& layout = profile_.object_array;
    if (item_bytes.size() < layout.item_size) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "item buffer is too small"));
    }
    const auto object = static_cast<Address>(
        decode_le(item_bytes.subspan(layout.item_object_offset, profile_.pointer_size))
    );
    if (object == 0U) {
        return std::optional<ObjectSlot>{};
    }
    if (!aligned_pointer(object) || !readable_range(object, profile_.uobject.min_size)) {
        // Structurally impossible slot: reported as not live rather than as an
        // object whose fields would be read out of an unmapped page.
        return std::optional<ObjectSlot>{};
    }

    ObjectSlot slot;
    slot.slot_index = slot_index;
    slot.object_address = object;
    slot.serial = static_cast<std::uint32_t>(decode_le(item_bytes.subspan(layout.item_serial_offset, 4U)));

    const auto& uobject = profile_.uobject;
    if (uobject.min_size > max_structure_bytes) {
        return std::unexpected(error(DebugErrorCode::unsupported, "profile object size is out of range"));
    }
    std::array<std::byte, max_structure_bytes> storage{};
    const auto object_header = std::span<std::byte>{storage}.first(uobject.min_size);
    auto read = read_exact(object, object_header, cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    const std::span<const std::byte> header{object_header};
    slot.object_index = static_cast<std::int32_t>(
        decode_le(header.subspan(uobject.index_offset, 4U))
    );
    slot.class_address = static_cast<Address>(
        decode_le(header.subspan(uobject.class_offset, profile_.pointer_size))
    );
    slot.name_index = static_cast<std::uint32_t>(decode_le(
        header.subspan(static_cast<std::size_t>(uobject.name_offset) + profile_.fname.index_offset, 4U)
    ));
    const auto outer = static_cast<Address>(
        decode_le(header.subspan(uobject.outer_offset, profile_.pointer_size))
    );
    if (outer != 0U) {
        slot.outer_address = outer;
    }
    return std::optional<ObjectSlot>{slot};
}

Result<std::optional<ObjectSlot>> UnrealRuntimeReader::read_slot(
    const ObjectArrayHeader& header,
    const std::uint64_t index,
    const std::stop_token cancellation
) const {
    std::vector<std::byte> buffer;
    auto digest = read_item_run(header, index, 1U, buffer, cancellation);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return decode_slot(buffer, index, cancellation);
}

Result<ObjectArrayHeader> UnrealRuntimeReader::read_checked_header(const std::stop_token cancellation) const {
    if (!aligned_pointer(roots_.gu_object_array) || !aligned_pointer(roots_.fname_pool)) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "roots are not pointer aligned"));
    }
    const auto& layout = profile_.object_array;
    if (!readable_range(roots_.gu_object_array, layout.num_chunks_offset + 4U) ||
        !readable_range(roots_.fname_pool, profile_.pointer_size)) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "roots are outside a readable region"));
    }

    auto header = read_object_array_header(cancellation);
    if (!header) {
        return std::unexpected(header.error());
    }

    // Counts drive every later loop and read size, so they are checked before
    // anything is reserved or swept.
    const bool counts_sane = header->num_elements <= header->max_elements &&
        header->max_elements <= max_reasonable_elements &&
        header->num_chunks <= header->max_chunks &&
        header->max_chunks <= max_reasonable_chunks &&
        layout.elements_per_chunk != 0U &&
        static_cast<std::uint64_t>(header->max_chunks) * layout.elements_per_chunk >= header->max_elements;
    if (!counts_sane) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "object array counts are inconsistent"));
    }
    if (!aligned_pointer(header->chunks) ||
        !readable_range(header->chunks, static_cast<std::uint64_t>(header->num_chunks) * profile_.pointer_size)) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "chunk table is not usable"));
    }
    return *header;
}

Result<RootValidation> UnrealRuntimeReader::validate_roots(const std::stop_token cancellation) const {
    RootValidation validation;

    auto header = read_checked_header(cancellation);
    if (!header) {
        validation.failed_invariants.push_back(RuntimeInvariant::object_array_counts);
        return std::unexpected(header.error());
    }
    validation.header = *header;
    validation.evidence.push_back(RuntimeEvidence::object_array_invariants);

    // Bounded sample of live slots. A sample failure lowers confidence and is
    // reported; it does not fabricate a valid context.
    const auto sample_limit = std::min<std::uint64_t>(
        limits_.validation_sample_slots, header->num_elements
    );
    bool names_resolved = false;
    bool class_resolved = false;
    bool properties_resolved = false;
    for (std::uint64_t index = 0; index < sample_limit; ++index) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
        }
        auto slot = read_slot(*header, index, cancellation);
        if (!slot) {
            continue;
        }
        ++validation.sampled_slots;
        if (!slot->has_value()) {
            continue;
        }
        const auto& live = **slot;
        if (live.object_index != static_cast<std::int32_t>(index)) {
            continue;
        }
        if (!aligned_pointer(live.class_address) ||
            !readable_range(live.class_address, profile_.ustruct.min_size)) {
            continue;
        }
        ++validation.valid_slots;

        if (!names_resolved) {
            auto name = read_name(live.name_index, cancellation);
            if (name) {
                names_resolved = true;
            }
        }
        if (!class_resolved) {
            auto summary = read_class_identity(live.class_address, cancellation);
            if (summary && !summary->name.empty()) {
                class_resolved = true;
                if (!properties_resolved) {
                    auto properties = read_declared_properties(
                        live.class_address, limits_.max_properties_per_type, cancellation
                    );
                    properties_resolved = properties.has_value();
                }
            }
        }
    }

    if (validation.valid_slots == 0U && header->num_elements != 0U) {
        validation.failed_invariants.push_back(RuntimeInvariant::slot_sample);
        return std::unexpected(error(DebugErrorCode::invalid_argument, "no sampled slot matched the profile"));
    }
    if (names_resolved) {
        validation.evidence.push_back(RuntimeEvidence::name_pool_invariants);
    } else {
        validation.failed_invariants.push_back(RuntimeInvariant::name_pool_bounds);
    }
    if (class_resolved) {
        validation.evidence.push_back(RuntimeEvidence::class_sample_validated);
    } else {
        validation.failed_invariants.push_back(RuntimeInvariant::class_name);
    }
    if (properties_resolved) {
        validation.evidence.push_back(RuntimeEvidence::property_sample_validated);
    }
    if (roots_.origin == RootOrigin::explicit_rva || roots_.origin == RootOrigin::build_profile) {
        validation.evidence.push_back(RuntimeEvidence::root_within_module);
    }

    // high needs the roots bound to a module *and* every optional sample to
    // have passed. A signature candidate never reaches it in this release.
    const bool bound_to_module = roots_.origin == RootOrigin::explicit_rva ||
        roots_.origin == RootOrigin::build_profile;
    if (validation.failed_invariants.empty() && names_resolved && class_resolved &&
        properties_resolved && bound_to_module) {
        validation.confidence = RuntimeConfidence::high;
    } else if (names_resolved && class_resolved) {
        validation.confidence = RuntimeConfidence::medium;
    } else {
        validation.confidence = RuntimeConfidence::low;
    }
    return validation;
}

Result<UnrealClassSummary> UnrealRuntimeReader::read_class_summary(
    const Address class_address,
    const std::stop_token cancellation
) const {
    auto summary = read_class_identity(class_address, cancellation);
    if (!summary) {
        return std::unexpected(summary.error());
    }
    auto properties = read_declared_properties(class_address, limits_.max_properties_per_type, cancellation);
    if (!properties) {
        return std::unexpected(properties.error());
    }
    summary->property_count = properties->size();
    return summary;
}

Result<UnrealClassSummary> UnrealRuntimeReader::read_class_identity(
    const Address class_address,
    const std::stop_token cancellation
) const {
    if (!aligned_pointer(class_address) || !readable_range(class_address, profile_.ustruct.min_size)) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "class address is not usable"));
    }
    UnrealClassSummary summary;
    summary.class_address = class_address;

    const auto name_address = checked_add(class_address, profile_.uobject.name_offset);
    if (!name_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "class name address overflow"));
    }
    auto name = read_name_at(*name_address, cancellation);
    if (!name) {
        return std::unexpected(name.error());
    }
    summary.name = std::move(*name);

    const auto super_address = checked_add(class_address, profile_.ustruct.super_offset);
    if (!super_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "super address overflow"));
    }
    auto super = read_pointer(*super_address, cancellation);
    if (super && *super != 0U && aligned_pointer(*super) &&
        readable_range(*super, profile_.ustruct.min_size)) {
        summary.super_address = *super;
        const auto super_name_address = checked_add(*super, profile_.uobject.name_offset);
        if (super_name_address) {
            auto super_name = read_name_at(*super_name_address, cancellation);
            if (super_name) {
                summary.super_name = std::move(*super_name);
            }
        }
    }
    return summary;
}

Result<std::vector<UnrealPropertyInfo>> UnrealRuntimeReader::read_declared_properties(
    const Address struct_address,
    const std::size_t max_properties,
    const std::stop_token cancellation
) const {
    std::vector<UnrealPropertyInfo> properties;
    if (!aligned_pointer(struct_address) || !readable_range(struct_address, profile_.ustruct.min_size)) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "struct address is not usable"));
    }
    const auto& property_layout = profile_.property;
    const std::uint32_t head_offset = property_layout.kind == PropertyChainKind::field_chain
        ? profile_.ustruct.child_properties_offset
        : profile_.ustruct.children_offset;
    const auto head_address = checked_add(struct_address, head_offset);
    if (!head_address) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "property head address overflow"));
    }
    auto head = read_pointer(*head_address, cancellation);
    if (!head) {
        return std::unexpected(head.error());
    }

    std::string declaring_name;
    if (const auto name_address = checked_add(struct_address, profile_.uobject.name_offset)) {
        auto name = read_name_at(*name_address, cancellation);
        if (name) {
            declaring_name = std::move(*name);
        }
    }

    // Every linked list in a live process is treated as adversarial: bounded
    // node count, bounded stored results and explicit cycle detection.
    if (property_layout.min_size > max_structure_bytes) {
        return std::unexpected(error(DebugErrorCode::unsupported, "profile property size is out of range"));
    }
    std::unordered_set<Address> visited;
    visited.reserve(std::min<std::size_t>(limits_.max_property_nodes, 256U));
    std::array<std::byte, max_structure_bytes> storage{};
    Address current = *head;
    std::size_t nodes = 0;
    while (current != 0U && nodes < limits_.max_property_nodes) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
        }
        if (!aligned_pointer(current) || !readable_range(current, property_layout.min_size)) {
            break;
        }
        if (!visited.insert(current).second) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "property chain contains a cycle"));
        }
        ++nodes;

        const auto node = std::span<std::byte>{storage}.first(property_layout.min_size);
        auto read = read_exact(current, node, cancellation);
        if (!read) {
            return std::unexpected(read.error());
        }
        const std::span<const std::byte> bytes{node};

        UnrealPropertyInfo info;
        info.metadata_address = current;
        info.array_dim = static_cast<std::uint64_t>(
            decode_le(bytes.subspan(property_layout.array_dim_offset, 4U))
        );
        info.element_size = static_cast<std::uint64_t>(
            decode_le(bytes.subspan(property_layout.element_size_offset, 4U))
        );
        info.flags = decode_le(bytes.subspan(property_layout.flags_offset, 8U));
        info.offset_internal = static_cast<std::uint64_t>(
            decode_le(bytes.subspan(property_layout.offset_internal_offset, 4U))
        );
        info.declaring_class = struct_address;
        info.declaring_class_name = declaring_name;

        const auto name_index = static_cast<std::uint32_t>(decode_le(bytes.subspan(
            static_cast<std::size_t>(property_layout.name_offset) + profile_.fname.index_offset, 4U
        )));
        auto name = read_name(name_index, cancellation);
        if (name) {
            info.name = std::move(*name);
        }

        const auto metaclass = static_cast<Address>(
            decode_le(bytes.subspan(property_layout.class_offset, profile_.pointer_size))
        );
        if (aligned_pointer(metaclass)) {
            const auto kind_address = checked_add(metaclass, property_layout.class_name_offset);
            if (kind_address && readable_range(*kind_address, profile_.fname.size)) {
                auto kind = read_name_at(*kind_address, cancellation);
                if (kind) {
                    info.reflected_kind = std::move(*kind);
                }
            }
        }

        // A hostile element_size/array_dim pair must not turn into an address
        // the caller would then read.
        const auto span_bytes = info.element_size == 0U || info.array_dim == 0U
            ? std::optional<std::uint64_t>{0U}
            : (info.array_dim > std::numeric_limits<std::uint64_t>::max() / info.element_size
                ? std::nullopt
                : std::optional<std::uint64_t>{info.element_size * info.array_dim});
        if (!span_bytes || !checked_add(info.offset_internal, *span_bytes).has_value()) {
            info.confidence = RuntimeConfidence::low;
        } else if (info.name.empty() || info.reflected_kind.empty()) {
            info.confidence = RuntimeConfidence::low;
        } else {
            info.confidence = RuntimeConfidence::medium;
        }

        if (properties.size() < max_properties && properties.size() < limits_.max_properties_per_type) {
            properties.push_back(std::move(info));
        } else {
            break;
        }

        // The next pointer came in the same read as the rest of the node, so
        // walking the chain costs one read per property, not two.
        current = static_cast<Address>(
            decode_le(bytes.subspan(property_layout.next_offset, profile_.pointer_size))
        );
    }
    return properties;
}

Result<UnrealRuntimeType> UnrealRuntimeReader::read_type(
    const Address class_address,
    const bool include_inherited,
    const std::size_t max_properties,
    const std::size_t max_super_depth,
    const std::stop_token cancellation
) const {
    auto summary = read_class_summary(class_address, cancellation);
    if (!summary) {
        return std::unexpected(summary.error());
    }

    UnrealRuntimeType type;
    type.type = std::move(*summary);

    auto declared = read_declared_properties(class_address, max_properties, cancellation);
    if (!declared) {
        return std::unexpected(declared.error());
    }
    type.declared_properties = std::move(*declared);
    std::size_t budget = type.declared_properties.size() >= max_properties
        ? 0U
        : max_properties - type.declared_properties.size();
    type.truncated = budget == 0U;

    if (include_inherited) {
        std::unordered_set<Address> visited{class_address};
        Address current = type.type.super_address.value_or(0U);
        const auto depth_limit = std::min(max_super_depth, limits_.max_super_depth);
        for (std::size_t depth = 0; depth < depth_limit && current != 0U; ++depth) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
            }
            if (!visited.insert(current).second) {
                type.failed_invariants.push_back(RuntimeInvariant::super_chain_acyclic);
                break;
            }
            if (budget == 0U) {
                type.truncated = true;
                break;
            }
            auto inherited = read_declared_properties(current, budget, cancellation);
            if (!inherited) {
                type.failed_invariants.push_back(RuntimeInvariant::property_bounds);
                break;
            }
            budget -= std::min(budget, inherited->size());
            type.inherited_properties.insert(
                type.inherited_properties.end(),
                std::make_move_iterator(inherited->begin()),
                std::make_move_iterator(inherited->end())
            );
            auto parent = read_class_identity(current, cancellation);
            if (!parent) {
                break;
            }
            current = parent->super_address.value_or(0U);
            if (current != 0U && depth + 1U == depth_limit) {
                type.truncated = true;
            }
        }
    }

    // Deterministic order: offset first, then name, so two reads of the same
    // unchanged type produce byte-identical output.
    const auto by_offset_then_name = [](const UnrealPropertyInfo& lhs, const UnrealPropertyInfo& rhs) {
        if (lhs.offset_internal != rhs.offset_internal) return lhs.offset_internal < rhs.offset_internal;
        return lhs.name < rhs.name;
    };
    std::ranges::sort(type.declared_properties, by_offset_then_name);
    std::ranges::sort(type.inherited_properties, by_offset_then_name);
    return type;
}

// A page is accepted only when the header and the tuple digest match before and
// after the parse. Counts alone are not enough: a slot can be recycled while the
// element count stays the same.
Result<ClassCatalog> UnrealRuntimeReader::build_class_catalog(const std::stop_token cancellation) const {
    auto checked = read_checked_header(cancellation);
    if (!checked) {
        return std::unexpected(checked.error());
    }
    const auto header = *checked;

    ClassCatalog catalog;
    catalog.progress.phase = UnrealRuntimePhase::building_catalog;

    std::unordered_set<Address> seen_classes;
    seen_classes.reserve(std::min<std::size_t>(limits_.max_classes_stored, 1024U));
    std::vector<std::byte> buffer;
    std::vector<std::byte> recheck;

    const std::uint64_t total_slots = std::min<std::uint64_t>(
        header.num_elements, limits_.max_slots_visited
    );
    if (total_slots < header.num_elements) {
        catalog.truncated = true;
    }
    const auto& layout = profile_.object_array;

    std::uint64_t slot = 0;
    while (slot < total_slots) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
        }
        const std::uint64_t within = slot % layout.elements_per_chunk;
        const std::uint64_t page = std::min<std::uint64_t>({
            limits_.page_slots,
            layout.elements_per_chunk - within,
            total_slots - slot,
            max_item_run_bytes / std::max<std::uint64_t>(layout.item_size, 1U)
        });
        if (page == 0U) {
            break;
        }

        bool accepted = false;
        std::vector<UnrealClassSummary> page_classes;
        for (std::size_t attempt = 0; attempt <= limits_.max_page_retries; ++attempt) {
            if (attempt != 0U) {
                ++catalog.progress.retries;
            }
            auto before_header = read_object_array_header(cancellation);
            if (!before_header) {
                return std::unexpected(before_header.error());
            }
            auto before = read_item_run(header, slot, page, buffer, cancellation);
            if (!before) {
                return std::unexpected(before.error());
            }

            page_classes.clear();
            std::size_t page_live = 0;
            for (std::uint64_t index = 0; index < page; ++index) {
                auto decoded = decode_slot(
                    std::span<const std::byte>{buffer}.subspan(
                        static_cast<std::size_t>(index * layout.item_size), layout.item_size
                    ),
                    slot + index,
                    cancellation
                );
                if (!decoded) {
                    // A slot that stopped being readable mid-page is exactly the
                    // instability the re-read below is meant to catch.
                    page_classes.clear();
                    page_live = 0;
                    break;
                }
                if (!decoded->has_value()) {
                    continue;
                }
                ++page_live;
                const auto& live = **decoded;
                if (!aligned_pointer(live.class_address) ||
                    !readable_range(live.class_address, profile_.ustruct.min_size)) {
                    continue;
                }
                if (seen_classes.contains(live.class_address)) {
                    continue;
                }
                if (seen_classes.size() + page_classes.size() >= limits_.max_classes_stored) {
                    catalog.truncated = true;
                    continue;
                }
                auto summary = read_class_summary(live.class_address, cancellation);
                if (!summary || summary->name.empty()) {
                    // Counted, not hidden: a class whose structures failed
                    // validation must not look like one that was never seen.
                    ++catalog.progress.classes_rejected;
                    seen_classes.insert(live.class_address);
                    continue;
                }
                page_classes.push_back(std::move(*summary));
            }

            auto after = read_item_run(header, slot, page, recheck, cancellation);
            if (!after) {
                return std::unexpected(after.error());
            }
            auto after_header = read_object_array_header(cancellation);
            if (!after_header) {
                return std::unexpected(after_header.error());
            }
            if (*before == *after && *before_header == *after_header) {
                catalog.progress.slots_visited += static_cast<std::size_t>(page);
                catalog.progress.slots_eligible += page_live;
                catalog.progress.objects_found += page_live;
                accepted = true;
                break;
            }
        }

        if (!accepted) {
            // No mixed draft is published: the caller gets an explicit unstable
            // snapshot instead of a catalog stitched from two generations.
            catalog.status = SnapshotStatus::unstable;
            return std::unexpected(error(DebugErrorCode::io_error, "unstable_snapshot"));
        }
        for (auto& summary : page_classes) {
            if (seen_classes.insert(summary.class_address).second) {
                catalog.classes.push_back(std::move(summary));
                ++catalog.progress.classes_validated;
            }
        }
        slot += page;
    }

    std::ranges::sort(catalog.classes, [](const UnrealClassSummary& lhs, const UnrealClassSummary& rhs) {
        if (lhs.name != rhs.name) return lhs.name < rhs.name;
        return lhs.class_address < rhs.class_address;
    });
    return catalog;
}

Result<ObjectPage> UnrealRuntimeReader::enumerate_objects(
    const std::string_view class_name,
    const bool include_derived,
    const std::uint64_t start_slot,
    const std::size_t max_objects,
    const std::stop_token cancellation
) const {
    auto header = read_checked_header(cancellation);
    if (!header) {
        return std::unexpected(header.error());
    }

    ObjectPage page_result;
    page_result.progress.phase = UnrealRuntimePhase::enumerating_slots;

    // Class identity is resolved once per class address and reused for every
    // object of that class, so a filtered sweep does not re-walk super chains.
    struct ClassDecision {
        std::string name;
        bool matches{false};
    };
    std::unordered_map<Address, ClassDecision> decisions;
    const auto decide = [&](const Address class_address) -> const ClassDecision* {
        if (const auto cached = decisions.find(class_address); cached != decisions.end()) {
            return &cached->second;
        }
        auto summary = read_class_identity(class_address, cancellation);
        if (!summary) {
            return nullptr;
        }
        ClassDecision decision;
        decision.name = summary->name;
        if (class_name.empty()) {
            decision.matches = true;
        } else if (summary->name == class_name) {
            decision.matches = true;
        } else if (include_derived) {
            std::unordered_set<Address> visited{class_address};
            Address parent = summary->super_address.value_or(0U);
            for (std::size_t depth = 0; depth < limits_.max_super_depth && parent != 0U; ++depth) {
                if (!visited.insert(parent).second) {
                    break;
                }
                auto ancestor = read_class_identity(parent, cancellation);
                if (!ancestor) {
                    break;
                }
                if (ancestor->name == class_name) {
                    decision.matches = true;
                    break;
                }
                parent = ancestor->super_address.value_or(0U);
            }
        }
        return &decisions.emplace(class_address, std::move(decision)).first->second;
    };

    const auto stored_limit = std::min(max_objects, limits_.max_objects_stored);
    const std::uint64_t total_slots = std::min<std::uint64_t>(
        header->num_elements, start_slot + limits_.max_slots_visited
    );
    const auto& layout = profile_.object_array;
    std::vector<std::byte> buffer;
    std::vector<std::byte> recheck;

    std::uint64_t slot = start_slot;
    while (slot < total_slots && page_result.objects.size() < stored_limit) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(DebugErrorCode::cancelled, "operation cancelled"));
        }
        const std::uint64_t within = slot % layout.elements_per_chunk;
        const std::uint64_t page = std::min<std::uint64_t>({
            limits_.page_slots,
            layout.elements_per_chunk - within,
            total_slots - slot,
            max_item_run_bytes / std::max<std::uint64_t>(layout.item_size, 1U)
        });
        if (page == 0U) {
            break;
        }

        bool accepted = false;
        std::optional<std::uint64_t> stopped_at;
        std::vector<UnrealObjectSummary> page_objects;
        for (std::size_t attempt = 0; attempt <= limits_.max_page_retries; ++attempt) {
            if (attempt != 0U) {
                ++page_result.progress.retries;
            }
            stopped_at.reset();
            auto before_header = read_object_array_header(cancellation);
            if (!before_header) {
                return std::unexpected(before_header.error());
            }
            auto before = read_item_run(*header, slot, page, buffer, cancellation);
            if (!before) {
                return std::unexpected(before.error());
            }

            page_objects.clear();
            std::size_t page_live = 0;
            for (std::uint64_t index = 0; index < page; ++index) {
                auto decoded = decode_slot(
                    std::span<const std::byte>{buffer}.subspan(
                        static_cast<std::size_t>(index * layout.item_size), layout.item_size
                    ),
                    slot + index,
                    cancellation
                );
                if (!decoded) {
                    page_objects.clear();
                    page_live = 0;
                    break;
                }
                if (!decoded->has_value()) {
                    continue;
                }
                ++page_live;
                const auto& live = **decoded;
                if (!aligned_pointer(live.class_address) ||
                    !readable_range(live.class_address, profile_.ustruct.min_size)) {
                    continue;
                }
                const auto* decision = decide(live.class_address);
                if (decision == nullptr || !decision->matches) {
                    continue;
                }
                if (page_result.objects.size() + page_objects.size() >= stored_limit) {
                    // Stop here and remember the slot that was not stored, so
                    // the next page resumes at it instead of past the whole run.
                    page_result.truncated = true;
                    stopped_at = slot + index;
                    break;
                }
                UnrealObjectSummary summary;
                summary.object_index = live.slot_index;
                summary.object_address = live.object_address;
                summary.class_address = live.class_address;
                summary.class_name = decision->name;
                summary.outer_address = live.outer_address;
                auto name = read_name(live.name_index, cancellation);
                if (name) {
                    summary.object_name = std::move(*name);
                }
                page_objects.push_back(std::move(summary));
            }

            auto after = read_item_run(*header, slot, page, recheck, cancellation);
            if (!after) {
                return std::unexpected(after.error());
            }
            auto after_header = read_object_array_header(cancellation);
            if (!after_header) {
                return std::unexpected(after_header.error());
            }
            if (*before == *after && *before_header == *after_header) {
                page_result.progress.slots_visited += static_cast<std::size_t>(page);
                page_result.progress.slots_eligible += page_live;
                page_result.progress.objects_found += page_live;
                accepted = true;
                break;
            }
        }

        if (!accepted) {
            page_result.status = SnapshotStatus::unstable;
            return std::unexpected(error(DebugErrorCode::io_error, "unstable_snapshot"));
        }
        for (auto& summary : page_objects) {
            page_result.objects.push_back(std::move(summary));
        }
        page_result.progress.objects_stored = page_result.objects.size();
        if (stopped_at) {
            slot = *stopped_at;
            break;
        }
        slot += page;
    }

    page_result.next_slot = slot;
    if (slot < header->num_elements) {
        page_result.truncated = true;
    }
    std::ranges::sort(page_result.objects, {}, &UnrealObjectSummary::object_index);
    return page_result;
}

}  // namespace argos::domain
