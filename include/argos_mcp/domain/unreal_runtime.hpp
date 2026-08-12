#pragma once

#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain {

// Read-only projection of an authorized process for the Unreal parsers. It is
// deliberately not TypeMetadataProvider: that port takes a symbol file, and
// widening it would hide a live process session behind a file-shaped API.
struct RuntimeAddressSpaceSnapshot {
    ProcessId pid{};
    std::string process_name;
    RegionIndex regions;
    ModuleIndex modules;
    // Monotonic per view. A catalog that was built against one sequence is
    // never mixed with data read after a refresh.
    std::uint64_t sequence{};
};

class RuntimeMemoryView {
public:
    RuntimeMemoryView() = default;
    virtual ~RuntimeMemoryView() = default;
    RuntimeMemoryView(const RuntimeMemoryView&) = delete;
    RuntimeMemoryView& operator=(const RuntimeMemoryView&) = delete;
    RuntimeMemoryView(RuntimeMemoryView&&) = delete;
    RuntimeMemoryView& operator=(RuntimeMemoryView&&) = delete;

    [[nodiscard]] virtual Result<std::size_t> read(
        Address address,
        std::span<std::byte> destination,
        std::stop_token cancellation
    ) const = 0;

    [[nodiscard]] virtual Result<std::shared_ptr<const RuntimeAddressSpaceSnapshot>> snapshot() const = 0;
};

enum class DiscoveryMode { explicit_roots, build_profile, auto_discovery };

// Where the roots came from. Kept separate from the discovery mode: a `profile`
// request whose fingerprint check failed is not the same thing as a root the
// client supplied by hand.
enum class RootOrigin { explicit_rva, explicit_address, build_profile, signature_candidate };

enum class RuntimeConfidence { low, medium, high };
enum class SnapshotStatus { stable, unstable, stale };

enum class RuntimeEvidence {
    module_fingerprint,
    root_within_module,
    object_array_invariants,
    name_pool_invariants,
    class_sample_validated,
    property_sample_validated,
    signature_match,
};

enum class RuntimeInvariant {
    root_alignment,
    root_region,
    object_array_counts,
    object_array_chunks,
    slot_sample,
    name_pool_bounds,
    name_length,
    class_name,
    super_chain_acyclic,
    property_chain_acyclic,
    property_bounds,
};

[[nodiscard]] std::string_view to_string(DiscoveryMode mode) noexcept;
[[nodiscard]] std::string_view to_string(RootOrigin origin) noexcept;
[[nodiscard]] std::string_view to_string(RuntimeConfidence confidence) noexcept;
[[nodiscard]] std::string_view to_string(SnapshotStatus status) noexcept;
[[nodiscard]] std::string_view to_string(RuntimeEvidence evidence) noexcept;
[[nodiscard]] std::string_view to_string(RuntimeInvariant invariant) noexcept;
[[nodiscard]] std::optional<DiscoveryMode> discovery_mode_from_string(std::string_view text) noexcept;

// --- layout profiles --------------------------------------------------------

// UE 4.23+ stores names in a block allocator indexed by (block, offset); older
// builds use a chunked array of FNameEntry pointers. The two have nothing in
// common beyond the concept, so the profile picks the parser outright.
enum class NamePoolKind { block_pool, legacy_chunked_array };

// FField/FProperty (UE 4.25+) hang off UStruct::ChildProperties; UField/UProperty
// hang off UStruct::Children. A profile never falls back from one to the other.
enum class PropertyChainKind { field_chain, uobject_chain };

struct FNameLayout {
    std::uint32_t size{8U};
    std::uint32_t index_offset{0U};
    std::uint32_t number_offset{4U};
};

struct ObjectArrayLayout {
    std::uint32_t chunks_pointer_offset{};
    std::uint32_t max_elements_offset{};
    std::uint32_t num_elements_offset{};
    std::uint32_t max_chunks_offset{};
    std::uint32_t num_chunks_offset{};
    std::uint32_t elements_per_chunk{};
    std::uint32_t item_size{};
    std::uint32_t item_object_offset{};
    std::uint32_t item_flags_offset{};
    std::uint32_t item_serial_offset{};
};

struct NamePoolLayout {
    NamePoolKind kind{NamePoolKind::block_pool};
    std::uint32_t blocks_offset{};
    std::uint32_t block_index_shift{16U};
    std::uint32_t block_offset_mask{0xFFFFU};
    std::uint32_t block_offset_stride{2U};
    std::uint32_t max_blocks{8192U};
    std::uint32_t header_size{2U};
    std::uint32_t wide_mask{0x1U};
    std::uint32_t length_shift{6U};
    std::uint32_t length_mask{0x3FFU};
    std::uint32_t legacy_elements_per_chunk{16384U};
    std::uint32_t legacy_chunk_count{};
    std::uint32_t legacy_entry_index_offset{};
    std::uint32_t legacy_entry_name_offset{};
    std::uint32_t legacy_wide_mask{0x1U};
};

struct UObjectLayout {
    std::uint32_t flags_offset{};
    std::uint32_t index_offset{};
    std::uint32_t class_offset{};
    std::uint32_t name_offset{};
    std::uint32_t outer_offset{};
    std::uint32_t min_size{};
};

struct UStructLayout {
    std::uint32_t super_offset{};
    std::uint32_t children_offset{};
    std::uint32_t child_properties_offset{};
    std::uint32_t properties_size_offset{};
    std::uint32_t min_size{};
};

struct PropertyLayout {
    PropertyChainKind kind{PropertyChainKind::field_chain};
    std::uint32_t class_offset{};
    std::uint32_t next_offset{};
    std::uint32_t name_offset{};
    std::uint32_t array_dim_offset{};
    std::uint32_t element_size_offset{};
    std::uint32_t flags_offset{};
    std::uint32_t offset_internal_offset{};
    std::uint32_t min_size{};
    // Offset of the FName inside the metaclass that names the property kind
    // (FFieldClass for field_chain, UClass for uobject_chain).
    std::uint32_t class_name_offset{};
};

// Immutable, versioned and enabled one by one in server configuration. A client
// can only pick from what the operator already allowed.
struct UnrealRuntimeProfile {
    std::string id;
    std::string engine_family;
    std::size_t pointer_size{8U};
    FNameLayout fname;
    ObjectArrayLayout object_array;
    NamePoolLayout name_pool;
    UObjectLayout uobject;
    UStructLayout ustruct;
    PropertyLayout property;
};

[[nodiscard]] std::span<const UnrealRuntimeProfile> builtin_unreal_profiles() noexcept;
[[nodiscard]] const UnrealRuntimeProfile* find_unreal_profile(std::string_view id) noexcept;

// --- bounded work ----------------------------------------------------------

struct RuntimeLimits {
    std::size_t max_slots_visited{1000000U};
    std::size_t max_objects_stored{10000U};
    std::size_t max_classes_stored{20000U};
    std::size_t max_properties_per_type{1024U};
    std::size_t max_super_depth{64U};
    std::size_t max_property_nodes{4096U};
    std::size_t max_name_bytes{1024U};
    std::size_t max_page_retries{2U};
    std::size_t page_slots{1024U};
    std::size_t validation_sample_slots{32U};
};

struct UnrealRuntimeRoots {
    Address gu_object_array{};
    Address fname_pool{};
    RootOrigin origin{RootOrigin::explicit_address};
};

struct ObjectArrayHeader {
    Address chunks{};
    std::uint32_t max_elements{};
    std::uint32_t num_elements{};
    std::uint32_t max_chunks{};
    std::uint32_t num_chunks{};

    [[nodiscard]] bool operator==(const ObjectArrayHeader&) const = default;
};

// One live entry of GUObjectArray plus the UObject header it points at. Both
// are fetched in a single read each, so a sweep costs two reads per live slot
// and none for a dead one.
struct ObjectSlot {
    std::uint64_t slot_index{};
    Address object_address{};
    std::uint32_t serial{};
    std::int32_t object_index{};
    Address class_address{};
    std::uint32_t name_index{};
    std::optional<Address> outer_address;
};

// --- derived catalogs ------------------------------------------------------

struct UnrealClassSummary {
    Address class_address{};
    std::string name;
    std::optional<Address> super_address;
    std::optional<std::string> super_name;
    std::size_t property_count{};
};

struct UnrealPropertyInfo {
    Address metadata_address{};
    std::string name;
    std::string reflected_kind;
    std::uint64_t offset_internal{};
    std::uint64_t element_size{};
    std::uint64_t array_dim{};
    std::uint64_t flags{};
    Address declaring_class{};
    std::string declaring_class_name;
    RuntimeConfidence confidence{RuntimeConfidence::medium};
};

struct UnrealRuntimeType {
    UnrealClassSummary type;
    std::vector<UnrealPropertyInfo> declared_properties;
    std::vector<UnrealPropertyInfo> inherited_properties;
    bool truncated{false};
    std::vector<RuntimeInvariant> failed_invariants;
};

struct UnrealObjectSummary {
    std::uint64_t object_index{};
    Address object_address{};
    Address class_address{};
    std::string object_name;
    std::string class_name;
    std::optional<Address> outer_address;
};

enum class UnrealRuntimePhase {
    locating_roots,
    validating_roots,
    enumerating_slots,
    building_catalog,
    publishing,
};

struct UnrealRuntimeProgress {
    std::uint64_t sequence{};
    UnrealRuntimePhase phase{};
    std::size_t slots_visited{};
    std::size_t slots_eligible{};
    std::size_t objects_found{};
    std::size_t objects_stored{};
    std::size_t classes_validated{};
    std::size_t classes_rejected{};
    std::size_t properties_validated{};
    std::size_t retries{};
    std::size_t unstable_slots{};
};

struct RootValidation {
    ObjectArrayHeader header;
    std::vector<RuntimeEvidence> evidence;
    std::vector<RuntimeInvariant> failed_invariants;
    RuntimeConfidence confidence{RuntimeConfidence::low};
    std::size_t sampled_slots{};
    std::size_t valid_slots{};
};

struct ClassCatalog {
    std::vector<UnrealClassSummary> classes;
    UnrealRuntimeProgress progress;
    bool truncated{false};
    SnapshotStatus status{SnapshotStatus::stable};
};

struct ObjectPage {
    std::vector<UnrealObjectSummary> objects;
    UnrealRuntimeProgress progress;
    // First slot the next page must start from. Derived from where the sweep
    // actually stopped, not from the last stored object: a page whose filter
    // matched nothing still has to advance, and a page cut off by the result
    // limit must not skip the slots it never looked at.
    std::uint64_t next_slot{};
    bool truncated{false};
    SnapshotStatus status{SnapshotStatus::stable};
};

// Reads and validates Unreal reflection structures out of a live process.
// Every traversal is bounded by RuntimeLimits, checks cycles, refuses hostile
// counts before allocating, treats a short read as instability rather than as
// zero bytes, and never calls a function in the target.
class UnrealRuntimeReader final {
public:
    UnrealRuntimeReader(
        const RuntimeMemoryView& view,
        std::shared_ptr<const RuntimeAddressSpaceSnapshot> snapshot,
        const UnrealRuntimeProfile& profile,
        RuntimeLimits limits,
        UnrealRuntimeRoots roots
    );

    [[nodiscard]] const UnrealRuntimeProfile& profile() const noexcept { return profile_; }
    [[nodiscard]] const UnrealRuntimeRoots& roots() const noexcept { return roots_; }
    [[nodiscard]] const RuntimeAddressSpaceSnapshot& snapshot() const noexcept { return *snapshot_; }

    [[nodiscard]] Result<ObjectArrayHeader> read_object_array_header(std::stop_token cancellation) const;

    // Header plus the count/chunk invariants every sweep depends on. Counts
    // read from the target never size a loop or a read before passing here.
    [[nodiscard]] Result<ObjectArrayHeader> read_checked_header(std::stop_token cancellation) const;

    // Structural proof that the roots belong to this profile. Failing a
    // mandatory invariant rejects the context; a failing optional sample only
    // lowers confidence, and is reported either way.
    [[nodiscard]] Result<RootValidation> validate_roots(std::stop_token cancellation) const;

    [[nodiscard]] Result<std::string> read_name(std::uint32_t index, std::stop_token cancellation) const;

    [[nodiscard]] Result<std::optional<ObjectSlot>> read_slot(
        const ObjectArrayHeader& header,
        std::uint64_t index,
        std::stop_token cancellation
    ) const;

    // Name and super only. Filtering objects by class needs nothing more, and
    // walking the property chain once per object class would dominate a sweep.
    [[nodiscard]] Result<UnrealClassSummary> read_class_identity(
        Address class_address,
        std::stop_token cancellation
    ) const;

    // Identity plus a validated property count. A chain that fails validation
    // makes the whole summary fail: a class reported with zero properties would
    // be indistinguishable from one that genuinely has none.
    [[nodiscard]] Result<UnrealClassSummary> read_class_summary(
        Address class_address,
        std::stop_token cancellation
    ) const;

    [[nodiscard]] Result<std::vector<UnrealPropertyInfo>> read_declared_properties(
        Address struct_address,
        std::size_t max_properties,
        std::stop_token cancellation
    ) const;

    [[nodiscard]] Result<UnrealRuntimeType> read_type(
        Address class_address,
        bool include_inherited,
        std::size_t max_properties,
        std::size_t max_super_depth,
        std::stop_token cancellation
    ) const;

    // One page-stable sweep over live slots. Classes are collected on the way.
    [[nodiscard]] Result<ClassCatalog> build_class_catalog(std::stop_token cancellation) const;

    [[nodiscard]] Result<ObjectPage> enumerate_objects(
        std::string_view class_name,
        bool include_derived,
        std::uint64_t start_slot,
        std::size_t max_objects,
        std::stop_token cancellation
    ) const;

private:
    [[nodiscard]] Result<void> read_exact(
        Address address,
        std::span<std::byte> destination,
        std::stop_token cancellation
    ) const;

    [[nodiscard]] Result<std::uint32_t> read_u32(Address address, std::stop_token cancellation) const;
    [[nodiscard]] Result<std::uint64_t> read_u64(Address address, std::stop_token cancellation) const;
    [[nodiscard]] Result<Address> read_pointer(Address address, std::stop_token cancellation) const;
    [[nodiscard]] Result<std::string> read_name_at(Address address, std::stop_token cancellation) const;

    [[nodiscard]] bool readable_range(Address address, std::uint64_t size) const noexcept;
    [[nodiscard]] bool aligned_pointer(Address value) const noexcept;

    [[nodiscard]] Result<Address> chunk_base(
        const ObjectArrayHeader& header,
        std::uint64_t chunk,
        std::stop_token cancellation
    ) const;

    // Reads a run of FUObjectItem entries that lies inside one chunk in a
    // single call and returns a digest of the (slot, object, serial) tuples.
    // Comparing digests -- not just counts -- is what catches a slot that was
    // recycled while the count stayed the same.
    [[nodiscard]] Result<std::uint64_t> read_item_run(
        const ObjectArrayHeader& header,
        std::uint64_t first_slot,
        std::uint64_t slot_count,
        std::vector<std::byte>& buffer,
        std::stop_token cancellation
    ) const;

    [[nodiscard]] Result<std::optional<ObjectSlot>> decode_slot(
        std::span<const std::byte> item_bytes,
        std::uint64_t slot_index,
        std::stop_token cancellation
    ) const;

    const RuntimeMemoryView& view_;
    std::shared_ptr<const RuntimeAddressSpaceSnapshot> snapshot_;
    const UnrealRuntimeProfile& profile_;
    RuntimeLimits limits_;
    UnrealRuntimeRoots roots_;
};

}  // namespace argos::domain
