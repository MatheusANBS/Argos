#pragma once

#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/domain/types.hpp"
#include "argos_mcp/domain/unreal_runtime.hpp"

#include <cstdint>
#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace argos::infrastructure::santamonica {

namespace reflection = domain::santamonica;

// Record shape of one engine family. It is a property of the build, never
// something an operator or a client can redefine: only the location of each
// table varies per build, not how a record is laid out.
//
// Every offset below addresses a table that lives inside the module image. The
// engine's per-type member array does NOT -- it is allocated outside the image,
// so this reader never follows it. Ownership comes from the attribute's own
// owner index instead, which keeps the whole walk inside validated RVAs.
struct NativeTypeTableLayout {
    // Type table.
    std::uint32_t record_stride{};
    std::uint32_t tag_offset{};         // "t<Name>", the canonical spelling
    std::uint32_t name_offset{};        // "<Name>"
    std::uint32_t size_offset{};
    std::uint32_t align_offset{};
    std::uint32_t base_index_offset{};  // u16; index_absent means none
    std::uint32_t first_attribute_offset{};
    std::uint32_t attribute_count_offset{};

    // Attribute (field) table.
    std::uint32_t attribute_stride{};
    std::uint32_t attribute_name_offset{};
    std::uint32_t attribute_offset_offset{};  // u16
    std::uint32_t attribute_size_offset{};    // u16
    std::uint32_t attribute_flags_offset{};   // u8: low 2 bits flag, rest kind
    std::uint32_t attribute_owner_offset{};   // u16 type index
    std::uint32_t attribute_guard_offset{};   // u16 enclosing attribute; FFFF for direct fields
    std::uint32_t attribute_custom_offset{};  // u16 type index, kind-dependent
    std::uint32_t attribute_enum_offset{};    // u16 enum index

    // Enum table.
    std::uint32_t enum_stride{};
    std::uint32_t enum_name_offset{};
    std::uint32_t enum_count_offset{};   // u32
    std::uint32_t enum_names_offset{};   // pointer to an array of char*
    std::uint32_t enum_values_offset{};  // pointer to an array of u64

    // Script-language-interface function table.
    std::uint32_t sli_stride{};
    std::uint32_t sli_name_offset{};
    std::uint32_t sli_callback_offset{};
    std::uint32_t sli_signature_offset{};
};

// Sentinel the engine uses for "no inherited type" and "no enum".
inline constexpr std::uint16_t index_absent = 0xFFFF;

[[nodiscard]] const NativeTypeTableLayout* find_native_type_table_layout(std::string_view profile_id);

// Where each table lives in one exact build. Supplied by the operator's build
// profile, never by an MCP request. A table whose range is left empty is simply
// not walked, so a profile may publish types only.
struct NativeTypeTableRequest {
    std::string profile_id;
    std::string module_name;
    std::uint64_t module_size{};
    reflection::Sha256Digest module_digest;
    reflection::Sha256Digest profile_digest;
    std::uint64_t table_begin_rva{};
    std::uint64_t table_end_rva{};
    std::uint64_t names_begin_rva{};
    std::uint64_t names_end_rva{};
    std::uint64_t attribute_begin_rva{};
    std::uint64_t attribute_end_rva{};
    std::uint64_t enum_begin_rva{};
    std::uint64_t enum_end_rva{};
    std::uint64_t sli_begin_rva{};
    std::uint64_t sli_end_rva{};
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t generation{1};
    std::chrono::milliseconds max_duration{5000};  // May only reduce the hard 5s limit.
};

[[nodiscard]] domain::Result<reflection::ProfileIdentity> native_profile_identity(
    const NativeTypeTableRequest& request);

// Reads the engine's own reflection tables directly from an authorized,
// read-only session -- no bridge, no code in the target, no writes.
//
// Types carry name, size and inheritance; fields carry name, offset, size, kind
// and the type or enum they reference; enums carry their values; SLI entries
// carry name and argument signature. Nothing is invented to fill a gap: a table
// the profile does not locate is not reported at all.
//
// What the reader can check against the live process is the module identity and
// the structure of each record. The file digest in the profile is the operator's
// claim about the build, not an attestation of the loaded image, so the boundary
// is validated_best_effort and never stable. Coverage remains incomplete:
// collection auxiliaries and SLI properties are not interpreted yet.
class NativeTypeTableReader final : public reflection::SantaMonicaRuntimeReader {
public:
    NativeTypeTableReader(const domain::RuntimeMemoryView& memory, NativeTypeTableRequest request);
    NativeTypeTableReader(const NativeTypeTableReader&) = delete;
    NativeTypeTableReader& operator=(const NativeTypeTableReader&) = delete;

    [[nodiscard]] domain::Result<reflection::ReadBoundary> begin(
        const reflection::ReflectionLimits& limits, std::stop_token cancellation) override;
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next(
        std::stop_token cancellation) override;
    [[nodiscard]] domain::Result<reflection::ReadBoundary> finish(
        std::stop_token cancellation) override;

    // Slots that failed structural validation and were left out. A non-zero
    // count is the reason coverage is reported as incomplete.
    [[nodiscard]] std::size_t skipped_slots() const noexcept { return skipped_; }
    [[nodiscard]] std::size_t emitted_types() const noexcept { return emitted_types_; }
    [[nodiscard]] std::size_t emitted_fields() const noexcept { return emitted_fields_; }
    [[nodiscard]] std::size_t emitted_enums() const noexcept { return emitted_enums_; }
    [[nodiscard]] std::size_t emitted_functions() const noexcept { return emitted_functions_; }

private:
    enum class State { idle, reading, ended, failed };
    // Emission order. The catalog resolves forward references after admission.
    enum class Phase { types, fields, enums, enum_values, functions, done };

    // One validated type slot, retained so fields and base links can name their
    // target without a second pass over the table.
    struct TypeSlot {
        std::string name;
        std::uint64_t size{};
        std::uint16_t base_index{index_absent};
        std::uint32_t first_attribute{};
        std::uint32_t attribute_count{};
        bool valid{false};
    };

    struct EnumSlot {
        std::string name;
        std::uint64_t names_address{};
        std::uint64_t values_address{};
        std::uint32_t count{};
        bool valid{false};
    };

    [[nodiscard]] domain::DebugError poison(domain::DebugErrorCode code, const char* reason);
    [[nodiscard]] domain::Result<void> read_exact(
        domain::Address address, std::span<std::byte> destination, std::stop_token cancellation);
    [[nodiscard]] domain::Result<std::string> read_name(
        std::uint64_t rva, std::stop_token cancellation);
    // Reads a name through a pointer that must resolve into the profile's name
    // window; a pointer anywhere else is rejected, never followed.
    [[nodiscard]] domain::Result<std::string> read_name_via_pointer(
        std::uint64_t pointer, std::stop_token cancellation);

    [[nodiscard]] domain::Result<void> load_types(std::stop_token cancellation);
    [[nodiscard]] domain::Result<void> load_enums(std::stop_token cancellation);

    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next_type(
        std::stop_token cancellation);
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next_field(
        std::stop_token cancellation);
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next_enum(
        std::stop_token cancellation);
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next_enum_value(
        std::stop_token cancellation);
    [[nodiscard]] domain::Result<std::optional<reflection::ReflectionRecord>> next_function(
        std::stop_token cancellation);

    [[nodiscard]] domain::Result<void> charge_record();
    [[nodiscard]] domain::Result<void> check_work(std::stop_token cancellation);
    [[nodiscard]] bool contains(std::uint64_t address, std::uint64_t size) const noexcept;

    const domain::RuntimeMemoryView& memory_;
    NativeTypeTableRequest request_;
    const NativeTypeTableLayout* layout_{};
    reflection::ReflectionLimits limits_;
    reflection::ReadBoundary boundary_;
    domain::Address module_base_{};
    std::vector<TypeSlot> types_;
    std::vector<EnumSlot> enums_;
    Phase phase_{Phase::types};
    std::size_t type_cursor_{};
    std::uint64_t attribute_cursor_{};
    std::size_t enum_cursor_{};
    std::uint32_t enum_value_cursor_{};
    std::uint64_t function_cursor_{};
    std::size_t skipped_{};
    std::size_t emitted_{};
    std::size_t emitted_types_{};
    std::size_t emitted_fields_{};
    std::size_t emitted_enums_{};
    std::size_t emitted_functions_{};
    std::uint64_t read_bytes_{};
    std::chrono::steady_clock::time_point deadline_{};
    State state_{State::idle};
};

}  // namespace argos::infrastructure::santamonica
