#pragma once

#include "argos_mcp/domain/types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace argos::domain::santamonica {

// Identity portion of a future executable profile. It does not describe any
// proprietary layout, implement hashing or attest a process by itself.
struct Sha256Digest {
    std::array<std::byte, 32> bytes{};
    [[nodiscard]] bool operator==(const Sha256Digest&) const = default;
};

struct ModuleIdentity {
    std::string name;  // Exact, canonical module basename, never a path.
    std::uint64_t image_size{};
    Sha256Digest file_digest;
    [[nodiscard]] bool operator==(const ModuleIdentity&) const = default;
};

enum class Architecture { x64 };

// Who produced a snapshot. A server-side native reader has no bridge at all,
// and the validator keeps the two apart so neither can present itself as the
// other: a bridge profile must carry bridge identity, a native one must not.
enum class SnapshotSource { bridge, native_reader };

struct ProfileIdentity {
    std::uint32_t schema_version{1};
    std::string profile_id;
    Sha256Digest profile_digest;
    Sha256Digest bridge_digest;
    std::uint32_t bridge_version{1};
    std::uint32_t protocol_version{1};
    std::vector<ModuleIdentity> modules;
    Architecture architecture{Architecture::x64};
    SnapshotSource source{SnapshotSource::bridge};
    [[nodiscard]] bool operator==(const ProfileIdentity&) const = default;
};

// This identity is supplied by a trusted reader after native authentication
// and loaded-image validation. It is NEVER accepted from an MCP request or
// considered proof merely because a peer supplied matching fields.
struct SnapshotIdentity {
    ProfileIdentity profile;
    std::string process_instance;
    std::string bridge_epoch;
    std::uint64_t generation{};
    [[nodiscard]] bool operator==(const SnapshotIdentity&) const = default;
};

enum class Consistency { validated_best_effort, stable, unstable };

// These IDs index normalized metadata only. They are not addresses and must
// be mapped to session/generation-bound opaque handles by a future MCP layer.
struct TypeKey {
    std::uint64_t value{};
    [[nodiscard]] bool operator==(const TypeKey&) const = default;
};
struct EnumKey {
    std::uint64_t value{};
    [[nodiscard]] bool operator==(const EnumKey&) const = default;
};
struct FunctionKey {
    std::uint64_t value{};
    [[nodiscard]] bool operator==(const FunctionKey&) const = default;
};

enum class FieldKind { scalar, object, pointer, array, map, enumeration };

struct TypeRecord {
    TypeKey id;
    std::string name;
    std::uint64_t size{};
    std::optional<TypeKey> base;
};

struct FieldRecord {
    TypeKey owner;
    std::string name;
    std::uint64_t offset{};
    std::uint64_t size{};
    FieldKind kind{FieldKind::scalar};
    // Object fields require a type. Pointer/array/map fields may have no
    // reflected target (e.g. primitive elements); a supplied key must resolve.
    std::optional<TypeKey> referenced_type;
    std::optional<EnumKey> referenced_enum;
};

struct EnumRecord {
    EnumKey id;
    std::string name;
};

struct EnumValueRecord {
    EnumKey owner;
    std::string name;
    // Lossless decimal spelling, including unsigned 64-bit values. No JSON
    // double or dependency-specific number representation enters the domain.
    std::string value;
};

struct SliFunctionRecord {
    FunctionKey id;
    std::string name;
    std::string signature;
    // Deliberately no callback, address or invocable flag in the read-only MVP.
};

using ReflectionRecord = std::variant<
    TypeRecord, FieldRecord, EnumRecord, EnumValueRecord, SliFunctionRecord>;

struct ReflectionLimits {
    std::size_t max_records{100000};
    std::size_t max_string_bytes{4096};
    std::size_t max_retained_bytes{32U * 1024U * 1024U};
    std::size_t max_inheritance_depth{32};
};

struct ReadBoundary {
    SnapshotIdentity identity;
    Consistency consistency{Consistency::validated_best_effort};
    bool coverage_complete{false};
};

class SantaMonicaRuntimeReader {
public:
    virtual ~SantaMonicaRuntimeReader() = default;
    // One reader per discovery. Native implementations must enforce the same
    // byte/string/work limits BEFORE allocating or decoding records, honor
    // cancellation/deadlines, and release partial native state on destruction.
    // A stable boundary means a protected immutable copy, not sampled headers.
    [[nodiscard]] virtual Result<ReadBoundary> begin(
        const ReflectionLimits& limits, std::stop_token cancellation) = 0;
    [[nodiscard]] virtual Result<std::optional<ReflectionRecord>> next(
        std::stop_token cancellation) = 0;
    [[nodiscard]] virtual Result<ReadBoundary> finish(std::stop_token cancellation) = 0;
};

class ReflectionCatalog final {
public:
    [[nodiscard]] const SnapshotIdentity& identity() const noexcept { return identity_; }
    [[nodiscard]] Consistency consistency() const noexcept { return consistency_; }
    [[nodiscard]] bool coverage_complete() const noexcept { return coverage_complete_; }
    // Admission is all-or-nothing; a catalog never silently drops records.
    [[nodiscard]] bool results_complete() const noexcept { return true; }
    [[nodiscard]] std::size_t retained_bytes() const noexcept { return retained_bytes_; }
    [[nodiscard]] std::span<const ReflectionRecord> records() const noexcept { return records_; }

    [[nodiscard]] static Result<std::unique_ptr<const ReflectionCatalog>> read(
        SantaMonicaRuntimeReader& reader,
        const ProfileIdentity& expected_profile,
        const ReflectionLimits& limits = {},
        std::stop_token cancellation = {});

private:
    ReflectionCatalog() = default;
    SnapshotIdentity identity_;
    Consistency consistency_{Consistency::validated_best_effort};
    bool coverage_complete_{false};
    std::size_t retained_bytes_{};
    std::vector<ReflectionRecord> records_;
};

[[nodiscard]] Result<void> validate_profile_identity(const ProfileIdentity& profile);

// Canonical identity token: non-empty ASCII of at most 128 bytes limited to
// letters, digits, '-', '_' and '.'. Shared by profile ids, module names,
// process instances and bridge epochs so those spellings cannot diverge.
[[nodiscard]] bool valid_identity_token(std::string_view value) noexcept;

}  // namespace argos::domain::santamonica
