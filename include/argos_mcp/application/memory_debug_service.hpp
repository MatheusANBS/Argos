#pragma once

#include "argos_mcp/application/scan_session_manager.hpp"
#include "argos_mcp/application/session_manager.hpp"
#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/type_metadata.hpp"
#include "argos_mcp/security/policy.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <stop_token>
#include <utility>
#include <vector>

namespace argos::application {

struct ScanResult {
    std::vector<domain::ScanMatch> matches;
    std::size_t bytes_scanned{};
    bool truncated{false};
};

struct StringMatch {
    domain::Address address{};
    std::string text;
    std::string encoding;
};

struct StringScanResult {
    std::vector<StringMatch> matches;
    std::size_t bytes_scanned{};
    bool truncated{false};
};

struct BatchReadItem {
    domain::Address address{};
    std::size_t size{};
};

struct BatchReadResult {
    domain::Address address{};
    std::vector<std::byte> bytes;
    bool success{false};
    std::string error;
};

class MemoryDebugService final {
public:
    MemoryDebugService(
        std::unique_ptr<domain::ProcessMemoryProvider> provider,
        security::SecurityPolicy policy,
        std::unique_ptr<domain::TypeMetadataProvider> metadata_provider = nullptr
    );

    [[nodiscard]] const security::SecurityPolicy& policy() const noexcept { return policy_; }

    [[nodiscard]] domain::Result<std::vector<domain::ProcessInfo>> list_processes(
        std::string_view filter,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<domain::SessionInfo> attach(
        domain::ProcessId pid,
        domain::AccessMode access,
        bool authorized
    );

    [[nodiscard]] domain::Result<void> detach(const domain::SessionId& id, bool terminate = false);
    [[nodiscard]] std::vector<domain::SessionInfo> list_sessions() const;

    [[nodiscard]] domain::Result<domain::SessionInfo> launch(
        const domain::LaunchSpec& spec,
        domain::AccessMode access,
        bool authorized
    );

    [[nodiscard]] domain::Result<domain::OutputChunk> read_output(
        const domain::SessionId& id,
        std::uint64_t since_cursor,
        std::size_t max_bytes
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::MemoryRegion>> regions(
        const domain::SessionId& id
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::ModuleInfo>> modules(
        const domain::SessionId& id
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> pdb_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> unity_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::TypeMetadata> unreal_type(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view type_name,
        std::size_t max_fields
    ) const;

    [[nodiscard]] domain::Result<domain::ReflectionMetadata> unreal_reflection(
        const domain::SessionId& id,
        std::string_view module_name,
        std::size_t max_symbols
    ) const;

    [[nodiscard]] domain::Result<domain::TypeCatalog> pdb_list_types(
        const domain::SessionId& id,
        std::string_view module_name,
        std::string_view name_filter,
        std::string_view kind_filter,
        std::size_t max_symbols
    ) const;

    [[nodiscard]] domain::Result<std::vector<std::byte>> read_memory(
        const domain::SessionId& id,
        domain::Address address,
        std::size_t size
    ) const;

    [[nodiscard]] domain::Result<std::vector<BatchReadResult>> read_batch(
        const domain::SessionId& id,
        std::span<const BatchReadItem> items
    ) const;

    [[nodiscard]] domain::Result<std::size_t> write_memory(
        const domain::SessionId& id,
        domain::Address address,
        std::span<const std::byte> bytes,
        std::string_view confirmation
    );

    [[nodiscard]] domain::Result<ScanResult> scan_exact(
        const domain::SessionId& id,
        std::span<const std::byte> pattern,
        std::size_t alignment,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<domain::Address> resolve_pointer_chain(
        const domain::SessionId& id,
        domain::Address base,
        std::span<const std::int64_t> offsets,
        std::size_t pointer_size
    ) const;

    [[nodiscard]] domain::Result<StringScanResult> extract_strings(
        const domain::SessionId& id,
        std::size_t min_length,
        std::string_view encoding,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<ScanResult> scan_pointers_to(
        const domain::SessionId& id,
        domain::Address target,
        std::size_t pointer_size,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> scan_first(
        const domain::SessionId& id,
        domain::ScanValueType value_type,
        domain::ScanComparison comparison,
        std::optional<std::vector<std::byte>> value,
        std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address = std::nullopt,
        std::optional<domain::Address> end_address = std::nullopt,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> scan_next(
        const domain::ScanSessionId& scan_id,
        domain::ScanComparison comparison,
        std::optional<std::vector<std::byte>> value,
        std::optional<std::vector<std::byte>> delta,
        std::stop_token cancellation = {}
    ) const;

    [[nodiscard]] domain::Result<std::vector<domain::ScanMatch>> scan_results(
        const domain::ScanSessionId& scan_id,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<void> scan_reset(const domain::ScanSessionId& scan_id);

private:
    [[nodiscard]] domain::Result<std::string> module_path(
        const domain::SessionId& id,
        std::string_view module_name
    ) const;

    [[nodiscard]] domain::Result<ScanResult> scan_pattern(
        const domain::SessionId& id,
        std::span<const std::byte> pattern,
        std::size_t alignment,
        std::size_t byte_budget,
        std::size_t result_limit,
        bool writable_only,
        std::optional<domain::Address> start_address,
        std::optional<domain::Address> end_address,
        std::stop_token cancellation
    ) const;

    std::unique_ptr<domain::ProcessMemoryProvider> provider_;
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider_;
    security::SecurityPolicy policy_;
    SessionManager sessions_;
    mutable ScanSessionManager scan_sessions_;
};

}  // namespace argos::application
