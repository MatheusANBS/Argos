#pragma once

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
#include <vector>

namespace argos::application {

struct ScanResult {
    std::vector<domain::ScanMatch> matches;
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

    [[nodiscard]] domain::Result<void> detach(const domain::SessionId& id);
    [[nodiscard]] std::vector<domain::SessionInfo> list_sessions() const;

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

private:
    [[nodiscard]] domain::Result<std::string> module_path(
        const domain::SessionId& id,
        std::string_view module_name
    ) const;

    std::unique_ptr<domain::ProcessMemoryProvider> provider_;
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider_;
    security::SecurityPolicy policy_;
    SessionManager sessions_;
};

}  // namespace argos::application
