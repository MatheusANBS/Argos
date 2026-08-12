#pragma once

#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/types.hpp"
#include "argos_mcp/domain/unreal_runtime.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace argos::application {

// Projects an authorized ProcessSession onto the domain's read-only runtime
// port. The address-space snapshot is captured once and shared for the whole
// operation, so no parser ever holds a span into storage that a refresh or a
// detach could replace underneath it.
class SessionRuntimeMemoryView final : public domain::RuntimeMemoryView {
public:
    explicit SessionRuntimeMemoryView(std::shared_ptr<domain::ProcessSession> session);

    [[nodiscard]] domain::Result<std::size_t> read(
        domain::Address address,
        std::span<std::byte> destination,
        std::stop_token cancellation
    ) const override;

    [[nodiscard]] domain::Result<std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot>>
        snapshot() const override;

    // Captures regions and modules once. Called before parsing starts so a
    // failure surfaces before any partial work.
    [[nodiscard]] domain::Result<std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot>> refresh();

private:
    std::shared_ptr<domain::ProcessSession> session_;
    mutable std::mutex mutex_;
    std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot> snapshot_;
    std::uint64_t sequence_{};
};

// A published runtime context: profile, validated roots, process identity and
// the derived class catalog. Immutable once published; queries take a
// shared_ptr and then do their I/O with no registry lock held.
struct UnrealRuntimeContext {
    domain::SessionId owner;
    domain::ProcessId pid{};
    std::string profile_id;
    std::string module_name;
    domain::UnrealRuntimeRoots roots;
    domain::RuntimeConfidence confidence{domain::RuntimeConfidence::low};
    std::vector<domain::RuntimeEvidence> evidence;
    std::vector<domain::RuntimeInvariant> failed_invariants;
    std::string process_fingerprint;
    std::shared_ptr<const domain::ClassCatalog> catalog;
    domain::SnapshotStatus snapshot_status{domain::SnapshotStatus::stable};
    std::chrono::steady_clock::time_point created_at{};
    std::chrono::steady_clock::time_point expires_at{};
    std::size_t retained_bytes{};
};

struct UnrealRuntimeContextInfo {
    domain::RuntimeId id;
    std::shared_ptr<const UnrealRuntimeContext> context;
};

// Registry with per-owner and global quotas, TTL and an explicit release that
// is independent of any job lifecycle.
class UnrealRuntimeManager final {
public:
    UnrealRuntimeManager();

    [[nodiscard]] domain::Result<UnrealRuntimeContextInfo> publish(
        UnrealRuntimeContext context,
        std::size_t max_per_owner,
        std::size_t max_total
    );

    [[nodiscard]] domain::Result<std::shared_ptr<const UnrealRuntimeContext>> get(
        const domain::SessionId& owner,
        const domain::RuntimeId& id
    ) const;

    [[nodiscard]] domain::Result<void> release(
        const domain::SessionId& owner,
        const domain::RuntimeId& id
    );

    void remove_owned_by(const domain::SessionId& owner);

    [[nodiscard]] std::size_t count() const;

private:
    [[nodiscard]] std::string generate_id();
    void drop_expired_locked(std::chrono::steady_clock::time_point now);

    struct Tombstone {
        std::string owner;
        std::chrono::steady_clock::time_point released_at;
    };

    static constexpr std::size_t max_tombstones = 64U;
    static constexpr std::chrono::seconds tombstone_ttl{60};

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<const UnrealRuntimeContext>> contexts_;
    std::unordered_map<std::string, Tombstone> tombstones_;
    std::mt19937_64 rng_;
};

}  // namespace argos::application
