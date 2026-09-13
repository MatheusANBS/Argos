#pragma once

#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/domain/santa_monica_inventory.hpp"
#include "argos_mcp/domain/types.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>

namespace argos::application {

// Cache of the last resource snapshot read for one published context. The
// mutex guards the pointer swap and the generation counter, never I/O.
struct SantaMonicaInventoryState {
    std::mutex mutex;
    std::shared_ptr<const domain::santamonica::ResourceSnapshot> snapshot;
    std::uint64_t generation{};
};

// Where the resource store of the snapshot's build lives. Present only when the
// native profile that produced the snapshot publishes a resource root.
struct SantaMonicaResourceTarget {
    std::string profile_id;
    std::string module_name;
    std::uint64_t module_size{};
    std::uint64_t root_rva{};
};

// A published Santa Monica runtime context. The catalog is immutable and was
// admitted by the domain before publication, so a query never parses again and
// never sees a partially read snapshot.
struct SantaMonicaRuntimeContext {
    domain::SessionId owner;
    domain::ProcessId peer_pid{};
    std::shared_ptr<const domain::santamonica::ReflectionCatalog> catalog;
    std::chrono::steady_clock::time_point created_at{};
    std::chrono::steady_clock::time_point expires_at{};
    std::shared_ptr<SantaMonicaInventoryState> inventory{std::make_shared<SantaMonicaInventoryState>()};
    std::optional<SantaMonicaResourceTarget> resources;
};

struct SantaMonicaRuntimeContextInfo {
    domain::RuntimeId id;
    std::shared_ptr<const SantaMonicaRuntimeContext> context;
};

// Registry with per-owner and global quotas, TTL and explicit release. A single
// live context owns a given process instance and bridge epoch: a second
// discovery for the same pair is refused instead of racing it.
class SantaMonicaRuntimeManager final {
public:
    SantaMonicaRuntimeManager();

    [[nodiscard]] domain::Result<SantaMonicaRuntimeContextInfo> publish(
        SantaMonicaRuntimeContext context, std::size_t max_per_owner, std::size_t max_total);

    [[nodiscard]] domain::Result<std::shared_ptr<const SantaMonicaRuntimeContext>> get(
        const domain::SessionId& owner, const domain::RuntimeId& id) const;

    [[nodiscard]] domain::Result<void> release(
        const domain::SessionId& owner, const domain::RuntimeId& id);

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
    std::unordered_map<std::string, std::shared_ptr<const SantaMonicaRuntimeContext>> contexts_;
    std::unordered_map<std::string, Tombstone> tombstones_;
    std::mt19937_64 rng_;
};

}  // namespace argos::application
