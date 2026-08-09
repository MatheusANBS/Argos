#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <random>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace argos::application {

struct ScanCandidate {
    domain::Address address{};
    std::vector<std::byte> value;
};

// Owns the in-memory candidate sets for incremental (first scan / next scan)
// value-diff scanning. Parallel to SessionManager: a coarse mutex guards the
// map itself, but candidate re-reads (I/O against the debugged process) must
// happen outside this manager's lock -- callers take a snapshot(), do the
// I/O, then write the filtered result back with replace().
class ScanSessionManager final {
public:
    ScanSessionManager();

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> create(
        const domain::SessionId& owner,
        domain::ScanValueType value_type,
        std::vector<ScanCandidate> candidates,
        std::size_t max_sessions_per_owner
    );

    struct Snapshot {
        domain::SessionId owner;
        domain::ScanValueType value_type{};
        std::vector<ScanCandidate> candidates;
    };

    [[nodiscard]] domain::Result<Snapshot> snapshot(const domain::ScanSessionId& id) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> replace(
        const domain::ScanSessionId& id,
        std::vector<ScanCandidate> candidates
    );

    [[nodiscard]] domain::Result<std::vector<domain::ScanMatch>> results(
        const domain::ScanSessionId& id,
        std::size_t offset,
        std::size_t limit
    ) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> reset(const domain::ScanSessionId& id);

    void remove_owned_by(const domain::SessionId& owner);

private:
    struct State {
        domain::SessionId owner;
        domain::ScanValueType value_type{};
        std::vector<ScanCandidate> candidates;
        std::uint32_t generation{};
    };

    [[nodiscard]] static domain::ScanSessionInfo info_of(const domain::ScanSessionId& id, const State& state);
    [[nodiscard]] std::string generate_id();

    mutable std::mutex mutex_;
    std::unordered_map<std::string, State> sessions_;
    mutable std::mutex rng_mutex_;
    std::mt19937_64 rng_;
};

}  // namespace argos::application
