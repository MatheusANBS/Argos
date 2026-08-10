#pragma once

#include "argos_mcp/domain/types.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace argos::application {

class ScanCandidate final {
public:
    static constexpr std::size_t max_value_size = sizeof(std::uint64_t);

    ScanCandidate() = default;

    ScanCandidate(const domain::Address candidate_address, const std::span<const std::byte> bytes) noexcept
        : address(candidate_address) {
        assert(bytes.size() <= value_storage_.size());
        const auto copy_size = std::min(bytes.size(), value_storage_.size());
        std::copy_n(bytes.begin(), copy_size, value_storage_.begin());
    }

    [[nodiscard]] std::span<const std::byte> value_bytes(const std::size_t value_size) const noexcept {
        assert(value_size <= value_storage_.size());
        return std::span<const std::byte>{value_storage_}.first(value_size);
    }

    domain::Address address{};

private:
    // Every supported ScanValueType is at most 8 bytes. Keeping the sampled
    // value inline avoids one heap allocation for every candidate while the
    // owning scan session already records the common value width.
    std::array<std::byte, max_value_size> value_storage_{};
};

static_assert(sizeof(ScanCandidate) <= 2U * sizeof(std::uint64_t));

// Owns the in-memory candidate sets for incremental (first scan / next scan)
// value-diff scanning. Candidate generations are immutable after publication:
// snapshot() only copies a shared_ptr, so callers retain a stable lifetime
// while doing process I/O outside the registry mutex. replace() publishes a
// new generation only if its source snapshot is still current.
class ScanSessionManager final {
    using CandidateSet = std::vector<ScanCandidate>;
    using CandidateSnapshot = std::shared_ptr<const CandidateSet>;

public:
    ScanSessionManager();

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> create(
        const domain::SessionId& owner,
        domain::ScanValueType value_type,
        std::vector<ScanCandidate> candidates,
        std::size_t max_sessions_per_owner
    );

    class Snapshot final {
    public:
        [[nodiscard]] const domain::SessionId& owner() const noexcept { return owner_; }
        [[nodiscard]] domain::ScanValueType value_type() const noexcept { return value_type_; }
        [[nodiscard]] std::uint32_t generation() const noexcept { return generation_; }
        [[nodiscard]] std::span<const ScanCandidate> candidates() const noexcept {
            return {candidates_->data(), candidates_->size()};
        }

    private:
        friend class ScanSessionManager;

        Snapshot(
            domain::SessionId owner,
            domain::ScanValueType value_type,
            CandidateSnapshot candidates,
            const std::uint32_t generation
        ) : owner_(std::move(owner)), value_type_(value_type),
            candidates_(std::move(candidates)), generation_(generation) {}

        domain::SessionId owner_;
        domain::ScanValueType value_type_{};
        CandidateSnapshot candidates_;
        std::uint32_t generation_{};
    };

    [[nodiscard]] domain::Result<Snapshot> snapshot(const domain::ScanSessionId& id) const;

    [[nodiscard]] domain::Result<domain::ScanSessionInfo> replace(
        const domain::ScanSessionId& id,
        const Snapshot& source,
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
        CandidateSnapshot candidates;
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
