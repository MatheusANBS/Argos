#include "argos_mcp/application/scan_session_manager.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

}  // namespace

ScanSessionManager::ScanSessionManager() : rng_(std::random_device{}()) {}

std::string ScanSessionManager::generate_id() {
    std::array<std::uint64_t, 2> words{};
    {
        std::scoped_lock lock(rng_mutex_);
        words[0] = rng_();
        words[1] = rng_();
    }

    std::array<char, 33> buffer{};
    buffer[32] = '\0';

    auto [ptr0, ec0] = std::to_chars(buffer.data(), buffer.data() + 16, words[0], 16);
    if (ec0 != std::errc{}) {
        return generate_id();
    }
    const auto written0 = static_cast<std::size_t>(ptr0 - buffer.data());
    if (written0 < 16U) {
        std::copy_backward(buffer.data(), buffer.data() + written0, buffer.data() + 16);
        std::fill(buffer.data(), buffer.data() + (16U - written0), '0');
    }

    auto [ptr1, ec1] = std::to_chars(buffer.data() + 16, buffer.data() + 32, words[1], 16);
    if (ec1 != std::errc{}) {
        return generate_id();
    }
    const auto written1 = static_cast<std::size_t>(ptr1 - (buffer.data() + 16));
    if (written1 < 16U) {
        std::copy_backward(buffer.data() + 16, buffer.data() + 16 + written1, buffer.data() + 32);
        std::fill(buffer.data() + 16, buffer.data() + 16 + (16U - written1), '0');
    }

    return std::string(buffer.data(), 32);
}

domain::ScanSessionInfo ScanSessionManager::info_of(const domain::ScanSessionId& id, const State& state) {
    return domain::ScanSessionInfo{id, state.owner, state.value_type, state.candidates->size(), state.generation};
}

domain::Result<domain::ScanSessionInfo> ScanSessionManager::create(
    const domain::SessionId& owner,
    const domain::ScanValueType value_type,
    std::vector<ScanCandidate> candidates,
    const std::size_t max_sessions_per_owner
) {
    auto shared_candidates = std::make_shared<const CandidateSet>(std::move(candidates));
    std::scoped_lock lock(mutex_);
    const auto owned_count = std::ranges::count_if(sessions_, [&owner](const auto& entry) {
        return entry.second.owner == owner;
    });
    if (static_cast<std::size_t>(owned_count) >= max_sessions_per_owner) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded,
            "the owning session already has the maximum number of active scan sessions"
        ));
    }
    for (std::size_t attempt = 0; attempt < 8U; ++attempt) {
        auto id_result = domain::ScanSessionId::create(generate_id());
        if (!id_result) {
            continue;
        }
        const auto [iterator, inserted] = sessions_.emplace(
            id_result->value(), State{owner, value_type, shared_candidates, 0U}
        );
        if (inserted) {
            return info_of(*id_result, iterator->second);
        }
    }
    return std::unexpected(error(domain::DebugErrorCode::invalid_state, "unable to allocate scan session id"));
}

domain::Result<ScanSessionManager::Snapshot> ScanSessionManager::snapshot(
    const domain::ScanSessionId& id
) const {
    std::scoped_lock lock(mutex_);
    const auto iterator = sessions_.find(id.value());
    if (iterator == sessions_.end()) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "scan session not found"));
    }
    return Snapshot{
        iterator->second.owner,
        iterator->second.value_type,
        iterator->second.candidates,
        iterator->second.generation
    };
}

domain::Result<domain::ScanSessionInfo> ScanSessionManager::replace(
    const domain::ScanSessionId& id,
    const Snapshot& source,
    std::vector<ScanCandidate> candidates
) {
    auto replacement = std::make_shared<const CandidateSet>(std::move(candidates));
    CandidateSnapshot retired;
    {
        std::scoped_lock lock(mutex_);
        const auto iterator = sessions_.find(id.value());
        if (iterator == sessions_.end()) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "scan session not found"));
        }
        if (iterator->second.candidates != source.candidates_) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_state,
                "scan session changed while candidates were being sampled"
            ));
        }
        retired = std::exchange(iterator->second.candidates, std::move(replacement));
        ++iterator->second.generation;
        return info_of(id, iterator->second);
    }
}

domain::Result<std::vector<domain::ScanMatch>> ScanSessionManager::results(
    const domain::ScanSessionId& id,
    const std::size_t offset,
    const std::size_t limit
) const {
    CandidateSnapshot candidates;
    {
        std::scoped_lock lock(mutex_);
        const auto iterator = sessions_.find(id.value());
        if (iterator == sessions_.end()) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "scan session not found"));
        }
        candidates = iterator->second.candidates;
    }
    std::vector<domain::ScanMatch> output;
    if (offset >= candidates->size()) {
        return output;
    }
    const auto count = std::min(limit, candidates->size() - offset);
    output.reserve(count);
    for (std::size_t index = offset; index < offset + count; ++index) {
        output.push_back(domain::ScanMatch{(*candidates)[index].address});
    }
    return output;
}

domain::Result<domain::ScanSessionInfo> ScanSessionManager::reset(const domain::ScanSessionId& id) {
    auto empty = std::make_shared<const CandidateSet>();
    CandidateSnapshot retired;
    {
        std::scoped_lock lock(mutex_);
        const auto iterator = sessions_.find(id.value());
        if (iterator == sessions_.end()) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "scan session not found"));
        }
        retired = std::exchange(iterator->second.candidates, std::move(empty));
        iterator->second.generation = 0U;
        return info_of(id, iterator->second);
    }
}

void ScanSessionManager::remove_owned_by(const domain::SessionId& owner) {
    std::vector<CandidateSnapshot> retired;
    {
        std::scoped_lock lock(mutex_);
        retired.reserve(sessions_.size());
        for (auto iterator = sessions_.begin(); iterator != sessions_.end();) {
            if (iterator->second.owner != owner) {
                ++iterator;
                continue;
            }
            retired.push_back(std::move(iterator->second.candidates));
            iterator = sessions_.erase(iterator);
        }
    }
}

}  // namespace argos::application
