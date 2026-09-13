#include "argos_mcp/application/santa_monica_runtime_manager.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(
    const domain::DebugErrorCode code, std::string message, std::string reason = {}) {
    return domain::DebugError{code, std::move(message), std::move(reason)};
}

}  // namespace

SantaMonicaRuntimeManager::SantaMonicaRuntimeManager() {
    std::random_device device;
    rng_.seed((static_cast<std::uint64_t>(device()) << 32U) ^ static_cast<std::uint64_t>(device()));
}

std::string SantaMonicaRuntimeManager::generate_id() {
    std::array<char, 32> buffer{};
    buffer.fill('0');
    std::size_t written = 0;
    for (std::size_t half = 0; half < 2U; ++half) {
        const auto word = rng_();
        std::array<char, 16> digits{};
        const auto [ptr, ec] = std::to_chars(digits.data(), digits.data() + digits.size(), word, 16);
        if (ec != std::errc{}) {
            continue;
        }
        const auto length = static_cast<std::size_t>(ptr - digits.data());
        const auto pad = 16U - length;
        std::copy_n(digits.data(), length, buffer.data() + written + pad);
        written += 16U;
    }
    return std::string(buffer.data(), buffer.size());
}

void SantaMonicaRuntimeManager::drop_expired_locked(const std::chrono::steady_clock::time_point now) {
    for (auto entry = contexts_.begin(); entry != contexts_.end();) {
        if (entry->second->expires_at <= now) {
            entry = contexts_.erase(entry);
        } else {
            ++entry;
        }
    }
    for (auto entry = tombstones_.begin(); entry != tombstones_.end();) {
        if (entry->second.released_at + tombstone_ttl <= now) {
            entry = tombstones_.erase(entry);
        } else {
            ++entry;
        }
    }
}

domain::Result<SantaMonicaRuntimeContextInfo> SantaMonicaRuntimeManager::publish(
    SantaMonicaRuntimeContext context, const std::size_t max_per_owner, const std::size_t max_total) {
    if (!context.catalog) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_state, "runtime context has no catalog", "invalid_state"));
    }
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    drop_expired_locked(now);

    // Quotas count per owner and globally at the same time: a single session
    // cannot exhaust the server, and many sessions cannot either.
    if (contexts_.size() >= max_total) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "runtime context limit reached for this server"));
    }
    const auto owned = static_cast<std::size_t>(std::ranges::count_if(
        contexts_, [&context](const auto& entry) { return entry.second->owner == context.owner; }));
    if (owned >= max_per_owner) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "runtime context limit reached for this session"));
    }

    // One live owner per process instance and epoch, across sessions: a second
    // discovery for the same target is refused instead of racing the first.
    const auto& identity = context.catalog->identity();
    const auto busy = std::ranges::any_of(contexts_, [&identity](const auto& entry) {
        const auto& published = entry.second->catalog->identity();
        return published.process_instance == identity.process_instance &&
               published.bridge_epoch == identity.bridge_epoch;
    });
    if (busy) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state,
                                     "another context already owns this bridge epoch", "runtime_busy"));
    }

    auto shared = std::make_shared<const SantaMonicaRuntimeContext>(std::move(context));
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto id_result = domain::RuntimeId::create(generate_id());
        if (!id_result) {
            continue;
        }
        const auto [entry, inserted] = contexts_.emplace(id_result->value(), shared);
        if (inserted) {
            return SantaMonicaRuntimeContextInfo{*id_result, entry->second};
        }
    }
    return std::unexpected(error(domain::DebugErrorCode::invalid_state,
                                 "unable to allocate a runtime context id"));
}

domain::Result<std::shared_ptr<const SantaMonicaRuntimeContext>> SantaMonicaRuntimeManager::get(
    const domain::SessionId& owner, const domain::RuntimeId& id) const {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    const auto entry = contexts_.find(id.value());
    if (entry == contexts_.end()) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "runtime context not found"));
    }
    // A context owned by another session is reported exactly like one that does
    // not exist: the id must never confirm activity in a session the caller
    // does not own.
    if (!(entry->second->owner == owner)) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "runtime context not found"));
    }
    if (entry->second->expires_at <= now) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "context expired",
                                     "context_expired"));
    }
    return entry->second;
}

domain::Result<void> SantaMonicaRuntimeManager::release(
    const domain::SessionId& owner, const domain::RuntimeId& id) {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    drop_expired_locked(now);

    const auto entry = contexts_.find(id.value());
    if (entry == contexts_.end()) {
        // Idempotent for the owner during a short tombstone window: a retried
        // release must not look like a missing context.
        const auto tomb = tombstones_.find(id.value());
        if (tomb != tombstones_.end() && tomb->second.owner == owner.value()) {
            return {};
        }
        return std::unexpected(error(domain::DebugErrorCode::not_found, "runtime context not found"));
    }
    if (!(entry->second->owner == owner)) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "runtime context not found"));
    }
    contexts_.erase(entry);
    if (tombstones_.size() >= max_tombstones) {
        tombstones_.clear();
    }
    tombstones_.emplace(id.value(), Tombstone{owner.value(), now});
    return {};
}

void SantaMonicaRuntimeManager::remove_owned_by(const domain::SessionId& owner) {
    std::scoped_lock lock(mutex_);
    for (auto entry = contexts_.begin(); entry != contexts_.end();) {
        if (entry->second->owner == owner) {
            entry = contexts_.erase(entry);
        } else {
            ++entry;
        }
    }
}

std::size_t SantaMonicaRuntimeManager::count() const {
    std::scoped_lock lock(mutex_);
    return contexts_.size();
}

}  // namespace argos::application
