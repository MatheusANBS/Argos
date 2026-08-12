#include "argos_mcp/application/unreal_runtime_manager.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <system_error>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(const domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

}  // namespace

SessionRuntimeMemoryView::SessionRuntimeMemoryView(std::shared_ptr<domain::ProcessSession> session)
    : session_(std::move(session)) {}

domain::Result<std::size_t> SessionRuntimeMemoryView::read(
    const domain::Address address,
    const std::span<std::byte> destination,
    const std::stop_token cancellation
) const {
    if (cancellation.stop_requested()) {
        return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
    }
    if (!session_) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "session is unavailable"));
    }
    auto read = session_->read(address, destination);
    if (!read) {
        return std::unexpected(read.error());
    }
    if (*read > destination.size()) {
        return std::unexpected(error(
            domain::DebugErrorCode::io_error, "memory backend returned an oversized read"
        ));
    }
    return *read;
}

domain::Result<std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot>>
SessionRuntimeMemoryView::snapshot() const {
    std::scoped_lock lock(mutex_);
    if (!snapshot_) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_state, "address space snapshot has not been captured"
        ));
    }
    return snapshot_;
}

domain::Result<std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot>>
SessionRuntimeMemoryView::refresh() {
    if (!session_) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "session is unavailable"));
    }
    auto regions = session_->regions();
    if (!regions) {
        return std::unexpected(regions.error());
    }
    auto modules = session_->modules();
    if (!modules) {
        return std::unexpected(modules.error());
    }

    auto captured = std::make_shared<domain::RuntimeAddressSpaceSnapshot>();
    captured->pid = session_->pid();
    captured->process_name = std::string{session_->process_name()};
    captured->regions = domain::RegionIndex::create(*regions);
    captured->modules = domain::ModuleIndex::create(*modules);
    {
        std::scoped_lock lock(mutex_);
        captured->sequence = ++sequence_;
        snapshot_ = captured;
    }
    return std::shared_ptr<const domain::RuntimeAddressSpaceSnapshot>{std::move(captured)};
}

UnrealRuntimeManager::UnrealRuntimeManager() {
    std::random_device device;
    rng_.seed((static_cast<std::uint64_t>(device()) << 32U) ^ static_cast<std::uint64_t>(device()));
}

std::string UnrealRuntimeManager::generate_id() {
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

void UnrealRuntimeManager::drop_expired_locked(const std::chrono::steady_clock::time_point now) {
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

domain::Result<UnrealRuntimeContextInfo> UnrealRuntimeManager::publish(
    UnrealRuntimeContext context,
    const std::size_t max_per_owner,
    const std::size_t max_total
) {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    drop_expired_locked(now);

    // Quotas count per owner and globally at the same time: a single session
    // cannot exhaust the server, and many sessions cannot either.
    if (contexts_.size() >= max_total) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "runtime context limit reached for this server"
        ));
    }
    const auto owned = static_cast<std::size_t>(std::ranges::count_if(
        contexts_,
        [&context](const auto& entry) { return entry.second->owner == context.owner; }
    ));
    if (owned >= max_per_owner) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "runtime context limit reached for this session"
        ));
    }

    auto shared = std::make_shared<const UnrealRuntimeContext>(std::move(context));
    for (int attempt = 0; attempt < 8; ++attempt) {
        auto id_result = domain::RuntimeId::create(generate_id());
        if (!id_result) {
            continue;
        }
        const auto [entry, inserted] = contexts_.emplace(id_result->value(), shared);
        if (inserted) {
            return UnrealRuntimeContextInfo{*id_result, entry->second};
        }
    }
    return std::unexpected(error(
        domain::DebugErrorCode::invalid_state, "unable to allocate a runtime context id"
    ));
}

domain::Result<std::shared_ptr<const UnrealRuntimeContext>> UnrealRuntimeManager::get(
    const domain::SessionId& owner,
    const domain::RuntimeId& id
) const {
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
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "context_expired"));
    }
    return entry->second;
}

domain::Result<void> UnrealRuntimeManager::release(
    const domain::SessionId& owner,
    const domain::RuntimeId& id
) {
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

void UnrealRuntimeManager::remove_owned_by(const domain::SessionId& owner) {
    std::scoped_lock lock(mutex_);
    for (auto entry = contexts_.begin(); entry != contexts_.end();) {
        if (entry->second->owner == owner) {
            entry = contexts_.erase(entry);
        } else {
            ++entry;
        }
    }
}

std::size_t UnrealRuntimeManager::count() const {
    std::scoped_lock lock(mutex_);
    return contexts_.size();
}

}  // namespace argos::application
