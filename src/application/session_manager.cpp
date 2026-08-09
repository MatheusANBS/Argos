#include "argos_mcp/application/session_manager.hpp"

#include <array>
#include <charconv>
#include <iomanip>
#include <random>
#include <sstream>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

}  // namespace

SessionManager::SessionManager() : rng_(std::random_device{}()) {}

std::string SessionManager::generate_id() {
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

domain::Result<domain::SessionInfo> SessionManager::add(
    std::unique_ptr<domain::ProcessSession> session
) {
    if (!session) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "session is null"));
    }
    auto shared = std::shared_ptr<domain::ProcessSession>{std::move(session)};
    std::scoped_lock lock(mutex_);
    for (std::size_t attempt = 0; attempt < 8U; ++attempt) {
        auto id_result = domain::SessionId::create(generate_id());
        if (!id_result) {
            continue;
        }
        const auto [iterator, inserted] = sessions_.emplace(id_result->value(), shared);
        if (inserted) {
            return domain::SessionInfo{
                *id_result, shared->pid(), std::string{shared->process_name()}, shared->access_mode()
            };
        }
        (void)iterator;
    }
    return std::unexpected(error(domain::DebugErrorCode::invalid_state, "unable to allocate session id"));
}

domain::Result<std::shared_ptr<domain::ProcessSession>> SessionManager::get(
    const domain::SessionId& id
) const {
    std::scoped_lock lock(mutex_);
    const auto iterator = sessions_.find(id.value());
    if (iterator == sessions_.end()) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "debug session not found"));
    }
    return iterator->second;
}

domain::Result<void> SessionManager::remove(const domain::SessionId& id) {
    std::scoped_lock lock(mutex_);
    if (sessions_.erase(id.value()) == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "debug session not found"));
    }
    return {};
}

std::size_t SessionManager::count_if(
    const std::function<bool(const domain::ProcessSession&)>& predicate
) const {
    std::scoped_lock lock(mutex_);
    std::size_t count = 0U;
    for (const auto& [id_text, session] : sessions_) {
        (void)id_text;
        if (session && predicate(*session)) {
            ++count;
        }
    }
    return count;
}

std::vector<domain::SessionInfo> SessionManager::list() const {
    std::scoped_lock lock(mutex_);
    std::vector<domain::SessionInfo> output;
    output.reserve(sessions_.size());
    for (const auto& [id_text, session] : sessions_) {
        auto id = domain::SessionId::create(id_text);
        if (id) {
            output.push_back(domain::SessionInfo{
                *id, session->pid(), std::string{session->process_name()}, session->access_mode()
            });
        }
    }
    return output;
}

}  // namespace argos::application
