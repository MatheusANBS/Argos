#pragma once

#include <mutex>
#include <string>
#include <string_view>

namespace argos::observability {

enum class LogLevel {
    debug,
    info,
    warning,
    error,
};

class Logger final {
public:
    explicit Logger(LogLevel minimum = LogLevel::info) noexcept : minimum_(minimum) {}
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    void log(LogLevel level, std::string_view event, std::string_view message) const;

private:
    LogLevel minimum_{LogLevel::info};
    mutable std::mutex mutex_;
    mutable std::string buffer_;
    static constexpr std::size_t BUFFER_THRESHOLD = 4096;

    void flush_buffer() const noexcept;
};

[[nodiscard]] LogLevel log_level_from_environment() noexcept;

}  // namespace argos::observability
