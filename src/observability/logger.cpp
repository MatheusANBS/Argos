#include "argos_mcp/observability/logger.hpp"

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

namespace argos::observability {
namespace {

[[nodiscard]] std::string_view level_name(const LogLevel level) noexcept {
    switch (level) {
        case LogLevel::debug: return "debug";
        case LogLevel::info: return "info";
        case LogLevel::warning: return "warning";
        case LogLevel::error: return "error";
    }
    return "unknown";
}

[[nodiscard]] std::string escape_json(std::string_view input) {
    std::string output;
    output.reserve(input.size() * 2U);
    for (const char ch : input) {
        switch (ch) {
            case '"': output.append("\\\"", 2); break;
            case '\\': output.append("\\\\", 2); break;
            case '\n': output.append("\\n", 2); break;
            case '\r': output.append("\\r", 2); break;
            case '\t': output.append("\\t", 2); break;
            default:
                if (static_cast<unsigned char>(ch) >= 0x20U) {
                    output.push_back(ch);
                }
                break;
        }
    }
    return output;
}

}  // namespace

void Logger::flush_buffer() const noexcept {
    if (buffer_.empty()) return;
    std::cerr << buffer_;
    std::cerr.flush();
    buffer_.clear();
}

Logger::~Logger() {
    std::scoped_lock lock(mutex_);
    flush_buffer();
}

void Logger::log(
    const LogLevel level,
    const std::string_view event,
    const std::string_view message
) const {
    if (static_cast<int>(level) < static_cast<int>(minimum_)) {
        return;
    }
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm utc{};
#if defined(_WIN32)
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    std::ostringstream timestamp;
    timestamp << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");

    std::string json_line;
    json_line.reserve(256);
    json_line += "{\"ts\":\"";
    json_line += timestamp.str();
    json_line += "\",\"level\":\"";
    json_line += level_name(level);
    json_line += "\",\"event\":\"";
    json_line += escape_json(event);
    json_line += "\",\"message\":\"";
    json_line += escape_json(message);
    json_line += "\"}\n";

    {
        std::scoped_lock lock(mutex_);
        buffer_ += json_line;
        // Important messages (warning/error) and buffer overflow flush immediately;
        // frequent low-severity logs stay batched for I/O efficiency.
        if (buffer_.size() >= BUFFER_THRESHOLD || level >= LogLevel::warning) {
            flush_buffer();
        }
    }
}

LogLevel log_level_from_environment() noexcept {
    const char* value = std::getenv("ARGOS_MCP_LOG_LEVEL");
    if (value == nullptr) {
        return LogLevel::info;
    }
    const std::string text{value};
    if (text == "debug") return LogLevel::debug;
    if (text == "warning" || text == "warn") return LogLevel::warning;
    if (text == "error") return LogLevel::error;
    return LogLevel::info;
}

}  // namespace argos::observability
