#include "argos_mcp/infrastructure/native_process_memory.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#elif defined(__linux__)
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace argos::infrastructure {
namespace {

using argos::domain::AccessMode;
using argos::domain::Address;
using argos::domain::DebugError;
using argos::domain::DebugErrorCode;
using argos::domain::MemoryRegion;
using argos::domain::ModuleInfo;
using argos::domain::ProcessId;
using argos::domain::ProcessInfo;
using argos::domain::ProcessSession;
using argos::domain::Result;

[[nodiscard]] DebugError error(DebugErrorCode code, std::string message) {
    return DebugError{code, std::move(message)};
}

[[nodiscard]] bool contains_case_insensitive(std::string_view text, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    const auto lower = [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); };
    std::string lhs{text};
    std::string rhs{needle};
    std::ranges::transform(lhs, lhs.begin(), lower);
    std::ranges::transform(rhs, rhs.begin(), lower);
    return lhs.find(rhs) != std::string::npos;
}

#if defined(_WIN32)

class UniqueHandle final {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~UniqueHandle() { reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    void reset(HANDLE handle = nullptr) noexcept {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_{nullptr};
};

[[nodiscard]] std::string utf8_from_wide(std::wstring_view input) {
    if (input.empty()) {
        return {};
    }
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
        nullptr, 0, nullptr, nullptr
    );
    if (required <= 0) {
        return {};
    }
    std::string output(static_cast<std::size_t>(required), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
        output.data(), required, nullptr, nullptr
    );
    if (written != required) {
        return {};
    }
    return output;
}

[[nodiscard]] bool token_user_equal(HANDLE left_token, HANDLE right_token) {
    DWORD left_size = 0;
    DWORD right_size = 0;
    GetTokenInformation(left_token, TokenUser, nullptr, 0, &left_size);
    GetTokenInformation(right_token, TokenUser, nullptr, 0, &right_size);
    if (left_size == 0 || right_size == 0) {
        return false;
    }
    std::vector<std::byte> left(left_size);
    std::vector<std::byte> right(right_size);
    if (!GetTokenInformation(left_token, TokenUser, left.data(), left_size, &left_size) ||
        !GetTokenInformation(right_token, TokenUser, right.data(), right_size, &right_size)) {
        return false;
    }
    const auto* left_user = reinterpret_cast<const TOKEN_USER*>(left.data());
    const auto* right_user = reinterpret_cast<const TOKEN_USER*>(right.data());
    return EqualSid(left_user->User.Sid, right_user->User.Sid) != FALSE;
}

[[nodiscard]] bool is_same_user_process(ProcessId pid) {
    UniqueHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process) {
        return false;
    }
    UniqueHandle process_token;
    HANDLE raw_process_token = nullptr;
    if (!OpenProcessToken(process.get(), TOKEN_QUERY, &raw_process_token)) {
        return false;
    }
    process_token.reset(raw_process_token);

    UniqueHandle current_token;
    HANDLE raw_current_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_current_token)) {
        return false;
    }
    current_token.reset(raw_current_token);
    return token_user_equal(process_token.get(), current_token.get());
}

[[nodiscard]] std::optional<std::string> executable_path(HANDLE process) {
    std::wstring buffer(32768U, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size)) {
        return std::nullopt;
    }
    buffer.resize(size);
    return utf8_from_wide(buffer);
}

class WindowsProcessSession final : public ProcessSession {
public:
    WindowsProcessSession(ProcessId pid, std::string name, AccessMode access, UniqueHandle handle)
        : pid_(pid), name_(std::move(name)), access_(access), handle_(std::move(handle)) {}

    [[nodiscard]] ProcessId pid() const noexcept override { return pid_; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return name_; }
    [[nodiscard]] AccessMode access_mode() const noexcept override { return access_; }

    [[nodiscard]] Result<std::size_t> read(Address address, std::span<std::byte> output) const override {
        SIZE_T read_count = 0;
        if (output.empty()) {
            return std::size_t{0};
        }
        const auto* remote = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address));
        if (!ReadProcessMemory(handle_.get(), remote, output.data(), output.size(), &read_count)) {
            return std::unexpected(error(DebugErrorCode::io_error, "ReadProcessMemory failed"));
        }
        return static_cast<std::size_t>(read_count);
    }

    [[nodiscard]] Result<std::size_t> write(Address address, std::span<const std::byte> input) override {
        if (access_ != AccessMode::read_write) {
            return std::unexpected(error(DebugErrorCode::access_denied, "session is read-only"));
        }
        SIZE_T written = 0;
        auto* remote = reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
        if (!WriteProcessMemory(handle_.get(), remote, input.data(), input.size(), &written)) {
            return std::unexpected(error(DebugErrorCode::io_error, "WriteProcessMemory failed"));
        }
        return static_cast<std::size_t>(written);
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> regions() const override {
        std::vector<MemoryRegion> output;
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        auto current = reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
        const auto maximum = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
        while (current < maximum) {
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T queried = VirtualQueryEx(
                handle_.get(), reinterpret_cast<const void*>(current), &mbi, sizeof(mbi)
            );
            if (queried == 0) {
                break;
            }
            const auto base = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
            const auto end = base + mbi.RegionSize;
            const DWORD protection = mbi.Protect & 0xFFU;
            const bool committed = mbi.State == MEM_COMMIT;
            const bool guarded = (mbi.Protect & PAGE_GUARD) != 0U;
            const bool readable_protection =
                protection == PAGE_READONLY || protection == PAGE_READWRITE ||
                protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
            const bool readable = committed && !guarded && readable_protection;
            const bool writable = readable && (
                protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY
            );
            const bool executable = readable && (
                protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY
            );
            output.push_back(MemoryRegion{
                static_cast<Address>(base), static_cast<Address>(end), readable, writable,
                executable, mbi.Type == MEM_PRIVATE, {}
            });
            if (end <= current) {
                break;
            }
            current = end;
        }
        return output;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() const override {
        UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_)};
        if (!snapshot) {
            return std::unexpected(error(DebugErrorCode::io_error, "module snapshot failed"));
        }
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        std::vector<ModuleInfo> output;
        if (!Module32FirstW(snapshot.get(), &entry)) {
            return output;
        }
        do {
            output.push_back(ModuleInfo{
                utf8_from_wide(entry.szModule), utf8_from_wide(entry.szExePath),
                static_cast<Address>(reinterpret_cast<std::uintptr_t>(entry.modBaseAddr)),
                static_cast<std::uint64_t>(entry.modBaseSize)
            });
        } while (Module32NextW(snapshot.get(), &entry));
        return output;
    }

private:
    ProcessId pid_{};
    std::string name_;
    AccessMode access_{AccessMode::read_only};
    UniqueHandle handle_;
};

#elif defined(__linux__)

[[nodiscard]] std::optional<ProcessId> parse_pid(std::string_view value) {
    if (value.empty() || !std::ranges::all_of(value, [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
        return std::nullopt;
    }
    std::uint64_t parsed = 0;
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size() ||
        parsed > std::numeric_limits<ProcessId>::max()) {
        return std::nullopt;
    }
    return static_cast<ProcessId>(parsed);
}

[[nodiscard]] std::string read_first_line(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::string line;
    std::getline(input, line);
    return line;
}

[[nodiscard]] std::optional<std::string> read_symlink_utf8(const std::filesystem::path& path) {
    std::error_code ec;
    const auto target = std::filesystem::read_symlink(path, ec);
    if (ec) {
        return std::nullopt;
    }
    return target.string();
}

[[nodiscard]] bool is_same_user_process(ProcessId pid) {
    struct stat process_stat {};
    const std::string path = "/proc/" + std::to_string(pid);
    if (::stat(path.c_str(), &process_stat) != 0) {
        return false;
    }
    return process_stat.st_uid == ::geteuid();
}

class LinuxProcessSession final : public ProcessSession {
public:
    LinuxProcessSession(ProcessId pid, std::string name, AccessMode access)
        : pid_(pid), name_(std::move(name)), access_(access) {}

    [[nodiscard]] ProcessId pid() const noexcept override { return pid_; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return name_; }
    [[nodiscard]] AccessMode access_mode() const noexcept override { return access_; }

    [[nodiscard]] Result<std::size_t> read(Address address, std::span<std::byte> output) const override {
        if (output.empty()) {
            return std::size_t{0};
        }
        iovec local{output.data(), output.size()};
        iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)), output.size()};
        const ssize_t count = ::process_vm_readv(
            static_cast<pid_t>(pid_), &local, 1, &remote, 1, 0
        );
        if (count < 0) {
            return std::unexpected(error(DebugErrorCode::io_error, "process_vm_readv failed"));
        }
        return static_cast<std::size_t>(count);
    }

    [[nodiscard]] Result<std::size_t> write(Address address, std::span<const std::byte> input) override {
        if (access_ != AccessMode::read_write) {
            return std::unexpected(error(DebugErrorCode::access_denied, "session is read-only"));
        }
        if (input.empty()) {
            return std::size_t{0};
        }
        iovec local{const_cast<std::byte*>(input.data()), input.size()};
        iovec remote{reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)), input.size()};
        const ssize_t count = ::process_vm_writev(
            static_cast<pid_t>(pid_), &local, 1, &remote, 1, 0
        );
        if (count < 0) {
            return std::unexpected(error(DebugErrorCode::io_error, "process_vm_writev failed"));
        }
        return static_cast<std::size_t>(count);
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> regions() const override {
        const std::string path = "/proc/" + std::to_string(pid_) + "/maps";
        std::ifstream input(path);
        if (!input) {
            return std::unexpected(error(DebugErrorCode::io_error, "unable to read process memory map"));
        }
        std::vector<MemoryRegion> output;
        std::string line;
        while (std::getline(input, line)) {
            std::istringstream stream(line);
            std::string range;
            std::string permissions;
            std::string offset;
            std::string device;
            std::string inode;
            if (!(stream >> range >> permissions >> offset >> device >> inode)) {
                continue;
            }
            std::string name;
            std::getline(stream, name);
            const auto first_non_space = name.find_first_not_of(' ');
            if (first_non_space != std::string::npos) {
                name.erase(0, first_non_space);
            } else {
                name.clear();
            }
            const auto dash = range.find('-');
            if (dash == std::string::npos) {
                continue;
            }
            Address start = 0;
            Address end = 0;
            const auto start_text = std::string_view(range).substr(0, dash);
            const auto end_text = std::string_view(range).substr(dash + 1U);
            const auto [start_ptr, start_ec] = std::from_chars(
                start_text.data(), start_text.data() + start_text.size(), start, 16
            );
            const auto [end_ptr, end_ec] = std::from_chars(
                end_text.data(), end_text.data() + end_text.size(), end, 16
            );
            if (start_ec != std::errc{} || end_ec != std::errc{} ||
                start_ptr != start_text.data() + start_text.size() ||
                end_ptr != end_text.data() + end_text.size()) {
                continue;
            }
            output.push_back(MemoryRegion{
                start, end,
                permissions.size() > 0U && permissions[0] == 'r',
                permissions.size() > 1U && permissions[1] == 'w',
                permissions.size() > 2U && permissions[2] == 'x',
                permissions.size() > 3U && permissions[3] == 'p',
                std::move(name)
            });
        }
        return output;
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() const override {
        auto region_result = regions();
        if (!region_result) {
            return std::unexpected(region_result.error());
        }
        struct Aggregate {
            Address min{std::numeric_limits<Address>::max()};
            Address max{0};
        };
        std::map<std::string, Aggregate> aggregates;
        for (const auto& region : *region_result) {
            if (region.name.empty() || region.name.front() != '/') {
                continue;
            }
            auto& aggregate = aggregates[region.name];
            aggregate.min = std::min(aggregate.min, region.start);
            aggregate.max = std::max(aggregate.max, region.end);
        }
        std::vector<ModuleInfo> output;
        output.reserve(aggregates.size());
        for (const auto& [path, aggregate] : aggregates) {
            output.push_back(ModuleInfo{
                std::filesystem::path(path).filename().string(), path,
                aggregate.min, aggregate.max - aggregate.min
            });
        }
        return output;
    }

private:
    ProcessId pid_{};
    std::string name_;
    AccessMode access_{AccessMode::read_only};
};

#endif

}  // namespace

domain::Result<std::vector<domain::ProcessInfo>> NativeProcessMemoryProvider::list_processes(
    std::string_view filter,
    std::size_t limit
) const {
    if (limit == 0U || limit > 4096U) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "limit must be between 1 and 4096"));
    }
    std::vector<ProcessInfo> output;
#if defined(_WIN32)
    UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snapshot) {
        return std::unexpected(error(DebugErrorCode::io_error, "process snapshot failed"));
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return output;
    }
    do {
        const auto pid = static_cast<ProcessId>(entry.th32ProcessID);
        const std::string name = utf8_from_wide(entry.szExeFile);
        if (!contains_case_insensitive(name, filter)) {
            continue;
        }
        UniqueHandle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
        output.push_back(ProcessInfo{
            pid, name, process ? executable_path(process.get()) : std::nullopt,
            is_same_user_process(pid)
        });
        if (output.size() >= limit) {
            break;
        }
    } while (Process32NextW(snapshot.get(), &entry));
#elif defined(__linux__)
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        if (ec) {
            return std::unexpected(error(DebugErrorCode::io_error, "unable to enumerate /proc"));
        }
        const auto pid = parse_pid(entry.path().filename().string());
        if (!pid) {
            continue;
        }
        const std::string name = read_first_line(entry.path() / "comm");
        if (!contains_case_insensitive(name, filter)) {
            continue;
        }
        output.push_back(ProcessInfo{
            *pid, name, read_symlink_utf8(entry.path() / "exe"), is_same_user_process(*pid)
        });
        if (output.size() >= limit) {
            break;
        }
    }
#else
    (void)filter;
    return std::unexpected(error(DebugErrorCode::unsupported, "platform is not supported"));
#endif
    std::ranges::sort(output, {}, &ProcessInfo::pid);
    return output;
}

domain::Result<std::unique_ptr<domain::ProcessSession>> NativeProcessMemoryProvider::attach(
    domain::ProcessId pid,
    domain::AccessMode access
) const {
    if (pid == 0U) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "pid must be greater than zero"));
    }
    if (!allow_foreign_user_ && !is_same_user_process(pid)) {
        return std::unexpected(error(
            DebugErrorCode::unauthorized,
            "target process is not owned by the current user or cannot be verified"
        ));
    }
#if defined(_WIN32)
    DWORD rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
    if (access == AccessMode::read_write) {
        rights |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    }
    UniqueHandle handle{OpenProcess(rights, FALSE, pid)};
    if (!handle) {
        return std::unexpected(error(DebugErrorCode::access_denied, "OpenProcess failed"));
    }
    std::string name = "pid-" + std::to_string(pid);
    const auto path = executable_path(handle.get());
    if (path) {
        name = std::filesystem::path(*path).filename().string();
    }
    return std::unique_ptr<ProcessSession>{
        std::make_unique<WindowsProcessSession>(pid, std::move(name), access, std::move(handle))
    };
#elif defined(__linux__)
    const std::filesystem::path root = "/proc/" + std::to_string(pid);
    std::error_code ec;
    if (!std::filesystem::exists(root, ec) || ec) {
        return std::unexpected(error(DebugErrorCode::not_found, "process does not exist"));
    }
    const std::string name = read_first_line(root / "comm");
    return std::unique_ptr<ProcessSession>{
        std::make_unique<LinuxProcessSession>(pid, name, access)
    };
#else
    (void)access;
    return std::unexpected(error(DebugErrorCode::unsupported, "platform is not supported"));
#endif
}

}  // namespace argos::infrastructure
