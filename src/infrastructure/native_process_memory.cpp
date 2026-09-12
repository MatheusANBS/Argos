#include "argos_mcp/infrastructure/native_process_memory.hpp"

#include "argos_mcp/infrastructure/output_ring_buffer.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
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
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
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

[[nodiscard]] Result<std::size_t> windows_read_memory(HANDLE handle, Address address, std::span<std::byte> output) {
    SIZE_T read_count = 0;
    if (output.empty()) {
        return std::size_t{0};
    }
    const auto* remote = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address));
    if (!ReadProcessMemory(handle, remote, output.data(), output.size(), &read_count)) {
        return std::unexpected(error(DebugErrorCode::io_error, "ReadProcessMemory failed"));
    }
    return static_cast<std::size_t>(read_count);
}

[[nodiscard]] Result<std::size_t> windows_write_memory(HANDLE handle, Address address, std::span<const std::byte> input) {
    SIZE_T written = 0;
    auto* remote = reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
    if (!WriteProcessMemory(handle, remote, input.data(), input.size(), &written)) {
        return std::unexpected(error(DebugErrorCode::io_error, "WriteProcessMemory failed"));
    }
    return static_cast<std::size_t>(written);
}

[[nodiscard]] Result<std::vector<MemoryRegion>> windows_query_regions(HANDLE handle) {
    std::vector<MemoryRegion> output;
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    auto current = reinterpret_cast<std::uintptr_t>(info.lpMinimumApplicationAddress);
    const auto maximum = reinterpret_cast<std::uintptr_t>(info.lpMaximumApplicationAddress);
    while (current < maximum) {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T queried = VirtualQueryEx(
            handle, reinterpret_cast<const void*>(current), &mbi, sizeof(mbi)
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

[[nodiscard]] Result<std::vector<ModuleInfo>> windows_query_modules(ProcessId pid) {
    UniqueHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)};
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

class WindowsProcessSession final : public ProcessSession {
public:
    WindowsProcessSession(
        ProcessId pid,
        std::string name,
        AccessMode access,
        UniqueHandle handle,
        bool debug_bridge_enabled
    ) : pid_(pid),
        name_(std::move(name)),
        access_(access),
        handle_(std::move(handle)),
        debug_bridge_enabled_(debug_bridge_enabled) {}

    [[nodiscard]] ProcessId pid() const noexcept override { return pid_; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return name_; }
    [[nodiscard]] AccessMode access_mode() const noexcept override { return access_; }

    [[nodiscard]] Result<std::size_t> read(Address address, std::span<std::byte> output) const override {
        return windows_read_memory(handle_.get(), address, output);
    }

    [[nodiscard]] Result<std::size_t> write(Address address, std::span<const std::byte> input) override {
        if (access_ != AccessMode::read_write) {
            return std::unexpected(error(DebugErrorCode::access_denied, "session is read-only"));
        }
        return windows_write_memory(handle_.get(), address, input);
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> regions() const override {
        return windows_query_regions(handle_.get());
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() const override {
        return windows_query_modules(pid_);
    }

    [[nodiscard]] Result<domain::InjectedDebugBridge> inject_debug_bridge(
        const domain::DebugBridgeSpec& spec
    ) override;

private:
    ProcessId pid_{};
    std::string name_;
    AccessMode access_{AccessMode::read_only};
    UniqueHandle handle_;
    bool debug_bridge_enabled_{false};
};

[[nodiscard]] std::wstring utf8_to_wide(std::string_view input) {
    if (input.empty()) {
        return {};
    }
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return {};
    }
    const auto input_size = static_cast<int>(input.size());
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), input_size, nullptr, 0);
    if (size <= 0) {
        return {};
    }
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), input_size, output.data(), size) != size) {
        return {};
    }
    return output;
}

class RemoteAllocation final {
public:
    RemoteAllocation(HANDLE process, void* address) noexcept : process_(process), address_(address) {}
    ~RemoteAllocation() {
        if (address_ != nullptr) {
            VirtualFreeEx(process_, address_, 0U, MEM_RELEASE);
        }
    }

    RemoteAllocation(const RemoteAllocation&) = delete;
    RemoteAllocation& operator=(const RemoteAllocation&) = delete;

private:
    HANDLE process_{};
    void* address_{};
};

Result<domain::InjectedDebugBridge> WindowsProcessSession::inject_debug_bridge(
    const domain::DebugBridgeSpec& spec
) {
    if (!debug_bridge_enabled_) {
        return std::unexpected(error(
            DebugErrorCode::access_denied, "debug bridge injection is disabled for this session"
        ));
    }
    const std::filesystem::path requested_path{spec.path};
    std::error_code filesystem_error;
    const auto canonical_path = std::filesystem::weakly_canonical(requested_path, filesystem_error);
    if (filesystem_error || !std::filesystem::is_regular_file(canonical_path, filesystem_error) || filesystem_error) {
        return std::unexpected(error(
            DebugErrorCode::not_found, "debug bridge does not exist or is not a regular file"
        ));
    }
    const auto find_loaded_bridge = [this, &canonical_path]() -> Result<std::optional<domain::InjectedDebugBridge>> {
        auto loaded_modules = windows_query_modules(pid_);
        if (!loaded_modules) {
            return std::unexpected(loaded_modules.error());
        }
        const auto expected_path = canonical_path.lexically_normal();
        for (const auto& module : *loaded_modules) {
            std::error_code module_error;
            const auto module_path = std::filesystem::weakly_canonical(module.path, module_error);
            if (!module_error && module_path.lexically_normal() == expected_path) {
                return domain::InjectedDebugBridge{pid_, module.name, module.base};
            }
        }
        return std::optional<domain::InjectedDebugBridge>{};
    };
    auto already_loaded = find_loaded_bridge();
    if (!already_loaded) {
        return std::unexpected(already_loaded.error());
    }
    if (*already_loaded) {
        return **already_loaded;
    }
    const std::wstring wide_path{canonical_path.native()};
    if (wide_path.empty() || wide_path.size() >= static_cast<std::size_t>(std::numeric_limits<DWORD>::max())) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "debug bridge path is invalid"));
    }
    const std::size_t byte_count = (wide_path.size() + 1U) * sizeof(wchar_t);
    void* remote_path = VirtualAllocEx(
        handle_.get(), nullptr, byte_count, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );
    if (remote_path == nullptr) {
        return std::unexpected(error(DebugErrorCode::io_error, "debug bridge allocation failed"));
    }
    RemoteAllocation allocation{handle_.get(), remote_path};
    SIZE_T bytes_written = 0U;
    if (!WriteProcessMemory(handle_.get(), remote_path, wide_path.c_str(), byte_count, &bytes_written) ||
        bytes_written != byte_count) {
        return std::unexpected(error(DebugErrorCode::io_error, "debug bridge path write failed"));
    }
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto loader = kernel32 == nullptr ? nullptr : GetProcAddress(kernel32, "LoadLibraryW");
    if (loader == nullptr) {
        return std::unexpected(error(DebugErrorCode::invalid_state, "system loader is unavailable"));
    }
    UniqueHandle thread{CreateRemoteThread(
        handle_.get(), nullptr, 0U, reinterpret_cast<LPTHREAD_START_ROUTINE>(loader), remote_path, 0U, nullptr
    )};
    if (!thread) {
        return std::unexpected(error(DebugErrorCode::io_error, "debug bridge loader thread could not be created"));
    }
    // The bridge is first-party and its DllMain must be constant-time. Waiting
    // here prevents releasing the remote UTF-16 buffer while LoadLibraryW is
    // still consuming it; no target memory is left behind on success.
    if (WaitForSingleObject(thread.get(), INFINITE) != WAIT_OBJECT_0) {
        return std::unexpected(error(DebugErrorCode::io_error, "debug bridge loader thread did not complete"));
    }
    auto injected_bridge = find_loaded_bridge();
    if (!injected_bridge) {
        return std::unexpected(injected_bridge.error());
    }
    if (*injected_bridge) {
        return **injected_bridge;
    }
    return std::unexpected(error(DebugErrorCode::io_error, "debug bridge was not loaded by the target"));
}

// Implements the argument-quoting rules documented by Microsoft for
// CommandLineToArgvW / the Visual C++ runtime so that argv reaches the child
// process exactly as provided -- never via a shell, never by naive string
// concatenation. See "Everyone quotes command line arguments the wrong way".
[[nodiscard]] std::wstring quote_windows_argument(const std::wstring& argument) {
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }
    std::wstring output(1, L'"');
    for (auto it = argument.begin(); ; ++it) {
        std::size_t backslash_count = 0;
        while (it != argument.end() && *it == L'\\') {
            ++it;
            ++backslash_count;
        }
        if (it == argument.end()) {
            output.append(backslash_count * 2U, L'\\');
            break;
        }
        if (*it == L'"') {
            output.append(backslash_count * 2U + 1U, L'\\');
            output.push_back(*it);
        } else {
            output.append(backslash_count, L'\\');
            output.push_back(*it);
        }
    }
    output.push_back(L'"');
    return output;
}

[[nodiscard]] std::wstring build_windows_command_line(
    const std::wstring& executable,
    const std::vector<std::string>& arguments
) {
    std::wstring command_line = quote_windows_argument(executable);
    for (const auto& argument : arguments) {
        command_line.push_back(L' ');
        command_line += quote_windows_argument(utf8_to_wide(argument));
    }
    return command_line;
}

// Captured child-process output is untrusted bytes that end up embedded in a
// JSON-RPC response on the MCP's own stdout. json::Value::dump() does not
// validate UTF-8 (the same responsibility utf8_from_wide already carries at
// every other native boundary in this file), so invalid or truncated
// multi-byte sequences and stray control bytes are replaced here before
// anything is appended to a capture buffer.
[[nodiscard]] std::string sanitize_utf8(std::string_view input) {
    std::string output;
    output.reserve(input.size());
    std::size_t index = 0;
    while (index < input.size()) {
        const auto byte0 = static_cast<unsigned char>(input[index]);
        if (byte0 == '\n' || byte0 == '\r' || byte0 == '\t') {
            output.push_back(static_cast<char>(byte0));
            ++index;
            continue;
        }
        if (byte0 < 0x20U || byte0 == 0x7FU) {
            ++index;
            continue;
        }
        if (byte0 < 0x80U) {
            output.push_back(static_cast<char>(byte0));
            ++index;
            continue;
        }
        std::size_t continuation_length = 0;
        unsigned char first_data_mask = 0;
        std::uint32_t codepoint_min = 0;
        if ((byte0 & 0xE0U) == 0xC0U) {
            continuation_length = 1U;
            first_data_mask = 0x1FU;
            codepoint_min = 0x80U;
        } else if ((byte0 & 0xF0U) == 0xE0U) {
            continuation_length = 2U;
            first_data_mask = 0x0FU;
            codepoint_min = 0x800U;
        } else if ((byte0 & 0xF8U) == 0xF0U) {
            continuation_length = 3U;
            first_data_mask = 0x07U;
            codepoint_min = 0x10000U;
        } else {
            output.push_back('?');
            ++index;
            continue;
        }

        bool valid = index + continuation_length < input.size();
        std::uint32_t codepoint = byte0 & first_data_mask;
        if (valid) {
            for (std::size_t offset = 1; offset <= continuation_length; ++offset) {
                const auto continuation = static_cast<unsigned char>(input[index + offset]);
                if ((continuation & 0xC0U) != 0x80U) {
                    valid = false;
                    break;
                }
                codepoint = (codepoint << 6U) | (continuation & 0x3FU);
            }
        }
        if (valid && codepoint >= codepoint_min && codepoint <= 0x10FFFFU &&
            !(codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            output.append(input.substr(index, continuation_length + 1U));
            index += continuation_length + 1U;
        } else {
            output.push_back('?');
            ++index;
        }
    }
    return output;
}

class WindowsLaunchedProcessSession final : public domain::LaunchedProcessSession {
public:
    WindowsLaunchedProcessSession(
        ProcessId pid,
        std::string name,
        AccessMode access,
        UniqueHandle process,
        UniqueHandle stdout_read,
        UniqueHandle stderr_read,
        std::size_t max_captured_output_bytes
    ) : pid_(pid), name_(std::move(name)), access_(access), process_(std::move(process)),
        stdout_read_(std::move(stdout_read)), stderr_read_(std::move(stderr_read)),
        stdout_buffer_(max_captured_output_bytes), stderr_buffer_(max_captured_output_bytes) {
        stdout_thread_ = std::jthread{[this](const std::stop_token stop) {
            pump(stdout_read_.get(), stdout_buffer_, stdout_mutex_, stop);
        }};
        stderr_thread_ = std::jthread{[this](const std::stop_token stop) {
            pump(stderr_read_.get(), stderr_buffer_, stderr_mutex_, stop);
        }};
    }

    ~WindowsLaunchedProcessSession() override {
        // Cancel synchronous I/O on the owning threads before closing either
        // handle. Closing a handle concurrently with ReadFile can race with the
        // in-flight call; CancelSynchronousIo + cooperative stop gives each
        // pump a defined exit and lets us join before destroying its state.
        stdout_thread_.request_stop();
        stderr_thread_.request_stop();
        if (stdout_thread_.joinable()) {
            static_cast<void>(CancelSynchronousIo(stdout_thread_.native_handle()));
        }
        if (stderr_thread_.joinable()) {
            static_cast<void>(CancelSynchronousIo(stderr_thread_.native_handle()));
        }
        if (stdout_thread_.joinable()) stdout_thread_.join();
        if (stderr_thread_.joinable()) stderr_thread_.join();
        stdout_read_.reset();
        stderr_read_.reset();
    }

    WindowsLaunchedProcessSession(const WindowsLaunchedProcessSession&) = delete;
    WindowsLaunchedProcessSession& operator=(const WindowsLaunchedProcessSession&) = delete;

    [[nodiscard]] ProcessId pid() const noexcept override { return pid_; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return name_; }
    [[nodiscard]] AccessMode access_mode() const noexcept override { return access_; }

    [[nodiscard]] Result<std::size_t> read(Address address, std::span<std::byte> output) const override {
        return windows_read_memory(process_.get(), address, output);
    }

    [[nodiscard]] Result<std::size_t> write(Address address, std::span<const std::byte> input) override {
        if (access_ != AccessMode::read_write) {
            return std::unexpected(error(DebugErrorCode::access_denied, "session is read-only"));
        }
        return windows_write_memory(process_.get(), address, input);
    }

    [[nodiscard]] Result<std::vector<MemoryRegion>> regions() const override {
        return windows_query_regions(process_.get());
    }

    [[nodiscard]] Result<std::vector<ModuleInfo>> modules() const override {
        return windows_query_modules(pid_);
    }

    [[nodiscard]] Result<domain::OutputChunk> read_output(
        const std::uint64_t since_cursor,
        const std::size_t max_bytes
    ) override {
        const auto want_stdout = static_cast<std::uint32_t>(since_cursor >> 32U);
        const auto want_stderr = static_cast<std::uint32_t>(since_cursor & 0xFFFFFFFFU);

        infrastructure::OutputRingBuffer::ReadResult stdout_result;
        {
            std::scoped_lock lock(stdout_mutex_);
            stdout_result = stdout_buffer_.read(want_stdout, max_bytes);
        }
        const auto remaining_budget = max_bytes - std::min(max_bytes, stdout_result.text.size());
        infrastructure::OutputRingBuffer::ReadResult stderr_result;
        {
            std::scoped_lock lock(stderr_mutex_);
            stderr_result = stderr_buffer_.read(want_stderr, remaining_budget);
        }

        domain::OutputChunk chunk;
        chunk.stdout_text = std::move(stdout_result.text);
        chunk.stderr_text = std::move(stderr_result.text);
        chunk.cursor = (stdout_result.next_position << 32U) | (stderr_result.next_position & 0xFFFFFFFFU);
        chunk.process_alive = WaitForSingleObject(process_.get(), 0) == WAIT_TIMEOUT;
        return chunk;
    }

    [[nodiscard]] Result<void> terminate() override {
        if (!TerminateProcess(process_.get(), 1U)) {
            return std::unexpected(error(DebugErrorCode::io_error, "TerminateProcess failed"));
        }
        if (WaitForSingleObject(process_.get(), 2000U) != WAIT_OBJECT_0) {
            return std::unexpected(error(DebugErrorCode::io_error, "process did not terminate within timeout"));
        }
        return {};
    }

    [[nodiscard]] bool owned() const noexcept override { return true; }

private:
    void pump(
        HANDLE handle,
        infrastructure::OutputRingBuffer& buffer,
        std::mutex& guard,
        const std::stop_token stop
    ) {
        std::array<char, 4096> chunk{};
        while (!stop.stop_requested()) {
            // Anonymous pipes are synchronous. Peek first so ReadFile is only
            // issued for bytes already available; this avoids an unbounded
            // blocking read in the request_stop/CancelSynchronousIo race
            // window during session destruction.
            DWORD available = 0U;
            if (!PeekNamedPipe(handle, nullptr, 0U, nullptr, &available, nullptr)) {
                break;
            }
            if (available == 0U) {
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
                continue;
            }
            const DWORD request = std::min<DWORD>(available, static_cast<DWORD>(chunk.size()));
            DWORD read_count = 0U;
            if (!ReadFile(handle, chunk.data(), request, &read_count, nullptr) || read_count == 0U) {
                break;
            }
            const auto sanitized = sanitize_utf8(std::string_view{chunk.data(), read_count});
            std::scoped_lock lock(guard);
            buffer.append(sanitized);
        }
    }

    ProcessId pid_{};
    std::string name_;
    AccessMode access_{AccessMode::read_only};
    UniqueHandle process_;
    UniqueHandle stdout_read_;
    UniqueHandle stderr_read_;

    std::mutex stdout_mutex_;
    infrastructure::OutputRingBuffer stdout_buffer_;

    std::mutex stderr_mutex_;
    infrastructure::OutputRingBuffer stderr_buffer_;

    std::jthread stdout_thread_;
    std::jthread stderr_thread_;
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
    if (allow_debug_bridge_injection_) {
        rights |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;
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
        std::make_unique<WindowsProcessSession>(
            pid, std::move(name), access, std::move(handle), allow_debug_bridge_injection_
        )
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

domain::Result<std::unique_ptr<domain::LaunchedProcessSession>> NativeProcessMemoryProvider::launch(
    const domain::LaunchSpec& spec,
    const domain::AccessMode access
) const {
#if defined(_WIN32)
    const std::filesystem::path requested_path{spec.executable};
    if (!requested_path.is_absolute()) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "executable path must be absolute"));
    }
    for (const auto& argument : spec.arguments) {
        if (argument.find('\0') != std::string::npos) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "arguments must not contain null bytes"));
        }
    }
    std::error_code filesystem_error;
    const auto canonical_path = std::filesystem::weakly_canonical(requested_path, filesystem_error);
    if (filesystem_error || !std::filesystem::is_regular_file(canonical_path, filesystem_error) || filesystem_error) {
        return std::unexpected(error(
            DebugErrorCode::not_found, "executable does not exist or is not a regular file"
        ));
    }

    SECURITY_ATTRIBUTES inheritable_sa{};
    inheritable_sa.nLength = sizeof(inheritable_sa);
    inheritable_sa.bInheritHandle = TRUE;
    inheritable_sa.lpSecurityDescriptor = nullptr;

    HANDLE raw_stdout_read = nullptr;
    HANDLE raw_stdout_write = nullptr;
    if (!CreatePipe(&raw_stdout_read, &raw_stdout_write, &inheritable_sa, 0)) {
        return std::unexpected(error(DebugErrorCode::io_error, "CreatePipe failed for stdout"));
    }
    UniqueHandle stdout_read{raw_stdout_read};
    UniqueHandle stdout_write{raw_stdout_write};
    if (!SetHandleInformation(stdout_read.get(), HANDLE_FLAG_INHERIT, 0)) {
        return std::unexpected(error(DebugErrorCode::io_error, "SetHandleInformation failed for stdout"));
    }

    HANDLE raw_stderr_read = nullptr;
    HANDLE raw_stderr_write = nullptr;
    if (!CreatePipe(&raw_stderr_read, &raw_stderr_write, &inheritable_sa, 0)) {
        return std::unexpected(error(DebugErrorCode::io_error, "CreatePipe failed for stderr"));
    }
    UniqueHandle stderr_read{raw_stderr_read};
    UniqueHandle stderr_write{raw_stderr_write};
    if (!SetHandleInformation(stderr_read.get(), HANDLE_FLAG_INHERIT, 0)) {
        return std::unexpected(error(DebugErrorCode::io_error, "SetHandleInformation failed for stderr"));
    }

    UniqueHandle stdin_null{CreateFileW(
        L"NUL", GENERIC_READ, FILE_SHARE_READ, &inheritable_sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
    )};
    if (!stdin_null) {
        return std::unexpected(error(DebugErrorCode::io_error, "unable to open NUL for child stdin"));
    }

    // bInheritHandles=TRUE (required so the three pipe/NUL handles below
    // reach the child) would, by itself, inherit *every* inheritable handle
    // open in this process -- including the MCP's own stdin/stdout, which
    // are frequently inheritable by default when the MCP itself was
    // spawned by its client. An explicit PROC_THREAD_ATTRIBUTE_HANDLE_LIST
    // restricts inheritance to exactly these three handles, so a launched
    // child can never end up holding the MCP's own protocol pipe open
    // (which would otherwise keep that pipe alive, and the MCP's client
    // blocked waiting for EOF, for as long as the child keeps running).
    SIZE_T attribute_list_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attribute_list_size);
    if (attribute_list_size == 0U) {
        return std::unexpected(error(DebugErrorCode::io_error, "InitializeProcThreadAttributeList sizing failed"));
    }
    std::vector<std::byte> attribute_list_storage(attribute_list_size);
    auto* attribute_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attribute_list_storage.data());
    if (!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size)) {
        return std::unexpected(error(DebugErrorCode::io_error, "InitializeProcThreadAttributeList failed"));
    }
    struct AttributeListDeleter final {
        LPPROC_THREAD_ATTRIBUTE_LIST list;
        ~AttributeListDeleter() { DeleteProcThreadAttributeList(list); }
    } attribute_list_deleter{attribute_list};

    std::array<HANDLE, 3> inherited_handles{stdin_null.get(), stdout_write.get(), stderr_write.get()};
    if (!UpdateProcThreadAttribute(
            attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited_handles.data(), inherited_handles.size() * sizeof(HANDLE), nullptr, nullptr
        )) {
        return std::unexpected(error(DebugErrorCode::io_error, "UpdateProcThreadAttribute failed"));
    }

    STARTUPINFOEXW startup_info{};
    startup_info.StartupInfo.cb = sizeof(startup_info);
    startup_info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup_info.StartupInfo.hStdInput = stdin_null.get();
    startup_info.StartupInfo.hStdOutput = stdout_write.get();
    startup_info.StartupInfo.hStdError = stderr_write.get();
    startup_info.lpAttributeList = attribute_list;

    const auto wide_executable = canonical_path.wstring();
    if (wide_executable.empty()) {
        return std::unexpected(error(DebugErrorCode::invalid_argument, "executable path is not valid"));
    }
    const auto command_line = build_windows_command_line(wide_executable, spec.arguments);
    std::vector<wchar_t> command_line_buffer(command_line.begin(), command_line.end());
    command_line_buffer.push_back(L'\0');

    std::optional<std::wstring> wide_working_directory;
    if (spec.working_directory) {
        wide_working_directory = utf8_to_wide(*spec.working_directory);
        if (wide_working_directory->empty()) {
            return std::unexpected(error(DebugErrorCode::invalid_argument, "working_directory is not valid"));
        }
    }

    PROCESS_INFORMATION process_info{};
    const BOOL created = CreateProcessW(
        wide_executable.c_str(),
        command_line_buffer.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        wide_working_directory ? wide_working_directory->c_str() : nullptr,
        &startup_info.StartupInfo,
        &process_info
    );
    if (!created) {
        return std::unexpected(error(DebugErrorCode::io_error, "CreateProcessW failed"));
    }
    UniqueHandle process_handle{process_info.hProcess};
    UniqueHandle thread_handle{process_info.hThread};
    // The write ends (and the NUL read handle) now live only in the child's
    // handle table; closing the parent's copies here is what lets the
    // reader threads observe end-of-file once the child exits.
    stdout_write.reset();
    stderr_write.reset();
    stdin_null.reset();

    std::string name = canonical_path.filename().string();
    const std::size_t capture_capacity = spec.capture_output ? max_captured_output_bytes_ : 0U;
    return std::unique_ptr<domain::LaunchedProcessSession>{
        std::make_unique<WindowsLaunchedProcessSession>(
            static_cast<ProcessId>(process_info.dwProcessId), std::move(name), access,
            std::move(process_handle), std::move(stdout_read), std::move(stderr_read), capture_capacity
        )
    };
#else
    (void)spec;
    (void)access;
    return std::unexpected(error(DebugErrorCode::unsupported, "process launch requires Windows"));
#endif
}

}  // namespace argos::infrastructure
