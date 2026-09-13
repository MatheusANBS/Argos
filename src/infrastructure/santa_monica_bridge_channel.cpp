#include "argos_mcp/infrastructure/santa_monica_bridge_channel.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <new>
#include <utility>
#include <string>
#include <vector>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#endif

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;

constexpr std::chrono::milliseconds wait_slice{25};
constexpr std::size_t endpoint_random_bytes = 16;
constexpr std::size_t peer_secret_bytes = 32;

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica bridge channel failed", reason};
}

#if defined(_WIN32)

class UniqueHandle final {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(const HANDLE handle) noexcept : handle_(handle) {}
    UniqueHandle(UniqueHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    ~UniqueHandle() { reset(); }

    void reset(const HANDLE handle = nullptr) noexcept {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_);
        handle_ = handle;
    }
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_{nullptr};
};

class LocalFreeGuard final {
public:
    explicit LocalFreeGuard(void* memory) noexcept : memory_(memory) {}
    LocalFreeGuard(const LocalFreeGuard&) = delete;
    LocalFreeGuard& operator=(const LocalFreeGuard&) = delete;
    ~LocalFreeGuard() {
        if (memory_ != nullptr) LocalFree(memory_);
    }

private:
    void* memory_;
};

[[nodiscard]] std::wstring wide_from_utf8(const std::string_view input) {
    if (input.empty()) return {};
    const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                             static_cast<int>(input.size()), nullptr, 0);
    if (required <= 0) return {};
    std::wstring output(static_cast<std::size_t>(required), L'\0');
    const int written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                            static_cast<int>(input.size()), output.data(), required);
    if (written != required) return {};
    return output;
}

// The DACL, not a later comparison, is what keeps other users out.
[[nodiscard]] Result<std::wstring> current_user_sid() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_identity_unavailable"));
    }
    UniqueHandle token{raw_token};
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    if (size == 0) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_identity_unavailable"));
    }
    std::vector<std::byte> buffer(size);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), size, &size)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_identity_unavailable"));
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR raw_sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &raw_sid)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_identity_unavailable"));
    }
    const LocalFreeGuard guard{raw_sid};
    return std::wstring{raw_sid};
}

[[nodiscard]] Result<std::string> random_endpoint(domain::santamonica::RandomSource& random) {
    std::array<std::byte, endpoint_random_bytes> bytes{};
    auto filled = random.fill(bytes);
    if (!filled) return std::unexpected(fail(DebugErrorCode::io_error, "channel_random_unavailable"));
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string name = "\\\\.\\pipe\\argos-santamonica-";
    for (const auto byte : bytes) {
        const auto value = static_cast<unsigned char>(byte);
        name.push_back(digits[value >> 4U]);
        name.push_back(digits[value & 0x0FU]);
    }
    return name;
}

#endif  // defined(_WIN32)

}  // namespace

#if defined(_WIN32)

struct LocalBridgeChannel::Native {
    UniqueHandle pipe;
    bool server{false};
    bool connected{false};
};

struct BridgePeerProcess::Native {
    UniqueHandle process;
    UniqueHandle thread;
};

namespace {

// Waits in slices so a deadline or a stop request is honored even while the
// peer is silent. A timeout cancels the operation and waits for it to settle
// before the caller's buffer can go out of scope.
[[nodiscard]] Result<DWORD> await_overlapped(
    const HANDLE handle, OVERLAPPED& overlapped, const LocalBridgeChannel::Clock::time_point deadline,
    const std::stop_token& cancellation, const char* timeout_reason) {
    while (true) {
        if (cancellation.stop_requested()) {
            CancelIoEx(handle, &overlapped);
            DWORD drained = 0;
            GetOverlappedResult(handle, &overlapped, &drained, TRUE);
            return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        const auto now = LocalBridgeChannel::Clock::now();
        if (now >= deadline) {
            CancelIoEx(handle, &overlapped);
            DWORD drained = 0;
            GetOverlappedResult(handle, &overlapped, &drained, TRUE);
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, timeout_reason));
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto slice = std::min(remaining, wait_slice);
        const auto status = WaitForSingleObject(overlapped.hEvent, static_cast<DWORD>(slice.count()));
        if (status == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            if (!GetOverlappedResult(handle, &overlapped, &transferred, FALSE)) {
                return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
            }
            return transferred;
        }
        if (status != WAIT_TIMEOUT) {
            CancelIoEx(handle, &overlapped);
            DWORD drained = 0;
            GetOverlappedResult(handle, &overlapped, &drained, TRUE);
            return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
        }
    }
}

}  // namespace

LocalBridgeChannel::LocalBridgeChannel(
    std::unique_ptr<Native> native, std::string endpoint, ChannelLimits limits)
    : native_(std::move(native)), endpoint_(std::move(endpoint)), limits_(limits) {}

LocalBridgeChannel::~LocalBridgeChannel() { close(); }

Result<std::unique_ptr<LocalBridgeChannel>> LocalBridgeChannel::listen(
    domain::santamonica::RandomSource& random, const ChannelLimits limits) {
    if (limits.connect_timeout <= std::chrono::milliseconds::zero() ||
        limits.io_timeout <= std::chrono::milliseconds::zero()) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_channel_limits"));
    }
    auto name = random_endpoint(random);
    if (!name) return std::unexpected(name.error());
    auto sid = current_user_sid();
    if (!sid) return std::unexpected(sid.error());

    // Protected DACL with a single ACE: only this user may open the pipe.
    const std::wstring descriptor = L"D:P(A;;GA;;;" + *sid + L")";
    PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.c_str(), SDDL_REVISION_1,
                                                              &raw_descriptor, nullptr)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_acl_unavailable"));
    }
    const LocalFreeGuard descriptor_guard{raw_descriptor};
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = raw_descriptor;
    attributes.bInheritHandle = FALSE;

    const auto wide_name = wide_from_utf8(*name);
    UniqueHandle pipe{CreateNamedPipeW(
        wide_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64U * 1024U, 64U * 1024U, 0, &attributes)};
    if (!pipe.valid()) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_unavailable"));
    }
    try {
        auto native = std::make_unique<Native>();
        native->pipe = std::move(pipe);
        native->server = true;
        return std::unique_ptr<LocalBridgeChannel>(
            new LocalBridgeChannel(std::move(native), std::move(*name), limits));
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

Result<std::unique_ptr<LocalBridgeChannel>> LocalBridgeChannel::connect(
    const std::string_view endpoint, const ChannelLimits limits) {
    if (endpoint.empty() || endpoint.size() > 256) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_endpoint"));
    }
    if (limits.connect_timeout <= std::chrono::milliseconds::zero() ||
        limits.io_timeout <= std::chrono::milliseconds::zero()) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_channel_limits"));
    }
    const auto wide_name = wide_from_utf8(endpoint);
    if (wide_name.empty()) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_endpoint"));
    }
    UniqueHandle pipe{CreateFileW(wide_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr)};
    if (!pipe.valid()) {
        return std::unexpected(fail(DebugErrorCode::not_found, "channel_unavailable"));
    }
    try {
        auto native = std::make_unique<Native>();
        native->pipe = std::move(pipe);
        native->server = false;
        native->connected = true;
        return std::unique_ptr<LocalBridgeChannel>(
            new LocalBridgeChannel(std::move(native), std::string{endpoint}, limits));
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

Result<void> LocalBridgeChannel::accept(
    const domain::ProcessId expected_pid, const Clock::time_point deadline,
    const std::stop_token cancellation) {
    if (!native_ || !native_->pipe.valid() || !native_->server) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "channel_state"));
    }
    if (native_->connected) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "channel_state"));
    }
    UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!event.valid()) {
        return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    if (!ConnectNamedPipe(native_->pipe.get(), &overlapped)) {
        const auto error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) {
            native_->connected = true;
        } else if (error == ERROR_IO_PENDING) {
            auto waited = await_overlapped(native_->pipe.get(), overlapped, deadline, cancellation,
                                           "channel_connect_timeout");
            if (!waited) return std::unexpected(waited.error());
            native_->connected = true;
        } else {
            return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
        }
    } else {
        native_->connected = true;
    }

    if (expected_pid != 0) {
        ULONG peer = 0;
        if (!GetNamedPipeClientProcessId(native_->pipe.get(), &peer)) {
            close();
            return std::unexpected(fail(DebugErrorCode::io_error, "channel_peer_unknown"));
        }
        if (static_cast<domain::ProcessId>(peer) != expected_pid) {
            close();
            return std::unexpected(fail(DebugErrorCode::unauthorized, "unexpected_peer_process"));
        }
    }
    return {};
}

Result<std::size_t> LocalBridgeChannel::read(
    const std::span<std::byte> destination, const Clock::time_point deadline,
    const std::stop_token cancellation) {
    if (!native_ || !native_->pipe.valid() || !native_->connected) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "channel_state"));
    }
    if (destination.empty()) return std::size_t{0};
    const auto wanted = static_cast<DWORD>(
        std::min<std::size_t>(destination.size(), (std::numeric_limits<DWORD>::max)()));
    UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    if (!event.valid()) return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD read_bytes = 0;
    if (!ReadFile(native_->pipe.get(), destination.data(), wanted, &read_bytes, &overlapped)) {
        const auto error = GetLastError();
        if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) return std::size_t{0};
        if (error != ERROR_IO_PENDING) {
            return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
        }
        auto waited = await_overlapped(native_->pipe.get(), overlapped, deadline, cancellation,
                                       "channel_read_timeout");
        if (!waited) return std::unexpected(waited.error());
        read_bytes = *waited;
    }
    return static_cast<std::size_t>(read_bytes);
}

Result<void> LocalBridgeChannel::write(
    const std::span<const std::byte> bytes, const Clock::time_point deadline,
    const std::stop_token cancellation) {
    if (!native_ || !native_->pipe.valid() || !native_->connected) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "channel_state"));
    }
    auto pending = bytes;
    while (!pending.empty()) {
        const auto wanted = static_cast<DWORD>(
            std::min<std::size_t>(pending.size(), (std::numeric_limits<DWORD>::max)()));
        UniqueHandle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        if (!event.valid()) return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();
        DWORD written = 0;
        if (!WriteFile(native_->pipe.get(), pending.data(), wanted, &written, &overlapped)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
            }
            auto waited = await_overlapped(native_->pipe.get(), overlapped, deadline, cancellation,
                                           "channel_write_timeout");
            if (!waited) return std::unexpected(waited.error());
            written = *waited;
        }
        if (written == 0) return std::unexpected(fail(DebugErrorCode::io_error, "channel_io_failed"));
        pending = pending.subspan(written);
    }
    return {};
}

void LocalBridgeChannel::close() noexcept {
    if (!native_) return;
    if (native_->pipe.valid()) {
        CancelIoEx(native_->pipe.get(), nullptr);
        if (native_->server && native_->connected) {
            FlushFileBuffers(native_->pipe.get());
            DisconnectNamedPipe(native_->pipe.get());
        }
    }
    native_->connected = false;
    native_->pipe.reset();
}

BridgePeerProcess::BridgePeerProcess(std::unique_ptr<Native> native, const domain::ProcessId pid)
    : native_(std::move(native)), pid_(pid) {}

BridgePeerProcess::~BridgePeerProcess() { terminate(); }

void BridgePeerProcess::terminate() noexcept {
    if (!native_ || !native_->process.valid()) return;
    if (WaitForSingleObject(native_->process.get(), 0) == WAIT_TIMEOUT) {
        TerminateProcess(native_->process.get(), 1);
        WaitForSingleObject(native_->process.get(), 2000);
    }
    native_->thread.reset();
    native_->process.reset();
}

Result<std::unique_ptr<BridgePeerProcess>> BridgePeerProcess::spawn(
    const std::string_view executable_path, const PeerLaunch& launch,
    const std::span<const std::byte> secret) {
    if (executable_path.empty() || executable_path.size() > 32768) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_peer_path"));
    }
    if (launch.endpoint.empty() || launch.endpoint.size() > 256 ||
        !domain::santamonica::valid_identity_token(launch.process_instance) ||
        !domain::santamonica::valid_identity_token(launch.bridge_epoch) || launch.request_id == 0) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_endpoint"));
    }
    if (secret.size() != peer_secret_bytes) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_secret_length"));
    }

    SECURITY_ATTRIBUTES inheritable{};
    inheritable.nLength = sizeof(inheritable);
    inheritable.bInheritHandle = TRUE;
    HANDLE raw_read = nullptr;
    HANDLE raw_write = nullptr;
    if (!CreatePipe(&raw_read, &raw_write, &inheritable, 4096)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "peer_bootstrap_unavailable"));
    }
    UniqueHandle bootstrap_read{raw_read};
    UniqueHandle bootstrap_write{raw_write};
    // Only the child's end is inheritable, so the secret cannot leak to any
    // other process the server may start later.
    if (!SetHandleInformation(bootstrap_write.get(), HANDLE_FLAG_INHERIT, 0)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "peer_bootstrap_unavailable"));
    }

    // Endpoint and identity are public; the secret never reaches the command
    // line, the environment or a log.
    std::wstring command = L"\"" + wide_from_utf8(executable_path) + L"\" --endpoint " +
        wide_from_utf8(launch.endpoint) + L" --process " + wide_from_utf8(launch.process_instance) +
        L" --epoch " + wide_from_utf8(launch.bridge_epoch) + L" --request " +
        wide_from_utf8(std::to_string(launch.request_id));
    if (command.size() > 32000) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_peer_path"));
    }
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = bootstrap_read.get();
    startup.hStdOutput = GetStdHandle(STD_ERROR_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION information{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    if (!CreateProcessW(nullptr, mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &information)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "peer_unavailable"));
    }
    UniqueHandle process{information.hProcess};
    UniqueHandle thread{information.hThread};
    bootstrap_read.reset();

    DWORD written = 0;
    const auto ok = WriteFile(bootstrap_write.get(), secret.data(),
                              static_cast<DWORD>(secret.size()), &written, nullptr);
    bootstrap_write.reset();
    if (!ok || written != secret.size()) {
        TerminateProcess(process.get(), 1);
        WaitForSingleObject(process.get(), 2000);
        return std::unexpected(fail(DebugErrorCode::io_error, "peer_bootstrap_unavailable"));
    }
    try {
        auto native = std::make_unique<Native>();
        native->process = std::move(process);
        native->thread = std::move(thread);
        return std::unique_ptr<BridgePeerProcess>(new BridgePeerProcess(
            std::move(native), static_cast<domain::ProcessId>(information.dwProcessId)));
    } catch (const std::bad_alloc&) {
        TerminateProcess(process.get(), 1);
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

#else  // defined(_WIN32)

struct LocalBridgeChannel::Native {};
struct BridgePeerProcess::Native {};

LocalBridgeChannel::LocalBridgeChannel(
    std::unique_ptr<Native> native, std::string endpoint, ChannelLimits limits)
    : native_(std::move(native)), endpoint_(std::move(endpoint)), limits_(limits) {}

LocalBridgeChannel::~LocalBridgeChannel() = default;

Result<std::unique_ptr<LocalBridgeChannel>> LocalBridgeChannel::listen(
    domain::santamonica::RandomSource&, ChannelLimits) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

Result<std::unique_ptr<LocalBridgeChannel>> LocalBridgeChannel::connect(
    std::string_view, ChannelLimits) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

Result<void> LocalBridgeChannel::accept(domain::ProcessId, Clock::time_point, std::stop_token) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

Result<std::size_t> LocalBridgeChannel::read(
    std::span<std::byte>, Clock::time_point, std::stop_token) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

Result<void> LocalBridgeChannel::write(
    std::span<const std::byte>, Clock::time_point, std::stop_token) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

void LocalBridgeChannel::close() noexcept {}

BridgePeerProcess::BridgePeerProcess(std::unique_ptr<Native> native, const domain::ProcessId pid)
    : native_(std::move(native)), pid_(pid) {}

BridgePeerProcess::~BridgePeerProcess() = default;

void BridgePeerProcess::terminate() noexcept {}

Result<std::unique_ptr<BridgePeerProcess>> BridgePeerProcess::spawn(
    std::string_view, const PeerLaunch&, std::span<const std::byte>) {
    return std::unexpected(fail(DebugErrorCode::unsupported, "channel_unsupported"));
}

#endif  // defined(_WIN32)

Result<std::size_t> ChannelReflectionStream::read(
    const std::span<std::byte> destination, const Clock::time_point deadline,
    const std::stop_token cancellation) {
    if (channel_ == nullptr) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "channel_state"));
    }
    return channel_->read(destination, deadline, cancellation);
}

Result<void> send_handshake_frame(
    LocalBridgeChannel& channel, const HandshakeMessage& message, const std::uint64_t request_id,
    const std::uint64_t sequence, const LocalBridgeChannel::Clock::time_point deadline,
    const std::stop_token cancellation) {
    auto frame = encode_handshake_frame(message, request_id, sequence);
    if (!frame) return std::unexpected(frame.error());
    return channel.write(*frame, deadline, cancellation);
}

Result<HandshakeMessage> receive_handshake_frame(
    LocalBridgeChannel& channel, const std::uint64_t request_id, const std::uint64_t sequence,
    const LocalBridgeChannel::Clock::time_point deadline, const std::stop_token cancellation) {
    const auto read_exact = [&](const std::span<std::byte> destination) -> Result<void> {
        auto pending = destination;
        while (!pending.empty()) {
            auto read = channel.read(pending, deadline, cancellation);
            if (!read) return std::unexpected(read.error());
            if (*read == 0) {
                return std::unexpected(fail(DebugErrorCode::io_error, "unexpected_eof"));
            }
            if (*read > pending.size()) {
                return std::unexpected(fail(DebugErrorCode::io_error, "channel_contract_violation"));
            }
            pending = pending.subspan(*read);
        }
        return {};
    };

    try {
        std::vector<std::byte> frame(handshake_header_bytes);
        if (auto header = read_exact(frame); !header) return std::unexpected(header.error());
        auto payload_size = handshake_payload_size(frame, request_id, sequence);
        if (!payload_size) return std::unexpected(payload_size.error());
        frame.resize(handshake_header_bytes + *payload_size);
        if (*payload_size != 0) {
            if (auto body = read_exact(std::span{frame}.subspan(handshake_header_bytes)); !body) {
                return std::unexpected(body.error());
            }
        }
        return decode_handshake_frame(frame, request_id, sequence);
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

}  // namespace argos::infrastructure::santamonica
