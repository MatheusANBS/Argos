#include "argos_mcp/infrastructure/santa_monica_bridge_crypto.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <utility>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#endif

namespace argos::infrastructure::santamonica {
namespace {

using domain::DebugError;
using domain::DebugErrorCode;

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica bridge cryptography unavailable", reason};
}

#if defined(_WIN32)

// RAII over the CNG provider. The handle is shared by every tag() call: CNG
// allows concurrent BCryptCreateHash on one algorithm handle, and each call
// owns its own hash object, so the authenticator holds no mutable state.
class AlgorithmHandle final {
public:
    AlgorithmHandle() = default;
    explicit AlgorithmHandle(const BCRYPT_ALG_HANDLE handle) noexcept : handle_(handle) {}
    AlgorithmHandle(AlgorithmHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)) {}
    AlgorithmHandle& operator=(AlgorithmHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    ~AlgorithmHandle() { close(); }

    [[nodiscard]] BCRYPT_ALG_HANDLE get() const noexcept { return handle_; }

private:
    void close() noexcept {
        if (handle_ != nullptr) {
            BCryptCloseAlgorithmProvider(handle_, 0);
            handle_ = nullptr;
        }
    }
    BCRYPT_ALG_HANDLE handle_{};
};

class HashHandle final {
public:
    HashHandle() = default;
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
    ~HashHandle() {
        if (handle_ != nullptr) BCryptDestroyHash(handle_);
    }
    [[nodiscard]] BCRYPT_HASH_HANDLE* address() noexcept { return &handle_; }
    [[nodiscard]] BCRYPT_HASH_HANDLE get() const noexcept { return handle_; }

private:
    BCRYPT_HASH_HANDLE handle_{};
};

class HmacAuthenticator final : public bridge::MessageAuthenticator {
public:
    HmacAuthenticator(AlgorithmHandle algorithm, bridge::BridgeSecret secret) noexcept
        : algorithm_(std::move(algorithm)), secret_(std::move(secret)) {}

    [[nodiscard]] domain::Result<bridge::HandshakeTag> tag(
        const std::span<const std::byte> message) const override {
        if (message.size() > (std::numeric_limits<ULONG>::max)()) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "message_too_large"));
        }
        const auto key = secret_.material();
        HashHandle hash;
        // The CNG C ABI takes non-const pointers although it only reads the
        // key and the message; the casts stay confined to this boundary.
        auto status = BCryptCreateHash(
            algorithm_.get(), hash.address(), nullptr, 0,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key.data())),
            static_cast<ULONG>(key.size()), 0);
        if (!BCRYPT_SUCCESS(status)) {
            return std::unexpected(fail(DebugErrorCode::io_error, "authenticator_unavailable"));
        }
        if (!message.empty()) {
            status = BCryptHashData(
                hash.get(), const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(message.data())),
                static_cast<ULONG>(message.size()), 0);
            if (!BCRYPT_SUCCESS(status)) {
                return std::unexpected(fail(DebugErrorCode::io_error, "authenticator_unavailable"));
            }
        }
        bridge::HandshakeTag result;
        status = BCryptFinishHash(hash.get(), reinterpret_cast<PUCHAR>(result.bytes.data()),
                                  static_cast<ULONG>(result.bytes.size()), 0);
        if (!BCRYPT_SUCCESS(status)) {
            return std::unexpected(fail(DebugErrorCode::io_error, "authenticator_unavailable"));
        }
        return result;
    }

private:
    AlgorithmHandle algorithm_;
    bridge::BridgeSecret secret_;
};

class SystemRandom final : public bridge::RandomSource {
public:
    [[nodiscard]] domain::Result<void> fill(const std::span<std::byte> destination) override {
        if (destination.empty()) return {};
        if (destination.size() > (std::numeric_limits<ULONG>::max)()) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "request_too_large"));
        }
        const auto status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(destination.data()),
                                            static_cast<ULONG>(destination.size()),
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!BCRYPT_SUCCESS(status)) {
            return std::unexpected(fail(DebugErrorCode::io_error, "random_unavailable"));
        }
        return {};
    }
};

#endif  // defined(_WIN32)

}  // namespace

domain::Result<std::unique_ptr<const bridge::MessageAuthenticator>> create_hmac_authenticator(
    [[maybe_unused]] bridge::BridgeSecret secret) {
#if defined(_WIN32)
    BCRYPT_ALG_HANDLE raw{};
    const auto status = BCryptOpenAlgorithmProvider(&raw, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) {
        return std::unexpected(fail(DebugErrorCode::io_error, "authenticator_unavailable"));
    }
    AlgorithmHandle algorithm{raw};
    try {
        return std::make_unique<const HmacAuthenticator>(std::move(algorithm), std::move(secret));
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
#else
    return std::unexpected(fail(DebugErrorCode::unsupported, "crypto_provider_unavailable"));
#endif
}

domain::Result<bridge::Sha256Digest> sha256([[maybe_unused]] const std::span<const std::byte> message) {
#if defined(_WIN32)
    if (message.size() > (std::numeric_limits<ULONG>::max)()) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "message_too_large"));
    }
    BCRYPT_ALG_HANDLE raw{};
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&raw, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return std::unexpected(fail(DebugErrorCode::io_error, "digest_unavailable"));
    }
    const AlgorithmHandle algorithm{raw};
    HashHandle hash;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(algorithm.get(), hash.address(), nullptr, 0, nullptr, 0, 0))) {
        return std::unexpected(fail(DebugErrorCode::io_error, "digest_unavailable"));
    }
    if (!message.empty()) {
        if (!BCRYPT_SUCCESS(BCryptHashData(
                hash.get(), const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(message.data())),
                static_cast<ULONG>(message.size()), 0))) {
            return std::unexpected(fail(DebugErrorCode::io_error, "digest_unavailable"));
        }
    }
    bridge::Sha256Digest digest;
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash.get(), reinterpret_cast<PUCHAR>(digest.bytes.data()),
                                         static_cast<ULONG>(digest.bytes.size()), 0))) {
        return std::unexpected(fail(DebugErrorCode::io_error, "digest_unavailable"));
    }
    return digest;
#else
    return std::unexpected(fail(DebugErrorCode::unsupported, "crypto_provider_unavailable"));
#endif
}

domain::Result<std::unique_ptr<bridge::RandomSource>> create_system_random() {
#if defined(_WIN32)
    try {
        return std::make_unique<SystemRandom>();
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
#else
    return std::unexpected(fail(DebugErrorCode::unsupported, "crypto_provider_unavailable"));
#endif
}

}  // namespace argos::infrastructure::santamonica
