#pragma once

#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/domain/types.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace argos::testing {

// Sparse address space for tests: segments are mapped by virtual address, so a
// fixture can place an object at 0x1FE44726700 and a vtable at 0x140002100
// without allocating everything in between. Regions and modules are declared
// separately from backing bytes, which is what makes "readable region with no
// data", "unreadable mapping" and "short read" expressible at all.
struct SparseSegment {
    domain::Address start{};
    std::vector<std::byte> bytes;

    [[nodiscard]] domain::Address end() const noexcept {
        return start + static_cast<domain::Address>(bytes.size());
    }
};

struct SparseState {
    std::vector<SparseSegment> segments;
    std::vector<domain::MemoryRegion> regions;
    std::vector<domain::ModuleInfo> modules;
    std::vector<domain::Address> failing_addresses;
    // 0 means "serve the whole request"; otherwise every read is capped.
    std::size_t short_read_limit{0U};
    std::size_t cancel_after_reads{0U};
    std::stop_source cancellation;

    // Simulates a target that keeps mutating while it is being read. Each
    // qualifying read bumps the 32-bit value at every listed address, which is
    // exactly the "slot recycled while the counts stayed the same" case that a
    // count-only stability check would miss.
    std::size_t mutate_every_reads{0U};
    std::vector<domain::Address> mutating_addresses;

    std::atomic<std::size_t> reads{0U};
    std::atomic<std::size_t> bytes_read{0U};
    std::atomic<std::size_t> region_calls{0U};
    std::atomic<std::size_t> module_calls{0U};

    void map(const domain::Address start, std::vector<std::byte> bytes) {
        segments.push_back(SparseSegment{start, std::move(bytes)});
    }

    void map_zeroed(const domain::Address start, const std::size_t size) {
        segments.push_back(SparseSegment{start, std::vector<std::byte>(size, std::byte{0})});
    }

    void write_pointer(
        const domain::Address address,
        const std::uint64_t value,
        const std::size_t width
    ) {
        for (auto& segment : segments) {
            if (address < segment.start || address + width > segment.end()) {
                continue;
            }
            const auto offset = static_cast<std::size_t>(address - segment.start);
            for (std::size_t index = 0; index < width; ++index) {
                segment.bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
            }
            return;
        }
    }

    void write_u32(const domain::Address address, const std::uint32_t value) {
        write_pointer(address, value, 4U);
    }

    void write_u16(const domain::Address address, const std::uint16_t value) {
        write_pointer(address, value, 2U);
    }

    void write_bytes(const domain::Address address, const std::span<const std::byte> input) {
        for (auto& segment : segments) {
            if (address < segment.start || address + input.size() > segment.end()) {
                continue;
            }
            const auto offset = static_cast<std::size_t>(address - segment.start);
            std::copy(input.begin(), input.end(), segment.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
            return;
        }
    }

    void write_text(const domain::Address address, const std::string_view text) {
        std::vector<std::byte> encoded;
        encoded.reserve(text.size() + 1U);
        for (const char ch : text) {
            encoded.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        encoded.push_back(std::byte{0});
        write_bytes(address, encoded);
    }

    [[nodiscard]] std::uint64_t read_value(const domain::Address address, const std::size_t width) const {
        for (const auto& segment : segments) {
            if (address < segment.start || address + width > segment.end()) {
                continue;
            }
            const auto offset = static_cast<std::size_t>(address - segment.start);
            std::uint64_t value = 0;
            for (std::size_t index = 0; index < width; ++index) {
                value |= static_cast<std::uint64_t>(
                    std::to_integer<unsigned int>(segment.bytes[offset + index])
                ) << (index * 8U);
            }
            return value;
        }
        return 0U;
    }

    void reset_counters() {
        reads.store(0U, std::memory_order_relaxed);
        bytes_read.store(0U, std::memory_order_relaxed);
        region_calls.store(0U, std::memory_order_relaxed);
        module_calls.store(0U, std::memory_order_relaxed);
    }
};

class SparseFakeSession final : public domain::ProcessSession {
public:
    explicit SparseFakeSession(std::shared_ptr<SparseState> state) : state_(std::move(state)) {}

    [[nodiscard]] domain::ProcessId pid() const noexcept override { return 4242U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "sparse-target"; }
    [[nodiscard]] domain::AccessMode access_mode() const noexcept override {
        return domain::AccessMode::read_only;
    }

    [[nodiscard]] domain::Result<std::size_t> read(
        const domain::Address address,
        const std::span<std::byte> output
    ) const override {
        const auto count = state_->reads.fetch_add(1U, std::memory_order_relaxed) + 1U;
        if (state_->cancel_after_reads != 0U && count >= state_->cancel_after_reads) {
            state_->cancellation.request_stop();
        }
        if (state_->mutate_every_reads != 0U && count % state_->mutate_every_reads == 0U) {
            for (const auto mutating : state_->mutating_addresses) {
                state_->write_u32(mutating, static_cast<std::uint32_t>(state_->read_value(mutating, 4U) + 1U));
            }
        }
        if (std::ranges::find(state_->failing_addresses, address) != state_->failing_addresses.end()) {
            return std::unexpected(domain::DebugError{
                domain::DebugErrorCode::io_error, "read failed at the configured address"
            });
        }
        for (const auto& segment : state_->segments) {
            if (address < segment.start || address >= segment.end()) {
                continue;
            }
            const auto offset = static_cast<std::size_t>(address - segment.start);
            const auto available = segment.bytes.size() - offset;
            auto size = std::min(output.size(), available);
            if (state_->short_read_limit != 0U) {
                size = std::min(size, state_->short_read_limit);
            }
            std::copy_n(
                segment.bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                size,
                output.begin()
            );
            state_->bytes_read.fetch_add(size, std::memory_order_relaxed);
            return size;
        }
        return std::unexpected(domain::DebugError{
            domain::DebugErrorCode::io_error, "address is not mapped in the sparse fixture"
        });
    }

    [[nodiscard]] domain::Result<std::size_t> write(
        domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(domain::DebugError{
            domain::DebugErrorCode::access_denied, "sparse fixture is read-only"
        });
    }

    [[nodiscard]] domain::Result<std::vector<domain::MemoryRegion>> regions() const override {
        state_->region_calls.fetch_add(1U, std::memory_order_relaxed);
        return state_->regions;
    }

    [[nodiscard]] domain::Result<std::vector<domain::ModuleInfo>> modules() const override {
        state_->module_calls.fetch_add(1U, std::memory_order_relaxed);
        return state_->modules;
    }

private:
    std::shared_ptr<SparseState> state_;
};

class SparseProvider final : public domain::ProcessMemoryProvider {
public:
    explicit SparseProvider(std::shared_ptr<SparseState> state) : state_(std::move(state)) {}

    [[nodiscard]] domain::Result<std::vector<domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<domain::ProcessInfo>{{4242U, "sparse-target", std::nullopt, true}};
    }

    [[nodiscard]] domain::Result<std::unique_ptr<domain::ProcessSession>> attach(
        const domain::ProcessId pid,
        domain::AccessMode
    ) const override {
        if (pid != 4242U) {
            return std::unexpected(domain::DebugError{
                domain::DebugErrorCode::not_found, "sparse fixture has no such process"
            });
        }
        return std::unique_ptr<domain::ProcessSession>{std::make_unique<SparseFakeSession>(state_)};
    }

    [[nodiscard]] domain::Result<std::unique_ptr<domain::LaunchedProcessSession>> launch(
        const domain::LaunchSpec&,
        domain::AccessMode
    ) const override {
        return std::unexpected(domain::DebugError{
            domain::DebugErrorCode::unsupported, "sparse fixture does not launch processes"
        });
    }

private:
    std::shared_ptr<SparseState> state_;
};

}  // namespace argos::testing
