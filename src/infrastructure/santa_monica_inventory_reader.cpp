#include "argos_mcp/infrastructure/santa_monica_inventory_reader.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace argos::infrastructure::santamonica {
namespace {

using domain::Address;
using domain::DebugError;
using domain::DebugErrorCode;
using domain::Result;
using domain::santamonica::ResourceEntry;
using domain::santamonica::ResourceSnapshot;

constexpr std::chrono::milliseconds hard_deadline{5000};
constexpr std::size_t read_budget_bytes = 8U * 1024U * 1024U;
constexpr std::size_t name_chunk_bytes = 64U;
constexpr std::size_t page_bytes = 0x1000U;

// One family only, like the reflection layout. Observed and code-confirmed on
// the build documented in docs/engines/gow2018-steam-11168363-evidence.md.
constexpr ResourceStoreLayout gow2018_resources{
    // wallet set: store, count
    0x10, 0x20,
    // balance record: stride, definition, quantity, state
    64, 0x28, 0x30, 0x38,
    // state: acquired, never acquired
    3, 2,
    // Resource definition: stride, name, localization id, maximum, display flag
    64, 0x00, 0x08, 0x28, 0x3C,
    // sizeof(ResourcesPerm), which immediately precedes its Resources data
    0x78};

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Resource inventory unavailable", reason};
}

[[nodiscard]] std::uint64_t load(
    const std::span<const std::byte> bytes, const std::size_t offset, const std::size_t width) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value |= std::to_integer<std::uint64_t>(bytes[offset + index]) << (8U * index);
    }
    return value;
}

[[nodiscard]] std::int32_t load_i32(const std::span<const std::byte> bytes, const std::size_t offset) {
    return std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(load(bytes, offset, 4)));
}

[[nodiscard]] bool ascii_equal(const std::string_view left, const std::string_view right) {
    if (left.size() != right.size()) return false;
    const auto lower = [](const char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (lower(left[index]) != lower(right[index])) return false;
    }
    return true;
}

// Every read goes through here: one deadline, one byte budget, cancellation
// between fragments, and no address arithmetic that can wrap.
class BoundedReader {
public:
    BoundedReader(const domain::RuntimeMemoryView& memory, const std::chrono::milliseconds duration,
                  std::stop_token stop)
        : memory_(memory), deadline_(std::chrono::steady_clock::now() + duration), stop_(std::move(stop)) {}

    [[nodiscard]] Result<void> ready() const {
        if (stop_.stop_requested()) {
            return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        }
        if (std::chrono::steady_clock::now() >= deadline_) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "resource_deadline"));
        }
        return {};
    }

    [[nodiscard]] Result<void> read(const Address address, const std::span<std::byte> output) {
        if (address == 0 || output.size() > std::numeric_limits<Address>::max() - address) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "resource_pointer"));
        }
        if (output.size() > read_budget_bytes - consumed_) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "resource_read_budget"));
        }
        consumed_ += output.size();
        std::size_t done = 0;
        while (done < output.size()) {
            if (auto ok = ready(); !ok) return ok;
            auto got = memory_.read(address + done, output.subspan(done), stop_);
            if (!got || *got == 0 || *got > output.size() - done) {
                if (auto ok = ready(); !ok) return ok;
                return std::unexpected(fail(DebugErrorCode::io_error, "resource_read_failed"));
            }
            done += *got;
        }
        return ready();
    }

    [[nodiscard]] Result<std::uint64_t> u64(const Address address) {
        std::array<std::byte, 8> bytes{};
        if (auto ok = read(address, bytes); !ok) return std::unexpected(ok.error());
        return load(bytes, 0, 8);
    }

    [[nodiscard]] Result<std::uint32_t> u32(const Address address) {
        std::array<std::byte, 4> bytes{};
        if (auto ok = read(address, bytes); !ok) return std::unexpected(ok.error());
        return static_cast<std::uint32_t>(load(bytes, 0, 4));
    }

    // NUL-terminated name of at most max_resource_name_bytes. Chunks never cross
    // a page boundary, so bytes past a terminator near the end of a mapping are
    // never required to be readable.
    [[nodiscard]] Result<std::string> name(const Address address) {
        constexpr auto limit = domain::santamonica::max_resource_name_bytes;
        std::string text;
        Address cursor = address;
        std::array<std::byte, name_chunk_bytes> chunk{};
        while (text.size() <= limit) {
            const auto to_page_end = page_bytes - static_cast<std::size_t>(cursor % page_bytes);
            const auto width = std::min({chunk.size(), to_page_end, limit + 1U - text.size()});
            const auto window = std::span{chunk}.first(width);
            if (auto ok = read(cursor, window); !ok) return std::unexpected(ok.error());
            for (const auto byte : window) {
                if (byte == std::byte{}) {
                    if (!domain::santamonica::valid_resource_name(text)) {
                        return std::unexpected(fail(DebugErrorCode::parse_error, "resource_name"));
                    }
                    return text;
                }
                text.push_back(static_cast<char>(byte));
            }
            cursor += width;
        }
        return std::unexpected(fail(DebugErrorCode::parse_error, "resource_name"));
    }

private:
    const domain::RuntimeMemoryView& memory_;
    std::chrono::steady_clock::time_point deadline_;
    std::stop_token stop_;
    std::size_t consumed_{};
};

[[nodiscard]] std::optional<Address> offset_address(const Address base, const std::uint64_t offset) {
    if (offset > std::numeric_limits<Address>::max() - base) return std::nullopt;
    return base + offset;
}

// The structural part of one pass. Two passes must agree on every field here.
struct Structure {
    Address sets{};
    Address store{};
    std::uint32_t count{};
    Address definitions{};
    std::array<std::byte, 12> perm{};
    std::vector<std::byte> records;
    std::vector<std::byte> definition_bytes;
};

[[nodiscard]] Result<Structure> capture(
    BoundedReader& reader, const ResourceStoreLayout& layout, const Address root) {
    Structure result;
    auto sets = reader.u64(root);
    if (!sets) return std::unexpected(sets.error());
    if (*sets == 0) return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_root_unset"));
    result.sets = *sets;

    const auto store_slot = offset_address(result.sets, layout.set_store_offset);
    const auto count_slot = offset_address(result.sets, layout.set_count_offset);
    if (!store_slot || !count_slot) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "resource_pointer"));
    }
    auto store = reader.u64(*store_slot);
    if (!store) return std::unexpected(store.error());
    auto count = reader.u32(*count_slot);
    if (!count) return std::unexpected(count.error());
    if (*store == 0) return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_store_unset"));
    if (*count == 0 || *count > domain::santamonica::max_resource_entries) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "resource_count"));
    }
    result.store = *store;
    result.count = *count;

    result.records.resize(static_cast<std::size_t>(result.count) * layout.record_stride);
    if (auto ok = reader.read(result.store, result.records); !ok) return std::unexpected(ok.error());

    result.definitions = load(result.records, layout.record_definition_offset, 8);
    if (result.definitions <= layout.perm_offset) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_perm_mismatch"));
    }
    if (auto ok = reader.read(result.definitions - layout.perm_offset, result.perm); !ok) {
        return std::unexpected(ok.error());
    }
    // ResourcesPerm must describe exactly the array the store links to.
    if (load(result.perm, 0, 8) != result.definitions || load(result.perm, 8, 4) != result.count) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_perm_mismatch"));
    }

    result.definition_bytes.resize(static_cast<std::size_t>(result.count) * layout.definition_stride);
    if (auto ok = reader.read(result.definitions, result.definition_bytes); !ok) {
        return std::unexpected(ok.error());
    }
    return result;
}

struct Validated {
    ResourceSnapshot snapshot;
    Structure structure;
    const ResourceStoreLayout* layout{};
};

[[nodiscard]] Result<Validated> read_validated(
    const domain::RuntimeMemoryView& memory, const ResourceStoreRequest& request,
    const std::stop_token cancellation) {
    const auto* layout = find_resource_store_layout(request.profile_id);
    if (layout == nullptr) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "unsupported_profile"));
    }
    if (request.max_duration.count() <= 0 || request.max_duration > hard_deadline) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_resource_limits"));
    }
    if (request.root_rva == 0 || request.module_size < 8U || request.root_rva > request.module_size - 8U) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_resource_profile"));
    }
    if (cancellation.stop_requested()) {
        return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
    }

    auto space = memory.snapshot();
    if (!space) return std::unexpected(fail(DebugErrorCode::invalid_state, "address_space_unavailable"));
    const domain::ModuleInfo* module = nullptr;
    for (const auto& candidate : (*space)->modules.all()) {
        if (ascii_equal(candidate.name, request.module_name) && candidate.size == request.module_size) {
            module = &candidate;
            break;
        }
    }
    // The loaded image must match the profile before a single RVA is trusted.
    if (module == nullptr || module->base > std::numeric_limits<Address>::max() - request.module_size) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "resource_profile_mismatch"));
    }

    BoundedReader reader{memory, request.max_duration, cancellation};
    const auto root = module->base + request.root_rva;

    auto first = capture(reader, *layout, root);
    if (!first) return std::unexpected(first.error());

    Validated result;
    result.layout = layout;
    result.snapshot.entries.reserve(first->count);
    for (std::uint32_t index = 0; index < first->count; ++index) {
        const auto offset = static_cast<std::size_t>(index) * layout->definition_stride;
        auto text = reader.name(load(first->definition_bytes, offset + layout->definition_name_offset, 8));
        if (!text) return std::unexpected(text.error());
        ResourceEntry entry;
        entry.index = index;
        entry.name = std::move(*text);
        entry.lams_name_id = load_i32(first->definition_bytes, offset + layout->definition_lams_offset);
        entry.maximum = load_i32(first->definition_bytes, offset + layout->definition_maximum_offset);
        entry.display_ui = load(first->definition_bytes, offset + layout->definition_display_offset, 1) != 0;
        result.snapshot.entries.push_back(std::move(entry));
    }

    auto second = capture(reader, *layout, root);
    if (!second) return std::unexpected(second.error());
    // Names were read through the first pass's pointers. They stay valid only if
    // every definition byte is still the same, and so is every structural link.
    if (first->sets != second->sets || first->store != second->store || first->count != second->count ||
        first->definitions != second->definitions || first->perm != second->perm ||
        first->definition_bytes != second->definition_bytes) {
        return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_snapshot_changed"));
    }

    for (std::uint32_t index = 0; index < second->count; ++index) {
        const auto record = static_cast<std::size_t>(index) * layout->record_stride;
        const auto expected = offset_address(
            second->definitions, static_cast<std::uint64_t>(index) * layout->definition_stride);
        if (!expected || load(second->records, record + layout->record_definition_offset, 8) != *expected) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "resource_link_mismatch"));
        }
        const auto state = static_cast<std::uint32_t>(load(second->records, record + layout->record_state_offset, 4));
        const auto quantity = load_i32(second->records, record + layout->record_quantity_offset);
        auto& entry = result.snapshot.entries[index];
        if (state == layout->state_acquired) {
            if (quantity < 0) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "resource_state_mismatch"));
            }
            entry.acquired = true;
            entry.quantity = quantity;
        } else if (state == layout->state_unacquired) {
            if (quantity != -1) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "resource_state_mismatch"));
            }
            entry.acquired = false;
            entry.quantity = 0;
        } else {
            return std::unexpected(fail(DebugErrorCode::parse_error, "resource_state_unrecognized"));
        }
    }

    if (auto valid = domain::santamonica::validate_resource_snapshot(result.snapshot); !valid) {
        return std::unexpected(valid.error());
    }
    if (auto ok = reader.ready(); !ok) return std::unexpected(ok.error());
    result.structure = std::move(*second);
    return result;
}

}  // namespace

const ResourceStoreLayout* find_resource_store_layout(const std::string_view profile_id) {
    return profile_id == "gow2018-reflection-x64-v2" ? &gow2018_resources : nullptr;
}

Result<ResourceSnapshot> read_resource_inventory(
    const domain::RuntimeMemoryView& memory, const ResourceStoreRequest& request,
    const std::stop_token cancellation) {
    auto validated = read_validated(memory, request, cancellation);
    if (!validated) return std::unexpected(validated.error());
    return std::move(validated->snapshot);
}

Result<ResourceBalanceLocation> locate_resource_balance(
    const domain::RuntimeMemoryView& memory, const ResourceStoreRequest& request,
    const std::string_view name, const std::stop_token cancellation) {
    if (!domain::santamonica::valid_resource_name(name)) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_resource_name"));
    }
    auto validated = read_validated(memory, request, cancellation);
    if (!validated) return std::unexpected(validated.error());

    const auto& entries = validated->snapshot.entries;
    const auto found = std::ranges::find_if(entries, [name](const ResourceEntry& entry) {
        return entry.name == name;
    });
    if (found == entries.end()) {
        return std::unexpected(fail(DebugErrorCode::not_found, "resource_not_found"));
    }

    const auto& layout = *validated->layout;
    const auto& structure = validated->structure;
    const auto record = offset_address(structure.store, static_cast<std::uint64_t>(found->index) * layout.record_stride);
    const auto definition = offset_address(
        structure.definitions, static_cast<std::uint64_t>(found->index) * layout.definition_stride);
    if (!record || !definition) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "resource_pointer"));
    }
    const auto definition_slot = offset_address(*record, layout.record_definition_offset);
    const auto quantity = offset_address(*record, layout.record_quantity_offset);
    const auto state = offset_address(*record, layout.record_state_offset);
    if (!definition_slot || !quantity || !state || *state > std::numeric_limits<Address>::max() - 4U) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "resource_pointer"));
    }

    ResourceBalanceLocation location;
    location.entry = *found;
    location.definition = *definition;
    location.definition_slot = *definition_slot;
    location.quantity = *quantity;
    location.state = *state;
    location.acquired_state = layout.state_acquired;
    return location;
}

}  // namespace argos::infrastructure::santamonica
