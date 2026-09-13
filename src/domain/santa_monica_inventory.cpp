#include "argos_mcp/domain/santa_monica_inventory.hpp"

#include <algorithm>
#include <limits>
#include <string_view>
#include <vector>

namespace argos::domain::santamonica {
namespace {

[[nodiscard]] DebugError invalid_snapshot(const DebugErrorCode code, const char* reason) {
    return DebugError{code, "Invalid resource inventory", reason};
}

[[nodiscard]] DebugError refused(const DebugErrorCode code, const char* reason) {
    return DebugError{code, "Resource quantity refused", reason};
}

}  // namespace

bool valid_resource_name(const std::string_view name) noexcept {
    if (name.empty() || name.size() > max_resource_name_bytes) return false;
    std::size_t index = 0;
    while (index < name.size()) {
        const auto lead = static_cast<unsigned char>(name[index]);
        if (lead < 0x80U) {
            if (lead < 0x20U || lead == 0x7FU) return false;
            ++index;
            continue;
        }
        std::size_t length = 0;
        std::uint32_t code_point = 0;
        if (lead >= 0xC2U && lead <= 0xDFU) {
            length = 2;
            code_point = lead & 0x1FU;
        } else if (lead >= 0xE0U && lead <= 0xEFU) {
            length = 3;
            code_point = lead & 0x0FU;
        } else if (lead >= 0xF0U && lead <= 0xF4U) {
            length = 4;
            code_point = lead & 0x07U;
        } else {
            return false;
        }
        if (name.size() - index < length) return false;
        for (std::size_t offset = 1; offset < length; ++offset) {
            const auto next = static_cast<unsigned char>(name[index + offset]);
            if ((next & 0xC0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (next & 0x3FU);
        }
        // Overlong spellings, surrogates, values past Unicode and C1 controls
        // are not a name.
        if ((length == 3 && code_point < 0x800U) || (length == 4 && code_point < 0x10000U) ||
            (code_point >= 0xD800U && code_point <= 0xDFFFU) || code_point > 0x10FFFFU ||
            code_point <= 0x9FU) {
            return false;
        }
        index += length;
    }
    return true;
}

Result<void> validate_resource_snapshot(const ResourceSnapshot& snapshot) {
    if (snapshot.entries.empty() || snapshot.entries.size() > max_resource_entries) {
        return std::unexpected(invalid_snapshot(DebugErrorCode::limit_exceeded, "resource_count"));
    }
    std::vector<std::string_view> names;
    names.reserve(snapshot.entries.size());
    for (std::size_t position = 0; position < snapshot.entries.size(); ++position) {
        const auto& entry = snapshot.entries[position];
        if (entry.index != position || !valid_resource_name(entry.name)) {
            return std::unexpected(invalid_snapshot(DebugErrorCode::parse_error, "resource_identity"));
        }
        if (entry.maximum < resource_unlimited) {
            return std::unexpected(invalid_snapshot(DebugErrorCode::parse_error, "resource_maximum"));
        }
        if (entry.quantity < 0 || (!entry.acquired && entry.quantity != 0)) {
            return std::unexpected(invalid_snapshot(DebugErrorCode::parse_error, "resource_quantity"));
        }
        names.push_back(entry.name);
    }
    std::ranges::sort(names);
    if (std::ranges::adjacent_find(names) != names.end()) {
        return std::unexpected(invalid_snapshot(DebugErrorCode::parse_error, "duplicate_resource"));
    }
    return {};
}

Result<std::int32_t> admit_resource_quantity(const ResourceEntry& entry, const std::int64_t requested) {
    if (requested < 0) {
        return std::unexpected(refused(DebugErrorCode::invalid_argument, "negative_quantity"));
    }
    if (requested > std::numeric_limits<std::int32_t>::max()) {
        return std::unexpected(refused(DebugErrorCode::invalid_argument, "quantity_overflow"));
    }
    if (!entry.acquired) {
        return std::unexpected(refused(DebugErrorCode::invalid_state, "resource_not_acquired"));
    }
    if (entry.maximum != resource_unlimited && requested > entry.maximum) {
        return std::unexpected(refused(DebugErrorCode::invalid_argument, "exceeds_resource_max"));
    }
    return static_cast<std::int32_t>(requested);
}

}  // namespace argos::domain::santamonica
