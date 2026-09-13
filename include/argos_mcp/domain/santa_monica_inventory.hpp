#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain::santamonica {

// The player's resource balances, copied out of the target. Values only, never
// pointers into the process: an entry names its definition by index and
// technical name and says how much of it the player holds.
inline constexpr std::size_t max_resource_entries = 4096U;
inline constexpr std::size_t max_resource_name_bytes = 256U;
// Maximum the engine gives a resource that has no cap.
inline constexpr std::int32_t resource_unlimited = -1;

struct ResourceEntry {
    std::uint32_t index{};
    std::string name;             // Technical NameId, UTF-8, not localized.
    std::int32_t quantity{};      // Zero while the resource was never acquired.
    std::int32_t maximum{resource_unlimited};
    std::int32_t lams_name_id{};  // Localization id; the text is not resolved.
    bool acquired{};
    bool display_ui{};
};

struct ResourceSnapshot {
    std::vector<ResourceEntry> entries;
    std::uint64_t generation{};  // Issued by the owning runtime manager.
};

// Well-formed UTF-8 of 1..max_resource_name_bytes bytes with no control
// character. Retail builds do carry non-ASCII technical names.
[[nodiscard]] bool valid_resource_name(std::string_view name) noexcept;

[[nodiscard]] Result<void> validate_resource_snapshot(const ResourceSnapshot& snapshot);

// Admission for a direct balance write. Only a resource the player already
// holds can be set, and never past its cap: a never-acquired entry carries
// engine state beyond its quantity that a balance write would not create.
[[nodiscard]] Result<std::int32_t> admit_resource_quantity(
    const ResourceEntry& entry, std::int64_t requested);

}  // namespace argos::domain::santamonica
