#pragma once

#include "argos_mcp/domain/santa_monica_inventory.hpp"
#include "argos_mcp/domain/types.hpp"
#include "argos_mcp/domain/unreal_runtime.hpp"

#include <chrono>
#include <cstdint>
#include <stop_token>
#include <string>
#include <string_view>

namespace argos::infrastructure::santamonica {

// Shape of the player's resource store in one engine family. Like the
// reflection layout it is a property of the build family, never of a request:
//
//   [module + root_rva]            -> wallet sets; the first one is active
//   set + set_store_offset         -> balance records, record_stride apart
//   set + set_count_offset         -> u32 number of records
//   record + definition_offset     -> &Resources[i] inside ResourcesPerm
//   Resources.data - perm_offset   -> ResourcesPerm, whose {data, size} must
//                                     agree with the store
struct ResourceStoreLayout {
    std::uint32_t set_store_offset{};
    std::uint32_t set_count_offset{};
    std::uint32_t record_stride{};
    std::uint32_t record_definition_offset{};
    std::uint32_t record_quantity_offset{};
    std::uint32_t record_state_offset{};
    std::uint32_t state_acquired{};
    std::uint32_t state_unacquired{};
    std::uint32_t definition_stride{};
    std::uint32_t definition_name_offset{};
    std::uint32_t definition_lams_offset{};
    std::uint32_t definition_maximum_offset{};
    std::uint32_t definition_display_offset{};
    std::uint32_t perm_offset{};
};

[[nodiscard]] const ResourceStoreLayout* find_resource_store_layout(std::string_view profile_id);

// Operator-owned location of the store in one exact build. The root is an RVA
// that the build's own code addresses: never an absolute address, never a pid.
struct ResourceStoreRequest {
    std::string profile_id;
    std::string module_name;
    std::uint64_t module_size{};
    std::uint64_t root_rva{};
    std::chrono::milliseconds max_duration{5000};  // May only reduce the hard 5 s limit.
};

// Copies the balances out of an authorized session. The structure is read
// twice and must match; quantities come from the second pass, because a game
// in play changes them legitimately. Read-only.
[[nodiscard]] domain::Result<domain::santamonica::ResourceSnapshot> read_resource_inventory(
    const domain::RuntimeMemoryView& memory, const ResourceStoreRequest& request,
    std::stop_token cancellation = {});

// Where one resource's quantity lives right now, together with the definition
// pointer and state that must still be in place when a caller writes.
struct ResourceBalanceLocation {
    domain::santamonica::ResourceEntry entry;
    domain::Address definition{};       // Expected value of the definition slot.
    domain::Address definition_slot{};
    domain::Address quantity{};
    domain::Address state{};
    std::uint32_t acquired_state{};     // Expected value of the state slot.
};

// Exact, case-sensitive technical name. Read-only: it locates, it never writes.
[[nodiscard]] domain::Result<ResourceBalanceLocation> locate_resource_balance(
    const domain::RuntimeMemoryView& memory, const ResourceStoreRequest& request,
    std::string_view name, std::stop_token cancellation = {});

}  // namespace argos::infrastructure::santamonica
