#include "argos_mcp/infrastructure/santa_monica_inventory_reader.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

[[nodiscard]] bool refused_with(const auto& result, const std::string_view reason) {
    return !result.has_value() && result.error().reason == reason;
}

constexpr Address module_base = 0x140000000ULL;
constexpr std::uint64_t module_size = 0x10000;
constexpr std::uint64_t root_rva = 0x1000;
constexpr std::uint64_t sets_rva = 0x2000;
constexpr std::uint64_t store_rva = 0x3000;
constexpr std::uint64_t definitions_rva = 0x5000;
constexpr std::uint64_t names_rva = 0x8000;

void poke(std::vector<std::byte>& bytes, const std::uint64_t rva, const std::uint64_t value,
          const std::size_t width) {
    for (std::size_t index = 0; index < width; ++index) {
        bytes[static_cast<std::size_t>(rva) + index] = static_cast<std::byte>((value >> (8U * index)) & 0xFFU);
    }
}

void poke_i32(std::vector<std::byte>& bytes, const std::uint64_t rva, const std::int32_t value) {
    poke(bytes, rva, static_cast<std::uint32_t>(value), 4);
}

struct Resource {
    std::string name;
    std::int32_t quantity{};
    bool acquired{};
    std::int32_t maximum{resource_unlimited};
    std::int32_t lams{};
    bool display{};
};

// A synthetic image shaped like the observed store: no proprietary bytes, only
// the structure the reader is contracted to follow.
[[nodiscard]] std::vector<std::byte> build_image(const std::vector<Resource>& resources) {
    std::vector<std::byte> bytes(module_size, std::byte{});
    poke(bytes, root_rva, module_base + sets_rva, 8);
    poke(bytes, sets_rva + 0x10, module_base + store_rva, 8);
    poke(bytes, sets_rva + 0x20, resources.size(), 4);
    poke(bytes, definitions_rva - 0x78, module_base + definitions_rva, 8);
    poke(bytes, definitions_rva - 0x70, resources.size(), 4);
    auto next_name = names_rva;
    for (std::size_t index = 0; index < resources.size(); ++index) {
        const auto& resource = resources[index];
        const auto record = store_rva + index * 64U;
        const auto definition = definitions_rva + index * 64U;
        poke(bytes, record + 0x28, module_base + definition, 8);
        poke_i32(bytes, record + 0x30, resource.acquired ? resource.quantity : -1);
        poke(bytes, record + 0x38, resource.acquired ? 3U : 2U, 4);
        poke(bytes, definition + 0x00, module_base + next_name, 8);
        poke_i32(bytes, definition + 0x08, resource.lams);
        poke_i32(bytes, definition + 0x28, resource.maximum);
        poke(bytes, definition + 0x3C, resource.display ? 1U : 0U, 1);
        for (const char c : resource.name) bytes[static_cast<std::size_t>(next_name++)] = static_cast<std::byte>(c);
        bytes[static_cast<std::size_t>(next_name++)] = std::byte{};
    }
    return bytes;
}

class FakeMemory final : public RuntimeMemoryView {
public:
    explicit FakeMemory(std::vector<std::byte> image, std::string module_name = "GoW.exe",
                        const std::uint64_t declared_size = module_size)
        : image_(std::move(image)) {
        auto snapshot = std::make_shared<RuntimeAddressSpaceSnapshot>();
        snapshot->pid = 4242;
        snapshot->process_name = "synthetic";
        const std::array<ModuleInfo, 1> modules{
            ModuleInfo{std::move(module_name), "C:/synthetic", module_base, declared_size}};
        snapshot->modules = ModuleIndex::create(modules);
        snapshot->sequence = 1;
        snapshot_ = std::move(snapshot);
    }

    [[nodiscard]] Result<std::size_t> read(const Address address, const std::span<std::byte> destination,
                                           const std::stop_token cancellation) const override {
        ++reads;
        if (mutate && reads == mutate_at) mutate(image_);
        if (delay.count() > 0) std::this_thread::sleep_for(delay);
        if (cancel_after_read != nullptr) cancel_after_read->request_stop();
        if (cancellation.stop_requested()) {
            return std::unexpected(DebugError{DebugErrorCode::cancelled, "cancelled"});
        }
        if (fail_reads) {
            return std::unexpected(DebugError{DebugErrorCode::io_error, "private native detail"});
        }
        if (address < module_base || address - module_base >= image_.size()) {
            ++outside_reads;
            return std::unexpected(DebugError{DebugErrorCode::io_error, "out of range"});
        }
        const auto offset = static_cast<std::size_t>(address - module_base);
        const auto available = std::min({destination.size(), image_.size() - offset, fragment_size});
        std::copy_n(std::next(image_.begin(), static_cast<std::ptrdiff_t>(offset)), available,
                    destination.begin());
        return available;
    }

    [[nodiscard]] Result<std::shared_ptr<const RuntimeAddressSpaceSnapshot>> snapshot() const override {
        return snapshot_;
    }

    mutable std::size_t reads{};
    mutable std::size_t outside_reads{};
    std::size_t fragment_size{module_size};
    std::chrono::milliseconds delay{};
    std::stop_source* cancel_after_read{};
    bool fail_reads{false};
    std::size_t mutate_at{};
    std::function<void(std::vector<std::byte>&)> mutate;

private:
    mutable std::vector<std::byte> image_;
    std::shared_ptr<const RuntimeAddressSpaceSnapshot> snapshot_;
};

[[nodiscard]] infra::ResourceStoreRequest request() {
    infra::ResourceStoreRequest value;
    value.profile_id = "gow2018-reflection-x64-v2";
    value.module_name = "GoW.exe";
    value.module_size = module_size;
    value.root_rva = root_rva;
    value.max_duration = std::chrono::milliseconds{5000};
    return value;
}

[[nodiscard]] std::vector<Resource> sample() {
    return {
        {"EconomyXP", 875279, true, resource_unlimited, 176, true},
        {"Bestiary_Unlock_Svart\xC3\xA1lfheim", 0, false, 1, 0, false},
        {"RareMuspelheimLoot01", 963, true, resource_unlimited, 11929, true},
    };
}

// Structure reads of one capture with unfragmented memory: root, store, count,
// records, ResourcesPerm header, definitions. The next read is the first name.
constexpr std::size_t first_name_read = 7U;

void test_names() {
    check(valid_resource_name("EconomyXP"), "an ASCII technical name is valid");
    check(valid_resource_name("Bestiary_Unlock_Svart\xC3\xA1lfheim"), "a two-byte UTF-8 name is valid");
    check(valid_resource_name("Bestiary_Unlock_Hr\xC3\xA6zlyr"), "another retail non-ASCII name is valid");
    check(valid_resource_name(std::string(max_resource_name_bytes, 'a')), "a name at the byte limit is valid");
    check(!valid_resource_name(""), "an empty name is invalid");
    check(!valid_resource_name(std::string(max_resource_name_bytes + 1U, 'a')), "a name past the limit is invalid");
    for (const auto* invalid : {"a\x01", "a\x7F", "a\xC3", "\xC0\x80", "\xE0\x80\x80", "\xED\xA0\x80",
                                "\xF4\x90\x80\x80", "\xC2\x80", "\xFF", "\xE2\x82"}) {
        check(!valid_resource_name(invalid),
              "controls, truncated, overlong, surrogate, out-of-range and C1 sequences are invalid");
    }
}

void test_snapshot_validation() {
    ResourceSnapshot valid;
    valid.entries = {{0, "A", 3, resource_unlimited, 0, true, true}, {1, "B", 0, 1, 0, false, false}};
    check(validate_resource_snapshot(valid).has_value(), "a coherent snapshot is valid");

    check(refused_with(validate_resource_snapshot(ResourceSnapshot{}), "resource_count"), "an empty snapshot is refused");
    ResourceSnapshot huge;
    huge.entries.resize(max_resource_entries + 1U);
    check(refused_with(validate_resource_snapshot(huge), "resource_count"), "an oversized snapshot is refused");

    auto shifted = valid;
    shifted.entries[1].index = 5;
    check(refused_with(validate_resource_snapshot(shifted), "resource_identity"), "an index out of position is refused");
    auto phantom = valid;
    phantom.entries[1].quantity = 4;
    check(refused_with(validate_resource_snapshot(phantom), "resource_quantity"),
          "a never-acquired resource with a quantity is refused");
    auto negative = valid;
    negative.entries[0].quantity = -3;
    check(refused_with(validate_resource_snapshot(negative), "resource_quantity"), "a negative quantity is refused");
    auto below = valid;
    below.entries[0].maximum = -2;
    check(refused_with(validate_resource_snapshot(below), "resource_maximum"), "a maximum below the sentinel is refused");
    auto twin = valid;
    twin.entries[1].name = "A";
    check(refused_with(validate_resource_snapshot(twin), "duplicate_resource"), "duplicated names are refused");
}

void test_quantity_admission() {
    const ResourceEntry held{0, "Ore", 5, resource_unlimited, 0, true, true};
    const ResourceEntry capped{1, "Key", 1, 3, 0, true, false};
    const ResourceEntry locked{2, "Locked", 0, resource_unlimited, 0, false, false};
    const ResourceEntry empty_cap{3, "None", 0, 0, 0, true, false};

    check(admit_resource_quantity(held, 999).value_or(-1) == 999, "an uncapped held resource accepts any value");
    check(admit_resource_quantity(held, std::numeric_limits<std::int32_t>::max()).has_value(),
          "the largest 32-bit value is accepted");
    check(refused_with(admit_resource_quantity(held, -1), "negative_quantity"), "a negative quantity is refused");
    check(refused_with(admit_resource_quantity(held, std::int64_t{1} << 31), "quantity_overflow"),
          "a quantity past 32 bits is refused");
    check(refused_with(admit_resource_quantity(locked, 1), "resource_not_acquired"),
          "a never-acquired resource cannot be set");
    check(admit_resource_quantity(capped, 3).has_value(), "a value at the cap is accepted");
    check(refused_with(admit_resource_quantity(capped, 4), "exceeds_resource_max"), "a value past the cap is refused");
    check(admit_resource_quantity(empty_cap, 0).has_value() &&
          refused_with(admit_resource_quantity(empty_cap, 1), "exceeds_resource_max"),
          "a zero cap only admits zero");
}

void test_reads_inventory() {
    FakeMemory memory{build_image(sample())};
    auto snapshot = infra::read_resource_inventory(memory, request());
    check(snapshot.has_value(), "a well-formed store is read");
    if (!snapshot) {
        std::cerr << "  reason: " << snapshot.error().reason << '\n';
        return;
    }
    check(snapshot->entries.size() == 3U, "every record becomes an entry");
    if (snapshot->entries.size() != 3U) return;
    const auto& xp = snapshot->entries[0];
    check(xp.index == 0U && xp.name == "EconomyXP" && xp.acquired && xp.quantity == 875279 &&
          xp.maximum == resource_unlimited && xp.lams_name_id == 176 && xp.display_ui,
          "an acquired, uncapped resource keeps every field");
    const auto& locked = snapshot->entries[1];
    check(!locked.acquired && locked.quantity == 0 && locked.maximum == 1 && !locked.display_ui,
          "a never-acquired resource reports zero, not the engine sentinel");
    check(locked.name == "Bestiary_Unlock_Svart\xC3\xA1lfheim", "a non-ASCII technical name survives");
    check(snapshot->entries[2].quantity == 963 && snapshot->entries[2].lams_name_id == 11929,
          "the last record is read");
    check(memory.outside_reads == 0U, "no read leaves the synthetic image");

    FakeMemory fragmented{build_image(sample())};
    fragmented.fragment_size = 3;
    auto pieces = infra::read_resource_inventory(fragmented, request());
    check(pieces.has_value() && pieces->entries.size() == 3U && pieces->entries[2].quantity == 963,
          "short reads are resumed without changing the result");
}

void test_profile_rejections() {
    auto unknown = request();
    unknown.profile_id = "gow2018-typetable-x64";
    FakeMemory memory{build_image(sample())};
    check(refused_with(infra::read_resource_inventory(memory, unknown), "unsupported_profile"),
          "a layout family the server does not know is unsupported");

    FakeMemory other_module{build_image(sample()), "Other.exe"};
    check(refused_with(infra::read_resource_inventory(other_module, request()), "resource_profile_mismatch"),
          "a missing module is a profile mismatch");
    FakeMemory resized{build_image(sample()), "GoW.exe", module_size * 2U};
    check(refused_with(infra::read_resource_inventory(resized, request()), "resource_profile_mismatch"),
          "a module of another size is a profile mismatch");

    auto unrooted = request();
    unrooted.root_rva = 0;
    check(refused_with(infra::read_resource_inventory(memory, unrooted), "invalid_resource_profile"),
          "a zero root is not a location");
    auto outside = request();
    outside.root_rva = module_size - 7U;
    check(refused_with(infra::read_resource_inventory(memory, outside), "invalid_resource_profile"),
          "a root slot crossing the module end is refused");

    for (const auto duration : {std::chrono::milliseconds{0}, std::chrono::milliseconds{5001}}) {
        auto limits = request();
        limits.max_duration = duration;
        check(refused_with(infra::read_resource_inventory(memory, limits), "invalid_resource_limits"),
              "a duration outside the hard limit is refused");
    }
    check(memory.reads == 0U, "profile validation happens before any read");
}

void test_structure_rejections() {
    struct Case {
        const char* reason;
        const char* message;
        std::function<void(std::vector<std::byte>&)> corrupt;
    };
    const std::vector<Case> cases{
        {"resource_root_unset", "a null root is refused",
         [](auto& bytes) { poke(bytes, root_rva, 0, 8); }},
        {"resource_store_unset", "a null store is refused",
         [](auto& bytes) { poke(bytes, sets_rva + 0x10, 0, 8); }},
        {"resource_count", "an empty store is refused",
         [](auto& bytes) { poke(bytes, sets_rva + 0x20, 0, 4); }},
        {"resource_count", "an oversized store is refused before it is read",
         [](auto& bytes) { poke(bytes, sets_rva + 0x20, max_resource_entries + 1U, 4); }},
        {"resource_perm_mismatch", "ResourcesPerm pointing at another array is refused",
         [](auto& bytes) { poke(bytes, definitions_rva - 0x78, module_base + definitions_rva + 64U, 8); }},
        {"resource_perm_mismatch", "ResourcesPerm with another size is refused",
         [](auto& bytes) { poke(bytes, definitions_rva - 0x70, 2, 4); }},
        {"resource_perm_mismatch", "a definition pointer below ResourcesPerm is refused",
         [](auto& bytes) { poke(bytes, store_rva + 0x28, 0x10, 8); }},
        {"resource_link_mismatch", "a record linked to another definition is refused",
         [](auto& bytes) { poke(bytes, store_rva + 64U + 0x28, module_base + definitions_rva, 8); }},
        {"resource_state_unrecognized", "an unknown record state is refused",
         [](auto& bytes) { poke(bytes, store_rva + 64U + 0x38, 7, 4); }},
        {"resource_state_mismatch", "an acquired resource with a negative quantity is refused",
         [](auto& bytes) { poke_i32(bytes, store_rva + 0x30, -5); }},
        {"resource_state_mismatch", "a never-acquired resource without the sentinel is refused",
         [](auto& bytes) { poke_i32(bytes, store_rva + 64U + 0x30, 0); }},
        {"resource_read_failed", "a definition pointer outside readable memory is refused",
         [](auto& bytes) { poke(bytes, definitions_rva + 0x00, module_base + module_size + 0x1000U, 8); }},
    };
    for (const auto& item : cases) {
        auto image = build_image(sample());
        item.corrupt(image);
        FakeMemory memory{std::move(image)};
        auto result = infra::read_resource_inventory(memory, request());
        check(refused_with(result, item.reason), item.message);
        if (result.has_value()) std::cerr << "  unexpectedly accepted\n";
        else if (result.error().reason != item.reason) std::cerr << "  reason: " << result.error().reason << '\n';
    }

    auto long_name = sample();
    long_name[0].name = std::string(300, 'A');
    FakeMemory unterminated{build_image(long_name)};
    check(refused_with(infra::read_resource_inventory(unterminated, request()), "resource_name"),
          "a name without a terminator inside the limit is refused");

    auto broken = sample();
    broken[2].name = "Bad\xC3";
    FakeMemory malformed{build_image(broken)};
    check(refused_with(infra::read_resource_inventory(malformed, request()), "resource_name"),
          "a name that is not UTF-8 is refused");

    auto twins = sample();
    twins[2].name = "EconomyXP";
    FakeMemory duplicated{build_image(twins)};
    check(refused_with(infra::read_resource_inventory(duplicated, request()), "duplicate_resource"),
          "a store with duplicated names is refused");
}

void test_passes() {
    FakeMemory changed{build_image(sample())};
    changed.mutate_at = first_name_read;
    changed.mutate = [](auto& bytes) { poke_i32(bytes, definitions_rva + 0x08, 999); };
    check(refused_with(infra::read_resource_inventory(changed, request()), "resource_snapshot_changed"),
          "a definition that changes between passes discards the snapshot");

    FakeMemory relinked{build_image(sample())};
    relinked.mutate_at = first_name_read;
    relinked.mutate = [](auto& bytes) { poke(bytes, sets_rva + 0x20, 2, 4); poke(bytes, definitions_rva - 0x70, 2, 4); };
    check(refused_with(infra::read_resource_inventory(relinked, request()), "resource_snapshot_changed"),
          "a store that shrinks between passes discards the snapshot");

    FakeMemory played{build_image(sample())};
    played.mutate_at = first_name_read;
    played.mutate = [](auto& bytes) { poke_i32(bytes, store_rva + 2U * 64U + 0x30, 900); };
    auto result = infra::read_resource_inventory(played, request());
    check(result.has_value() && result->entries[2].quantity == 900,
          "a quantity spent between passes is reported from the second pass");
}

void test_failures_and_cancellation() {
    FakeMemory failing{build_image(sample())};
    failing.fail_reads = true;
    check(refused_with(infra::read_resource_inventory(failing, request()), "resource_read_failed"),
          "a failed native read is reported without the native detail");

    FakeMemory memory{build_image(sample())};
    std::stop_source cancelled;
    cancelled.request_stop();
    check(refused_with(infra::read_resource_inventory(memory, request(), cancelled.get_token()), "operation_cancelled"),
          "an already cancelled read does nothing");
    check(memory.reads == 0U, "a cancelled read never touches memory");

    FakeMemory interrupted{build_image(sample())};
    std::stop_source midway;
    interrupted.cancel_after_read = &midway;
    check(refused_with(infra::read_resource_inventory(interrupted, request(), midway.get_token()), "operation_cancelled"),
          "cancellation between reads stops the capture");

    FakeMemory slow{build_image(sample())};
    slow.delay = std::chrono::milliseconds{3};
    auto hurried = request();
    hurried.max_duration = std::chrono::milliseconds{5};
    check(refused_with(infra::read_resource_inventory(slow, hurried), "resource_deadline"),
          "a capture past its deadline is abandoned");
}

void test_locate() {
    FakeMemory memory{build_image(sample())};
    auto located = infra::locate_resource_balance(memory, request(), "RareMuspelheimLoot01");
    check(located.has_value(), "a held resource is located");
    if (located) {
        const auto record = module_base + store_rva + 2U * 64U;
        check(located->entry.index == 2U && located->entry.quantity == 963, "the located entry is the named one");
        check(located->quantity == record + 0x30 && located->definition_slot == record + 0x28 &&
              located->state == record + 0x38, "the slots belong to the named record");
        check(located->definition == module_base + definitions_rva + 2U * 64U && located->acquired_state == 3U,
              "the expected link and state are reported for re-validation");
    }
    check(refused_with(infra::locate_resource_balance(memory, request(), "rareMuspelheimLoot01"), "resource_not_found"),
          "locating is exact and case-sensitive");
    check(refused_with(infra::locate_resource_balance(memory, request(), "MissingResource"), "resource_not_found"),
          "an unknown resource is not found");
    const auto reads_before = memory.reads;
    check(refused_with(infra::locate_resource_balance(memory, request(), ""), "invalid_resource_name"),
          "an empty name is refused");
    check(memory.reads == reads_before, "an invalid name is refused before reading");
}

}  // namespace

int main() {
    test_names();
    test_snapshot_validation();
    test_quantity_admission();
    test_reads_inventory();
    test_profile_rejections();
    test_structure_rejections();
    test_passes();
    test_failures_and_cancellation();
    test_locate();
    if (failures == 0) {
        std::cout << "All Santa Monica inventory tests passed\n";
        return 0;
    }
    std::cerr << failures << " Santa Monica inventory test(s) failed\n";
    return 1;
}
