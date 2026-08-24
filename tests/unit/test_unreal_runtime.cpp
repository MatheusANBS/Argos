#include "sparse_fake_session.hpp"

#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/unreal_runtime.hpp"
#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace {

using argos::domain::Address;
using argos::testing::SparseProvider;
using argos::testing::SparseState;

int failures = 0;

void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// --- synthetic UE5-style fixture -------------------------------------------
//
// Built against the shipped ue5-fproperty-x64 profile, so the test exercises
// the constants the server actually offers rather than a private copy of them.
// No proprietary dump is involved: every structure is written here by hand.

constexpr Address module_base = 0x140000000ULL;
constexpr std::uint64_t module_size = 0x1000000ULL;
constexpr Address data_start = 0x140010000ULL;
constexpr Address object_array_root = 0x140010000ULL;
constexpr Address name_pool_root = 0x140010100ULL;
constexpr std::uint64_t object_array_rva = object_array_root - module_base;
constexpr std::uint64_t name_pool_rva = name_pool_root - module_base;

constexpr Address heap_start = 0x200000000ULL;
constexpr Address chunk_table = 0x200000000ULL;
constexpr Address chunk_zero = 0x200001000ULL;
constexpr Address objects_base = 0x200002000ULL;
constexpr Address classes_base = 0x200003000ULL;
constexpr Address properties_base = 0x200004000ULL;
constexpr Address field_classes_base = 0x200005000ULL;
constexpr Address name_block = 0x200006000ULL;

constexpr std::uint32_t elements_per_chunk = 64U * 1024U;
constexpr std::uint32_t item_size = 0x18U;

// Field offset kept as an explicit regression case, not as a constant of the
// product: a real build decides its own offsets.
constexpr std::uint64_t credits_offset = 0x590U;

struct NameWriter {
    SparseState* state{};
    std::uint32_t cursor{2U};

    [[nodiscard]] std::uint32_t add(const std::string_view text) {
        const auto offset = cursor;
        state->write_u16(name_block + offset, static_cast<std::uint16_t>(text.size() << 6U));
        std::vector<std::byte> encoded;
        encoded.reserve(text.size());
        for (const char ch : text) {
            encoded.push_back(static_cast<std::byte>(static_cast<unsigned char>(ch)));
        }
        state->write_bytes(name_block + offset + 2U, encoded);
        cursor = static_cast<std::uint32_t>((offset + 2U + text.size() + 1U) & ~std::size_t{1U});
        return offset / 2U;
    }
};

struct Fixture {
    std::shared_ptr<SparseState> state;
    Address class_player_state{};
    Address class_blueprint{};
    Address property_credits{};
    Address property_health{};
    Address property_score{};
};

void write_item(SparseState& state, const std::uint32_t slot, const Address object, const std::uint32_t serial) {
    const auto item = chunk_zero + static_cast<Address>(slot) * item_size;
    state.write_pointer(item + 0x00U, object, 8U);
    state.write_u32(item + 0x08U, 0U);
    state.write_u32(item + 0x10U, serial);
}

void write_object(
    SparseState& state,
    const Address object,
    const std::int32_t index,
    const Address class_address,
    const std::uint32_t name_index,
    const Address outer
) {
    state.write_u32(object + 0x08U, 0U);
    state.write_u32(object + 0x0CU, static_cast<std::uint32_t>(index));
    state.write_pointer(object + 0x10U, class_address, 8U);
    state.write_u32(object + 0x18U, name_index);
    state.write_pointer(object + 0x20U, outer, 8U);
}

void write_property(
    SparseState& state,
    const Address property,
    const Address field_class,
    const Address next,
    const std::uint32_t name_index,
    const std::uint32_t offset_internal,
    const std::uint32_t element_size,
    const std::uint32_t array_dim
) {
    state.write_pointer(property + 0x08U, field_class, 8U);
    state.write_pointer(property + 0x20U, next, 8U);
    state.write_u32(property + 0x28U, name_index);
    state.write_u32(property + 0x38U, array_dim);
    state.write_u32(property + 0x3CU, element_size);
    state.write_pointer(property + 0x40U, 0x0000000000000004ULL, 8U);
    state.write_u32(property + 0x4CU, offset_internal);
}

[[nodiscard]] Fixture make_fixture(const std::uint32_t live_slots = 4U) {
    Fixture fixture;
    fixture.state = std::make_shared<SparseState>();
    auto& state = *fixture.state;

    state.modules.push_back({
        "Game-Win64-Shipping.exe", "C:\\game\\Game-Win64-Shipping.exe", module_base, module_size
    });
    state.regions.push_back({data_start, data_start + 0x1000ULL, true, true, false, false, ".data"});
    state.regions.push_back({heap_start, heap_start + 0x10000ULL, true, true, false, true, ""});
    state.map_zeroed(data_start, 0x1000U);
    state.map_zeroed(heap_start, 0x10000U);

    NameWriter names{&state, 2U};
    const auto name_player_state = names.add("APlayerState");
    const auto name_blueprint = names.add("BP_PlayerState_C");
    const auto name_credits = names.add("Credits");
    const auto name_health = names.add("Health");
    const auto name_score = names.add("Score");
    const auto name_int_property = names.add("IntProperty");
    const auto name_float_property = names.add("FloatProperty");
    const auto name_default = names.add("DefaultPlayerState");
    const auto name_instance_a = names.add("BP_PlayerState_C_0");
    const auto name_instance_b = names.add("BP_PlayerState_C_1");

    // FNamePool: one block, its pointer stored in FNameEntryAllocator::Blocks.
    state.write_pointer(name_pool_root + 0x10U, name_block, 8U);

    // FUObjectArray -> FChunkedFixedUObjectArray.
    state.write_pointer(object_array_root + 0x10U, chunk_table, 8U);
    state.write_u32(object_array_root + 0x20U, elements_per_chunk);
    state.write_u32(object_array_root + 0x24U, live_slots);
    state.write_u32(object_array_root + 0x28U, 1U);
    state.write_u32(object_array_root + 0x2CU, 1U);
    state.write_pointer(chunk_table, chunk_zero, 8U);

    const Address field_class_int = field_classes_base;
    const Address field_class_float = field_classes_base + 0x40ULL;
    state.write_u32(field_class_int, name_int_property);
    state.write_u32(field_class_float, name_float_property);

    fixture.class_player_state = classes_base;
    fixture.class_blueprint = classes_base + 0x100ULL;
    fixture.property_credits = properties_base;
    fixture.property_health = properties_base + 0x80ULL;
    fixture.property_score = properties_base + 0x100ULL;

    write_property(state, fixture.property_credits, field_class_int, fixture.property_health,
                   name_credits, static_cast<std::uint32_t>(credits_offset), 4U, 1U);
    write_property(state, fixture.property_health, field_class_float, 0U,
                   name_health, 0x600U, 4U, 1U);
    write_property(state, fixture.property_score, field_class_int, 0U,
                   name_score, 0x700U, 4U, 1U);

    write_object(state, fixture.class_player_state, 100, 0U, name_player_state, 0U);
    state.write_pointer(fixture.class_player_state + 0x40U, 0U, 8U);
    state.write_pointer(fixture.class_player_state + 0x50U, fixture.property_credits, 8U);
    state.write_u32(fixture.class_player_state + 0x58U, 0x800U);

    write_object(state, fixture.class_blueprint, 101, 0U, name_blueprint, 0U);
    state.write_pointer(fixture.class_blueprint + 0x40U, fixture.class_player_state, 8U);
    state.write_pointer(fixture.class_blueprint + 0x50U, fixture.property_score, 8U);
    state.write_u32(fixture.class_blueprint + 0x58U, 0x900U);

    const Address object_default = objects_base;
    const Address object_a = objects_base + 0x100ULL;
    const Address object_b = objects_base + 0x200ULL;
    write_object(state, object_default, 0, fixture.class_player_state, name_default, 0U);
    write_object(state, object_a, 1, fixture.class_blueprint, name_instance_a, object_default);
    write_object(state, object_b, 3, fixture.class_blueprint, name_instance_b, object_default);

    write_item(state, 0U, object_default, 11U);
    write_item(state, 1U, object_a, 12U);
    // Slot 2 stays dead: a null object pointer must be skipped, not parsed.
    write_item(state, 2U, 0U, 0U);
    write_item(state, 3U, object_b, 13U);
    return fixture;
}

[[nodiscard]] argos::security::SecurityPolicy enabled_policy() {
    argos::security::SecurityPolicy policy;
    policy.enable_unreal_runtime = true;
    policy.unreal_profile_allowlist = {"ue5-fproperty-x64", "ue4-uproperty-x64"};
    return policy;
}

struct Harness {
    std::shared_ptr<SparseState> state;
    std::unique_ptr<argos::application::MemoryDebugService> service;
    argos::domain::SessionId session{*argos::domain::SessionId::create("harness")};
};

[[nodiscard]] Harness make_harness(
    std::shared_ptr<SparseState> state,
    argos::security::SecurityPolicy policy = enabled_policy()
) {
    Harness harness{std::move(state), nullptr, *argos::domain::SessionId::create("harness")};
    harness.service = std::make_unique<argos::application::MemoryDebugService>(
        std::make_unique<SparseProvider>(harness.state), policy
    );
    auto attached = harness.service->attach(4242U, argos::domain::AccessMode::read_only, true);
    if (!attached) {
        check(false, "unreal harness attaches");
        return harness;
    }
    harness.session = attached->id;
    return harness;
}

[[nodiscard]] argos::application::UnrealDiscoverRequest rva_request() {
    argos::application::UnrealDiscoverRequest request;
    request.module_name = "Game-Win64-Shipping.exe";
    request.profile_id = "ue5-fproperty-x64";
    request.mode = argos::domain::DiscoveryMode::explicit_roots;
    request.gu_object_array_rva = object_array_rva;
    request.fname_pool_rva = name_pool_rva;
    return request;
}

// --- gates ------------------------------------------------------------------

void test_feature_is_gated_off_by_default() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state, argos::security::SecurityPolicy{});
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!result.has_value(), "discovery is refused while the feature gate is off");
    check(!result && result.error().code == argos::domain::DebugErrorCode::unsupported,
          "a disabled feature reports unsupported");
}

void test_profile_must_be_allowlisted() {
    auto fixture = make_fixture();
    argos::security::SecurityPolicy policy;
    policy.enable_unreal_runtime = true;
    // Feature on, but no profile allowlisted: an empty allowlist means none.
    auto harness = make_harness(fixture.state, policy);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!result.has_value(), "an empty profile allowlist enables nothing");

    auto known = make_harness(fixture.state, enabled_policy());
    auto request = rva_request();
    request.profile_id = "ue9-imaginary";
    auto unknown = known.service->unreal_runtime_discover(known.session, request);
    check(!unknown.has_value(), "an unknown profile is refused");
    check(!unknown && unknown.error().code == argos::domain::DebugErrorCode::unsupported,
          "an unknown profile reports unsupported");
}

void test_auto_discovery_needs_its_own_gate() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state, enabled_policy());
    auto request = rva_request();
    request.mode = argos::domain::DiscoveryMode::auto_discovery;
    auto result = harness.service->unreal_runtime_discover(harness.session, request);
    check(!result.has_value(), "auto discovery stays off behind the general gate");
    check(!result && result.error().code == argos::domain::DebugErrorCode::unsupported,
          "auto discovery without its gate reports unsupported");
}

void test_roots_are_one_of_not_a_merge() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);

    auto mixed = rva_request();
    mixed.gu_object_array_address = object_array_root;
    mixed.fname_pool_address = name_pool_root;
    auto both = harness.service->unreal_runtime_discover(harness.session, mixed);
    check(!both.has_value(), "mixing RVA and absolute roots is rejected");

    auto partial = rva_request();
    partial.fname_pool_rva.reset();
    auto half = harness.service->unreal_runtime_discover(harness.session, partial);
    check(!half.has_value(), "half of a root pair is rejected");
    check(!half && half.error().code == argos::domain::DebugErrorCode::invalid_argument,
          "conflicting roots are an invalid argument");
}

// --- happy path -------------------------------------------------------------

void test_discover_validates_and_publishes() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(result.has_value(), "discovery over a valid fixture succeeds");
    if (!result) return;

    check(result->roots.origin == argos::domain::RootOrigin::explicit_rva, "the root origin is reported");
    check(result->roots.gu_object_array == object_array_root, "the RVA resolves against a fresh module base");
    check(result->provenance.confidence == argos::domain::RuntimeConfidence::high,
          "a module-bound profile with every invariant passing reaches high confidence");
    check(result->provenance.failed_invariants.empty(), "no invariant failed");
    check(result->provenance.source == "unreal:runtime-reflection",
          "runtime results stay a separate source from the PDB path");
    check(!result->provenance.process_fingerprint.empty(), "a comparable process fingerprint is published");
    check(result->class_count == 2U, "both classes reachable from live slots are catalogued");
    check(result->progress.slots_visited == 4U, "every live and dead slot is visited");
    check(result->progress.objects_found == 3U, "the dead slot is not counted as an object");
}

void test_classes_page_and_filter() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) {
        check(false, "classes test needs a published context");
        return;
    }
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    auto all = harness.service->unreal_runtime_classes(harness.session, runtime_id, "", 100U, "");
    check(all.has_value() && all->classes.size() == 2U, "the catalog lists both classes");
    check(all && all->classes.front().name == "APlayerState", "classes are ordered by name");
    check(all && all->classes.back().super_name.has_value() &&
              *all->classes.back().super_name == "APlayerState",
          "inheritance is resolved to a name");

    auto filtered = harness.service->unreal_runtime_classes(harness.session, runtime_id, "Blueprint", 100U, "");
    check(filtered.has_value() && filtered->classes.empty(), "a filter that matches nothing returns nothing");

    auto paged = harness.service->unreal_runtime_classes(harness.session, runtime_id, "", 1U, "");
    check(paged.has_value() && paged->classes.size() == 1U, "the limit caps the page");
    check(paged && paged->total_matched == 2U, "the total counts every match");
    check(paged && paged->next_page_token.has_value(), "a partial page offers a continuation token");
    if (paged && paged->next_page_token) {
        auto second = harness.service->unreal_runtime_classes(
            harness.session, runtime_id, "", 1U, *paged->next_page_token
        );
        check(second.has_value() && second->classes.size() == 1U, "the token returns the next page");
        check(second && second->classes.front().name != paged->classes.front().name,
              "pages do not repeat a class");
        auto wrong_filter = harness.service->unreal_runtime_classes(
            harness.session, runtime_id, "Player", 1U, *paged->next_page_token
        );
        check(!wrong_filter.has_value(), "a token is bound to the filter that produced it");
    }
}

void test_type_reports_declared_and_inherited_properties() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) {
        check(false, "type test needs a published context");
        return;
    }
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    auto type = harness.service->unreal_runtime_type(
        harness.session, runtime_id, std::nullopt, "BP_PlayerState_C", true, 256U, 32U
    );
    check(type.has_value(), "reading a catalogued type succeeds");
    if (!type) return;

    check(type->type.type.name == "BP_PlayerState_C", "the class name comes from FNamePool");
    check(type->type.declared_properties.size() == 1U, "declared properties belong to the class itself");
    check(type->type.declared_properties.front().name == "Score", "the declared property name resolves");
    check(type->type.declared_properties.front().reflected_kind == "IntProperty",
          "the property kind comes from FFieldClass");
    check(type->type.inherited_properties.size() == 2U, "inherited properties come from the super chain");

    const auto credits = std::ranges::find(
        type->type.inherited_properties, std::string{"Credits"}, &argos::domain::UnrealPropertyInfo::name
    );
    check(credits != type->type.inherited_properties.end(), "the inherited property is found");
    check(credits != type->type.inherited_properties.end() && credits->offset_internal == credits_offset,
          "FProperty offsets are read without a PDB");
    check(credits != type->type.inherited_properties.end() && credits->element_size == 4U,
          "element_size is reported");
    check(credits != type->type.inherited_properties.end() && credits->array_dim == 1U,
          "array_dim is reported");
    check(credits != type->type.inherited_properties.end() &&
              credits->declaring_class_name == "APlayerState",
          "the declaring class is reported for an inherited property");
    check(type->type.inherited_properties.front().offset_internal <=
              type->type.inherited_properties.back().offset_internal,
          "properties are ordered by offset");
}

void test_type_requires_an_unambiguous_catalogued_class() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    auto unknown = harness.service->unreal_runtime_type(
        harness.session, runtime_id, Address{0x200009000ULL}, "", true, 256U, 32U
    );
    check(!unknown.has_value(), "an address outside the catalog is refused");
    check(!unknown && unknown.error().code == argos::domain::DebugErrorCode::not_found,
          "an uncatalogued class is not_found");

    auto both = harness.service->unreal_runtime_type(
        harness.session, runtime_id, Address{fixture.class_blueprint}, "BP_PlayerState_C", true, 256U, 32U
    );
    check(!both.has_value(), "class_address and class_name are mutually exclusive");
}

void test_objects_filter_and_derived() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    auto exact = harness.service->unreal_runtime_objects(
        harness.session, runtime_id, "BP_PlayerState_C", false, 100U, ""
    );
    check(exact.has_value() && exact->objects.size() == 2U, "the exact class filter finds both instances");
    check(exact && exact->objects.front().object_name == "BP_PlayerState_C_0",
          "object names resolve through FNamePool");
    check(exact && exact->objects.front().outer_address.has_value(), "the outer object is reported");

    auto base_only = harness.service->unreal_runtime_objects(
        harness.session, runtime_id, "APlayerState", false, 100U, ""
    );
    check(base_only.has_value() && base_only->objects.size() == 1U,
          "without include_derived only exact instances match");

    auto derived = harness.service->unreal_runtime_objects(
        harness.session, runtime_id, "APlayerState", true, 100U, ""
    );
    check(derived.has_value() && derived->objects.size() == 3U,
          "include_derived walks the super chain");

    auto everything = harness.service->unreal_runtime_objects(harness.session, runtime_id, "", false, 100U, "");
    check(everything.has_value() && everything->objects.size() == 3U,
          "an empty filter enumerates every live object and skips the dead slot");
    check(everything && everything->objects.front().object_index == 0U,
          "objects are ordered by slot index");
}

void test_objects_paging_skips_nothing() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    // One object per page: the continuation must resume at the slot the sweep
    // stopped on, not past the whole run it had already read.
    std::vector<std::uint64_t> seen;
    std::string token;
    for (int page = 0; page < 6; ++page) {
        auto result = harness.service->unreal_runtime_objects(
            harness.session, runtime_id, "", false, 1U, token
        );
        check(result.has_value(), "each object page succeeds");
        if (!result) return;
        for (const auto& object : result->objects) seen.push_back(object.object_index);
        if (!result->next_page_token) break;
        token = *result->next_page_token;
    }
    check(seen.size() == 3U, "paging one object at a time still returns every live object");
    check(std::ranges::find(seen, std::uint64_t{0}) != seen.end() &&
              std::ranges::find(seen, std::uint64_t{1}) != seen.end() &&
              std::ranges::find(seen, std::uint64_t{3}) != seen.end(),
          "no live slot is skipped between pages");
}

void test_objects_never_return_field_values() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);
    auto objects = harness.service->unreal_runtime_objects(harness.session, runtime_id, "", false, 100U, "");
    check(objects.has_value(), "object enumeration succeeds");
    if (!objects) return;
    // The summary carries addresses and names only; reading a field still needs
    // an explicit memory_debug read under the session's own policy.
    for (const auto& object : objects->objects) {
        check(object.object_address != 0U, "each summary points at the object");
        check(!object.class_name.empty(), "each summary names its class");
    }
}

// --- hostile input ----------------------------------------------------------

void test_hostile_counts_are_rejected_before_sweeping() {
    auto fixture = make_fixture();
    // NumElements above MaxElements: a sweep driven by this would read past the
    // chunk table.
    fixture.state->write_u32(object_array_root + 0x24U, 1000000U);
    fixture.state->write_u32(object_array_root + 0x20U, 8U);
    auto harness = make_harness(fixture.state);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!result.has_value(), "inconsistent counts reject the context");
    check(!result && result.error().code == argos::domain::DebugErrorCode::invalid_argument,
          "hostile counts are an invalid argument");
}

void test_unaligned_root_is_rejected() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto request = rva_request();
    request.gu_object_array_rva = object_array_rva + 1U;
    auto result = harness.service->unreal_runtime_discover(harness.session, request);
    check(!result.has_value(), "a misaligned root is rejected");
}

void test_root_outside_module_is_rejected() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto request = rva_request();
    request.gu_object_array_rva = module_size + 0x1000U;
    auto result = harness.service->unreal_runtime_discover(harness.session, request);
    check(!result.has_value(), "an RVA outside the module is rejected");
    check(!result && result.error().code == argos::domain::DebugErrorCode::invalid_argument,
          "an out-of-module RVA is an invalid argument");
}

void test_short_read_is_not_zero_bytes() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    harness.state->short_read_limit = 4U;
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!result.has_value(), "a short read fails instead of parsing zeros");
    check(!result && result.error().code == argos::domain::DebugErrorCode::io_error,
          "a short read is an io error");
}

void test_hostile_name_length_lowers_confidence_without_inventing_names() {
    auto fixture = make_fixture();
    auto policy = enabled_policy();
    policy.max_unreal_name_bytes = 4U;
    auto harness = make_harness(fixture.state, policy);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(result.has_value(), "unreadable names do not crash discovery");
    if (!result) return;
    check(result->provenance.confidence != argos::domain::RuntimeConfidence::high,
          "names that exceed the limit prevent high confidence");
    check(!result->provenance.failed_invariants.empty(), "the failed invariant is reported");
    check(result->class_count == 0U, "no class is catalogued with a fabricated name");
}

void test_property_chain_cycle_is_detected() {
    auto fixture = make_fixture();
    // The blueprint class points its only property back at itself.
    fixture.state->write_pointer(fixture.property_score + 0x20U, fixture.property_score, 8U);
    auto harness = make_harness(fixture.state);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(result.has_value(), "a cyclic property chain does not hang or fail the whole sweep");
    if (!result) return;
    check(result->progress.classes_rejected == 1U, "the class with the cyclic chain is counted as rejected");
    check(result->class_count == 1U, "only the structurally valid class is catalogued");

    const auto runtime_id = *argos::domain::RuntimeId::create(result->runtime_id);
    auto rejected = harness.service->unreal_runtime_type(
        harness.session, runtime_id, std::nullopt, "BP_PlayerState_C", true, 256U, 32U
    );
    check(!rejected.has_value(), "the rejected class is not queryable as if it were valid");

    auto valid = harness.service->unreal_runtime_type(
        harness.session, runtime_id, std::nullopt, "APlayerState", false, 256U, 32U
    );
    check(valid.has_value() && valid->type.declared_properties.size() == 2U,
          "the untouched class still reads correctly");
}

void test_super_chain_cycle_is_detected() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) {
        check(false, "super cycle test needs a published context");
        return;
    }
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);
    // Close the loop after publication so the walk hits it.
    harness.state->write_pointer(fixture.class_player_state + 0x40U, fixture.class_blueprint, 8U);

    auto type = harness.service->unreal_runtime_type(
        harness.session, runtime_id, std::nullopt, "BP_PlayerState_C", true, 256U, 32U
    );
    check(type.has_value(), "a cyclic super chain still returns what was validated");
    if (!type) return;
    const auto reported = std::ranges::find(
        type->provenance.failed_invariants, argos::domain::RuntimeInvariant::super_chain_acyclic
    );
    check(reported != type->provenance.failed_invariants.end(), "the super chain cycle is reported");
    check(type->provenance.confidence == argos::domain::RuntimeConfidence::low,
          "a failed invariant lowers the confidence of the answer");
}

void test_mutating_target_reports_unstable_snapshot() {
    auto fixture = make_fixture();
    // A slot recycled on every read while the counts stay constant: only the
    // tuple digest can catch this.
    fixture.state->mutating_addresses.push_back(chunk_zero + item_size + 0x10U);
    fixture.state->mutate_every_reads = 1U;
    auto harness = make_harness(fixture.state);
    auto result = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!result.has_value(), "a target that keeps changing does not publish a mixed catalog");
    check(!result && result.error().code == argos::domain::DebugErrorCode::io_error,
          "an unstable snapshot is an io error");
    check(!result && result.error().safe_message == "unstable_snapshot",
          "the reason names the instability");
}

// --- context lifecycle ------------------------------------------------------

void test_context_requires_its_owner() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    auto other = harness.service->attach(4242U, argos::domain::AccessMode::read_only, true);
    check(other.has_value(), "a second session attaches");
    if (!other) return;
    auto stolen = harness.service->unreal_runtime_classes(other->id, runtime_id, "", 10U, "");
    check(!stolen.has_value(), "a runtime id alone is not a capability");
    check(!stolen && stolen.error().code == argos::domain::DebugErrorCode::not_found,
          "another owner sees not_found, not a hint that the id exists");
}

void test_release_and_detach_invalidate_the_context() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    auto discovered = harness.service->unreal_runtime_discover(harness.session, rva_request());
    if (!discovered) return;
    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);

    check(harness.service->unreal_runtime_release(harness.session, runtime_id).has_value(),
          "release succeeds for the owner");
    check(harness.service->unreal_runtime_release(harness.session, runtime_id).has_value(),
          "release is idempotent during the tombstone window");
    auto after = harness.service->unreal_runtime_classes(harness.session, runtime_id, "", 10U, "");
    check(!after.has_value(), "a released context cannot be queried");

    auto second = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(second.has_value(), "a new context can be published after a release");
    if (!second) return;
    const auto second_id = *argos::domain::RuntimeId::create(second->runtime_id);
    check(harness.service->detach(harness.session).has_value(), "detach succeeds");
    auto after_detach = harness.service->unreal_runtime_classes(harness.session, second_id, "", 10U, "");
    check(!after_detach.has_value(), "detach invalidates every context of the session");
}

void test_context_quota_and_ttl() {
    auto fixture = make_fixture();
    auto policy = enabled_policy();
    policy.max_unreal_contexts_per_session = 1U;
    auto harness = make_harness(fixture.state, policy);
    check(harness.service->unreal_runtime_discover(harness.session, rva_request()).has_value(),
          "the first context fits the quota");
    auto second = harness.service->unreal_runtime_discover(harness.session, rva_request());
    check(!second.has_value(), "the per-session quota is enforced");
    check(!second && second.error().code == argos::domain::DebugErrorCode::limit_exceeded,
          "a quota breach is a limit error");

    auto expiring_policy = enabled_policy();
    expiring_policy.unreal_context_ttl_seconds = 0U;
    auto expiring = make_harness(make_fixture().state, expiring_policy);
    auto published = expiring.service->unreal_runtime_discover(expiring.session, rva_request());
    check(published.has_value(), "a context with a zero TTL is still published");
    if (!published) return;
    const auto expired_id = *argos::domain::RuntimeId::create(published->runtime_id);
    auto query = expiring.service->unreal_runtime_classes(expiring.session, expired_id, "", 10U, "");
    check(!query.has_value(), "an expired context cannot be queried");
    check(!query && query.error().code == argos::domain::DebugErrorCode::invalid_state,
          "an expired context is an invalid state");
}

// --- legacy profile ---------------------------------------------------------

// UE4-style layout: properties hang off UStruct::Children as UObjects, and
// names live in a chunked array of FNameEntry pointers. Nothing is shared with
// the modern profile by fallback.
void test_legacy_uproperty_profile() {
    auto state = std::make_shared<SparseState>();
    constexpr Address legacy_names_root = 0x140010200ULL;
    constexpr Address legacy_name_chunk = 0x200007000ULL;
    constexpr Address legacy_entries = 0x200008000ULL;

    state->modules.push_back({"UE4Game.exe", "C:\\g\\UE4Game.exe", module_base, module_size});
    state->regions.push_back({data_start, data_start + 0x1000ULL, true, true, false, false, ".data"});
    state->regions.push_back({heap_start, heap_start + 0x10000ULL, true, true, false, true, ""});
    state->map_zeroed(data_start, 0x1000U);
    state->map_zeroed(heap_start, 0x10000U);

    // TNameEntryArray: chunk table inline at the root, chunk of FNameEntry*.
    state->write_pointer(legacy_names_root, legacy_name_chunk, 8U);
    const auto legacy_name = [&](const std::uint32_t index, const std::string_view text) {
        const auto entry = legacy_entries + static_cast<Address>(index) * 0x80ULL;
        state->write_pointer(legacy_name_chunk + static_cast<Address>(index) * 8ULL, entry, 8U);
        state->write_u32(entry, index << 1U);  // bit 0 clear: narrow characters
        state->write_text(entry + 0x10U, text);
        return index;
    };
    const auto name_class = legacy_name(1U, "AActor");
    const auto name_property = legacy_name(2U, "Credits");
    const auto name_kind = legacy_name(3U, "IntProperty");
    const auto name_object = legacy_name(4U, "Actor_0");

    state->write_pointer(object_array_root + 0x10U, chunk_table, 8U);
    state->write_u32(object_array_root + 0x20U, 16U * 1024U);
    state->write_u32(object_array_root + 0x24U, 1U);
    state->write_u32(object_array_root + 0x28U, 1U);
    state->write_u32(object_array_root + 0x2CU, 1U);
    state->write_pointer(chunk_table, chunk_zero, 8U);

    const Address legacy_class = classes_base;
    const Address legacy_property = properties_base;
    const Address legacy_kind_class = field_classes_base;
    const Address legacy_object = objects_base;

    write_object(*state, legacy_kind_class, 200, 0U, name_kind, 0U);
    write_object(*state, legacy_class, 201, 0U, name_class, 0U);
    state->write_pointer(legacy_class + 0x30U, 0U, 8U);            // SuperStruct
    state->write_pointer(legacy_class + 0x38U, legacy_property, 8U);  // Children

    write_object(*state, legacy_property, 202, legacy_kind_class, name_property, 0U);
    state->write_pointer(legacy_property + 0x28U, 0U, 8U);  // UField::Next
    state->write_u32(legacy_property + 0x30U, 1U);          // ArrayDim
    state->write_u32(legacy_property + 0x34U, 4U);          // ElementSize
    state->write_u32(legacy_property + 0x44U, static_cast<std::uint32_t>(credits_offset));

    write_object(*state, legacy_object, 0, legacy_class, name_object, 0U);
    write_item(*state, 0U, legacy_object, 7U);

    auto harness = make_harness(state);
    argos::application::UnrealDiscoverRequest request;
    request.module_name = "UE4Game.exe";
    request.profile_id = "ue4-uproperty-x64";
    request.mode = argos::domain::DiscoveryMode::explicit_roots;
    request.gu_object_array_rva = object_array_rva;
    request.fname_pool_rva = legacy_names_root - module_base;

    auto discovered = harness.service->unreal_runtime_discover(harness.session, request);
    check(discovered.has_value(), "the legacy profile discovers its own layout");
    if (!discovered) return;
    check(discovered->class_count == 1U, "the legacy catalog holds the class");

    const auto runtime_id = *argos::domain::RuntimeId::create(discovered->runtime_id);
    auto type = harness.service->unreal_runtime_type(
        harness.session, runtime_id, std::nullopt, "AActor", false, 128U, 16U
    );
    check(type.has_value(), "the legacy profile reads a UProperty chain");
    if (!type) return;
    check(type->type.declared_properties.size() == 1U, "the legacy property is found through Children");
    check(type->type.declared_properties.front().name == "Credits",
          "legacy names decode from a NUL-terminated entry");
    check(type->type.declared_properties.front().offset_internal == credits_offset,
          "the legacy offset is read at its own layout position");
    check(type->type.declared_properties.front().reflected_kind == "IntProperty",
          "the legacy property kind comes from its UClass");
}

void test_profiles_do_not_share_offsets() {
    auto fixture = make_fixture();
    auto harness = make_harness(fixture.state);
    // The modern fixture parsed with the legacy profile must fail structurally
    // rather than silently borrow offsets that happen to be readable.
    auto request = rva_request();
    request.profile_id = "ue4-uproperty-x64";
    auto result = harness.service->unreal_runtime_discover(harness.session, request);
    const bool refused = !result.has_value() ||
        result->provenance.confidence != argos::domain::RuntimeConfidence::high;
    check(refused, "a profile mismatch never produces a high-confidence context");
}

}  // namespace

int main() {
    test_feature_is_gated_off_by_default();
    test_profile_must_be_allowlisted();
    test_auto_discovery_needs_its_own_gate();
    test_roots_are_one_of_not_a_merge();

    test_discover_validates_and_publishes();
    test_classes_page_and_filter();
    test_type_reports_declared_and_inherited_properties();
    test_type_requires_an_unambiguous_catalogued_class();
    test_objects_filter_and_derived();
    test_objects_paging_skips_nothing();
    test_objects_never_return_field_values();

    test_hostile_counts_are_rejected_before_sweeping();
    test_unaligned_root_is_rejected();
    test_root_outside_module_is_rejected();
    test_short_read_is_not_zero_bytes();
    test_hostile_name_length_lowers_confidence_without_inventing_names();
    test_property_chain_cycle_is_detected();
    test_super_chain_cycle_is_detected();
    test_mutating_target_reports_unstable_snapshot();

    test_context_requires_its_owner();
    test_release_and_detach_invalidate_the_context();
    test_context_quota_and_ttl();

    test_legacy_uproperty_profile();
    test_profiles_do_not_share_offsets();

    if (failures == 0) {
        std::cout << "All unreal runtime tests passed\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed\n";
    return 1;
}
