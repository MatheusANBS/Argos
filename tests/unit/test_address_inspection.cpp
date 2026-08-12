#include "sparse_fake_session.hpp"

#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

using argos::domain::Address;
using argos::domain::TargetPointerWidth;
using argos::testing::SparseProvider;
using argos::testing::SparseState;

int failures = 0;

void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

// --- fixtures ---------------------------------------------------------------

constexpr Address x64_module_base = 0x140000000ULL;
constexpr Address x64_text_start = 0x140001000ULL;
constexpr Address x64_rdata_start = 0x140002000ULL;
constexpr Address x64_vtable = 0x140002100ULL;
constexpr Address x64_heap_start = 0x1FE44726000ULL;
constexpr Address x64_object = 0x1FE44726700ULL;
constexpr Address x64_field = x64_object + 0x590ULL;

// x64 target: a heap object whose first qword points at a vtable in the
// module's read-only data, with every sampled entry landing in executable code.
[[nodiscard]] std::shared_ptr<SparseState> make_x64_state() {
    auto state = std::make_shared<SparseState>();
    state->modules.push_back({"game.exe", "C:\\game\\game.exe", x64_module_base, 0x100000ULL});
    state->regions.push_back({x64_text_start, x64_text_start + 0x1000ULL, true, false, true, false, ".text"});
    state->regions.push_back({x64_rdata_start, x64_rdata_start + 0x1000ULL, true, false, false, false, ".rdata"});
    state->regions.push_back({x64_heap_start, x64_heap_start + 0x2000ULL, true, true, false, true, ""});

    state->map_zeroed(x64_text_start, 0x1000U);
    state->map_zeroed(x64_rdata_start, 0x1000U);
    state->map_zeroed(x64_heap_start, 0x2000U);

    state->write_pointer(x64_object, x64_vtable, 8U);
    for (std::size_t entry = 0; entry < 8U; ++entry) {
        state->write_pointer(x64_vtable + entry * 8U, x64_text_start + entry * 0x10ULL, 8U);
    }
    return state;
}

constexpr Address x86_module_base = 0x00400000ULL;
constexpr Address x86_text_start = 0x00401000ULL;
constexpr Address x86_rdata_start = 0x00402000ULL;
constexpr Address x86_vtable = 0x00402100ULL;
constexpr Address x86_heap_start = 0x00A00000ULL;
constexpr Address x86_object = 0x00A00700ULL;
constexpr Address x86_field = x86_object + 0x590ULL;

[[nodiscard]] std::shared_ptr<SparseState> make_x86_state() {
    auto state = std::make_shared<SparseState>();
    state->modules.push_back({"game32.exe", "C:\\game\\game32.exe", x86_module_base, 0x10000ULL});
    state->regions.push_back({x86_text_start, x86_text_start + 0x1000ULL, true, false, true, false, ".text"});
    state->regions.push_back({x86_rdata_start, x86_rdata_start + 0x1000ULL, true, false, false, false, ".rdata"});
    state->regions.push_back({x86_heap_start, x86_heap_start + 0x2000ULL, true, true, false, true, ""});

    state->map_zeroed(x86_text_start, 0x1000U);
    state->map_zeroed(x86_rdata_start, 0x1000U);
    state->map_zeroed(x86_heap_start, 0x2000U);

    state->write_pointer(x86_object, x86_vtable, 4U);
    for (std::size_t entry = 0; entry < 8U; ++entry) {
        state->write_pointer(x86_vtable + entry * 4U, x86_text_start + entry * 0x10ULL, 4U);
    }
    return state;
}

[[nodiscard]] argos::application::AddressInspectionRequest x64_request() {
    argos::application::AddressInspectionRequest request;
    request.address = x64_field;
    request.pointer_width = TargetPointerWidth::x64;
    request.limits.lookbehind_bytes = 2048U;
    request.limits.vtable_entries = 8U;
    request.limits.min_executable_entries = 3U;
    request.limits.max_candidates = 8U;
    return request;
}

struct Harness {
    std::shared_ptr<SparseState> state;
    std::unique_ptr<argos::application::MemoryDebugService> service;
    argos::domain::SessionId session{*argos::domain::SessionId::create("harness")};
};

[[nodiscard]] Harness make_harness(
    std::shared_ptr<SparseState> state,
    argos::security::SecurityPolicy policy = {}
) {
    Harness harness{std::move(state), nullptr, *argos::domain::SessionId::create("harness")};
    harness.service = std::make_unique<argos::application::MemoryDebugService>(
        std::make_unique<SparseProvider>(harness.state), policy
    );
    auto attached = harness.service->attach(4242U, argos::domain::AccessMode::read_only, true);
    if (!attached) {
        check(false, "sparse harness attaches");
        return harness;
    }
    harness.session = attached->id;
    harness.state->reset_counters();
    return harness;
}

// --- pure domain ------------------------------------------------------------

void test_region_index_half_open() {
    const std::vector<argos::domain::MemoryRegion> regions{
        {0x2000U, 0x3000U, true, false, false, true, "second"},
        {0x1000U, 0x1100U, true, true, false, true, "first"},
        {0x5000U, 0x5000U, true, true, false, true, "degenerate"}
    };
    const auto index = argos::domain::RegionIndex::create(regions);
    check(index.size() == 2U, "region index drops degenerate intervals");
    check(index.all().front().start == 0x1000U, "region index sorts by start");
    check(index.find(0x1000U) != nullptr, "first byte of a region is inside it");
    check(index.find(0x10FFU) != nullptr, "last byte of a region is inside it");
    check(index.find(0x1100U) == nullptr, "end of a region is exclusive");
    check(index.find(0x1FFFU) == nullptr, "a gap between regions matches nothing");
    check(index.find(0x2000U) != nullptr, "the next region starts at its own start");
    check(index.find(0x9000U) == nullptr, "an address above every region matches nothing");
    check(index.find(0x0U) == nullptr, "an address below every region matches nothing");
}

void test_module_index_and_rva() {
    const std::vector<argos::domain::ModuleInfo> modules{
        {"b.dll", "b", 0x200000U, 0x1000U},
        {"a.exe", "a", 0x100000U, 0x2000U},
        {"empty.dll", "empty", 0x300000U, 0U},
        {"overflow.dll", "overflow", 0xFFFFFFFFFFFFFF00ULL, 0x1000U}
    };
    const auto index = argos::domain::ModuleIndex::create(modules);
    check(index.all().size() == 2U, "zero-sized and overflowing modules are dropped");
    const auto reference = index.reference(0x100590U);
    check(reference.has_value(), "an address inside a module resolves");
    check(reference && reference->rva == 0x590U, "rva is the offset from the module base");
    check(!index.reference(0x102000U).has_value(), "the module end is exclusive");
    check(!index.reference(0x1FFFFFU).has_value(), "a gap between modules resolves to nothing");
}

void test_pointer_decode_and_arithmetic() {
    const std::array<std::byte, 9> raw{
        std::byte{0x00},
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44},
        std::byte{0x55}, std::byte{0x66}, std::byte{0x77}, std::byte{0x88}
    };
    // Deliberately decoded from an offset that is not pointer aligned in the
    // buffer: alignment is a property of the virtual address, not of storage.
    const auto unaligned = std::span<const std::byte>{raw}.subspan(1U);
    check(
        argos::domain::decode_target_pointer(unaligned, TargetPointerWidth::x86) == 0x44332211ULL,
        "x86 decodes exactly four little-endian bytes"
    );
    check(
        argos::domain::decode_target_pointer(unaligned, TargetPointerWidth::x64) == 0x8877665544332211ULL,
        "x64 decodes exactly eight little-endian bytes"
    );
    check(!argos::domain::checked_add(0xFFFFFFFFFFFFFFFFULL, 1U).has_value(), "checked_add rejects overflow");
    check(!argos::domain::checked_sub(0x10U, 0x11U).has_value(), "checked_sub rejects underflow");
}

void test_lookbehind_window_clamps() {
    const argos::domain::MemoryRegion region{0x1000U, 0x2000U, true, true, false, true, ""};
    const auto clamped = argos::domain::compute_lookbehind_window(
        0x1010U, TargetPointerWidth::x64, 4096U, region
    );
    check(clamped.has_value(), "a lookbehind larger than the region still produces a window");
    check(clamped && clamped->start == 0x1000U, "the window clamps to the region start");
    check(clamped && clamped->clamped_by_region, "clamping is reported");
    check(clamped && clamped->end == 0x1018U, "the window includes one pointer at the inspected address");

    const argos::domain::MemoryRegion low{0x0U, 0x100U, true, true, false, true, ""};
    const auto near_zero = argos::domain::compute_lookbehind_window(
        0x8U, TargetPointerWidth::x64, 4096U, low
    );
    check(near_zero.has_value(), "a lookbehind past zero does not underflow");
    check(near_zero && near_zero->start == 0U, "the window floors at zero");

    const argos::domain::MemoryRegion elsewhere{0x9000U, 0x9100U, true, true, false, true, ""};
    check(
        !argos::domain::compute_lookbehind_window(0x1010U, TargetPointerWidth::x64, 64U, elsewhere).has_value(),
        "an address outside the region is rejected"
    );
}

void test_inspection_limits_validation() {
    argos::domain::InspectionLimits limits;
    limits.vtable_entries = 4U;
    limits.min_executable_entries = 5U;
    check(!limits.validate().has_value(), "min_executable_entries above vtable_entries is rejected");
    limits.min_executable_entries = 4U;
    check(limits.validate().has_value(), "a consistent limit set is accepted");
    limits.lookbehind_bytes = argos::domain::inspection_max_lookbehind_bytes + 1U;
    check(!limits.validate().has_value(), "lookbehind above the hard cap is rejected");
}

void test_resume_token_is_bound_to_its_query() {
    constexpr std::uint64_t key = 0xA5A5A5A5DEADBEEFULL;
    const auto binding = argos::domain::resume_token::binding(
        "session-a", 0x1000U, TargetPointerWidth::x64, false, std::nullopt, std::nullopt
    );
    const auto other = argos::domain::resume_token::binding(
        "session-b", 0x1000U, TargetPointerWidth::x64, false, std::nullopt, std::nullopt
    );
    const auto token = argos::domain::resume_token::encode(key, binding, 0x4000U);
    check(argos::domain::resume_token::decode(token, key, binding) == 0x4000U, "a token round-trips");
    check(!argos::domain::resume_token::decode(token, key, other).has_value(),
          "a token from another session is rejected");
    check(!argos::domain::resume_token::decode(token, key + 1U, binding).has_value(),
          "a token minted with another server key is rejected");
    check(!argos::domain::resume_token::decode("0x4000", key, binding).has_value(),
          "a raw address is not accepted as a continuation");
}

// --- service over the sparse fixture ---------------------------------------

void test_inspect_x64_object_candidate() {
    auto harness = make_harness(make_x64_state());
    auto result = harness.service->inspect_address(harness.session, x64_request());
    check(result.has_value(), "x64 inspection succeeds");
    if (!result) return;

    check(result->region.has_value(), "the inspected address resolves to a region");
    check(result->region && result->region->writable, "the heap region reports its protections");
    check(!result->module.has_value(), "a heap address has no owning module");
    check(result->analysis.complete, "a fully readable window reports a complete analysis");
    check(result->candidates_total == 1U, "exactly one shape reaches the evidence minimum");
    if (result->candidates.empty()) {
        check(false, "x64 inspection returns a candidate");
        return;
    }

    const auto& candidate = result->candidates.front();
    check(candidate.object_address == x64_object, "the object base is the pointer-aligned vptr slot");
    check(candidate.field_offset == 0x590U, "field_offset is the derived distance to the object base");
    check(candidate.vtable.address == x64_vtable, "the probable vtable address is reported");
    check(candidate.vtable.module.has_value(), "the vtable resolves to its owning module");
    check(candidate.vtable.module && candidate.vtable.module->rva == x64_vtable - x64_module_base,
          "the vtable rva is relative to the module base");
    check(candidate.confidence == argos::domain::DerivedConfidence::high,
          "eight executable entries in the owning module reach high confidence");

    const auto executable = std::ranges::find(
        candidate.evidence, argos::domain::EvidenceKind::executable_vtable_entry,
        &argos::domain::DerivedEvidence::kind
    );
    check(executable != candidate.evidence.end(), "executable entries are reported as evidence");
    check(executable != candidate.evidence.end() && executable->observed == 8U && executable->sampled == 8U,
          "evidence separates observed from sampled");
    check(candidate.provenance.size() == 4U, "provenance lists every derived source");
}

void test_inspect_x86_matches_x64_meaning() {
    auto harness = make_harness(make_x86_state());
    argos::application::AddressInspectionRequest request;
    request.address = x86_field;
    request.pointer_width = TargetPointerWidth::x86;
    request.limits.lookbehind_bytes = 2048U;
    request.limits.vtable_entries = 8U;
    request.limits.min_executable_entries = 3U;

    auto result = harness.service->inspect_address(harness.session, request);
    check(result.has_value(), "x86 inspection succeeds on a 64-bit host");
    if (!result || result->candidates.empty()) {
        check(false, "x86 inspection returns a candidate");
        return;
    }
    check(result->candidates.front().object_address == x86_object, "x86 finds the same object base");
    check(result->candidates.front().field_offset == 0x590U, "x86 derives the same field offset");
    check(result->candidates.front().vtable.address == x86_vtable, "x86 reads a four-byte vptr");
}

void test_inspect_rejects_wide_address_in_x86_mode() {
    auto harness = make_harness(make_x86_state());
    argos::application::AddressInspectionRequest request;
    request.address = 0x1FE44726C90ULL;
    request.pointer_width = TargetPointerWidth::x86;
    auto result = harness.service->inspect_address(harness.session, request);
    check(!result.has_value(), "a 64-bit address is not silently truncated in x86 mode");
    check(!result && result.error().code == argos::domain::DebugErrorCode::invalid_argument,
          "the truncation attempt is an invalid argument");
    check(harness.state->reads.load() == 0U, "the rejection happens before any process read");
}

void test_inspect_ranks_multiple_bases() {
    auto state = make_x64_state();
    // A second plausible base further back: both are reported, ranked, with
    // distinct offsets instead of one silently chosen truth.
    state->write_pointer(x64_object - 0x100ULL, x64_vtable, 8U);
    auto harness = make_harness(std::move(state));

    auto result = harness.service->inspect_address(harness.session, x64_request());
    check(result.has_value(), "inspection with two plausible bases succeeds");
    if (!result || result->candidates.size() < 2U) {
        check(false, "both plausible bases are returned");
        return;
    }
    check(result->candidates_total == 2U, "the total counts every shape that met the minimum");
    check(result->candidates[0].field_offset == 0x590U, "the nearest base ranks first on a tie");
    check(result->candidates[1].field_offset == 0x690U, "the farther base keeps its own derived offset");
    check(result->candidates[0].object_address != result->candidates[1].object_address,
          "candidates are distinct");
}

void test_inspect_ignores_non_executable_vtable_shape() {
    auto state = make_x64_state();
    // The vptr still points into the module's read-only data, but the entries
    // now point at data rather than code.
    for (std::size_t entry = 0; entry < 8U; ++entry) {
        state->write_pointer(x64_vtable + entry * 8U, x64_rdata_start + 0x800ULL + entry * 8U, 8U);
    }
    auto harness = make_harness(std::move(state));

    auto result = harness.service->inspect_address(harness.session, x64_request());
    check(result.has_value(), "inspection without executable entries still succeeds");
    check(result && result->candidates.empty(), "a shape without executable entries is not a candidate");
    check(result && result->candidates_total == 0U, "no candidate total is reported either");
}

void test_inspect_reports_short_vtable_read() {
    auto state = make_x64_state();
    auto harness = make_harness(std::move(state));
    // Every read is capped, so the vtable probe cannot complete.
    harness.state->short_read_limit = 24U;

    auto result = harness.service->inspect_address(harness.session, x64_request());
    check(result.has_value(), "a short read does not fail the whole inspection");
    if (!result) return;
    check(!result->analysis.complete, "a short read makes the analysis incomplete");
    const auto limitation = std::ranges::find(
        result->analysis.limitations, argos::domain::InspectionLimitation::lookbehind_short_read
    );
    check(limitation != result->analysis.limitations.end(), "the short read is reported as a limitation");
    for (const auto& candidate : result->candidates) {
        check(candidate.confidence != argos::domain::DerivedConfidence::high,
              "a truncated sample never reaches high confidence");
    }
}

void test_inspect_unmapped_and_unreadable_addresses() {
    auto state = make_x64_state();
    state->regions.push_back({0x30000U, 0x31000U, false, false, false, true, "guard"});
    auto harness = make_harness(std::move(state));

    argos::application::AddressInspectionRequest missing = x64_request();
    missing.address = 0x9000000000ULL;
    auto unmapped = harness.service->inspect_address(harness.session, missing);
    check(unmapped.has_value(), "an unmapped address is a result, not an error");
    check(unmapped && !unmapped->region.has_value(), "an unmapped address reports no region");
    check(unmapped && unmapped->candidates.empty(), "an unmapped address invents no candidate");
    check(unmapped && !unmapped->analysis.complete, "an unmapped address marks the analysis incomplete");

    harness.state->reset_counters();
    argos::application::AddressInspectionRequest guarded = x64_request();
    guarded.address = 0x30100U;
    auto unreadable = harness.service->inspect_address(harness.session, guarded);
    check(unreadable.has_value(), "an unreadable region is a result, not an error");
    check(unreadable && unreadable->region.has_value(), "an unreadable region is still described");
    check(harness.state->reads.load() == 0U, "no speculative read is issued into an unreadable region");
}

void test_inspect_reads_maps_once_and_coalesces_probes() {
    auto state = make_x64_state();
    // Two bases sharing one vptr: the probe must be read a single time.
    state->write_pointer(x64_object - 0x100ULL, x64_vtable, 8U);
    auto harness = make_harness(std::move(state));

    auto result = harness.service->inspect_address(harness.session, x64_request());
    check(result.has_value(), "inspection with a shared vtable succeeds");
    check(harness.state->region_calls.load() == 1U, "regions are enumerated once per inspection");
    check(harness.state->module_calls.load() == 1U, "modules are enumerated once per inspection");
    check(result && result->analysis.vtable_probes_attempted == 1U,
          "a repeated vtable address is probed once");
    check(harness.state->reads.load() == 2U, "one lookbehind read plus one vtable probe");
}

void test_inspect_handles_unaligned_window_start() {
    auto harness = make_harness(make_x64_state());
    // A lookbehind that stops short of the first pointer-aligned base: the
    // aligned-down base sits below the sampled window and must not be read.
    argos::application::AddressInspectionRequest request = x64_request();
    request.address = x64_field + 4U;
    request.limits.lookbehind_bytes = 0U;
    auto result = harness.service->inspect_address(harness.session, request);
    check(result.has_value(), "an unaligned address with an empty lookbehind still answers");
    check(result && result->candidates.empty(), "no base fits inside the window, so none is reported");

    // The same address with room to reach the object base finds it again.
    request.limits.lookbehind_bytes = 2048U;
    auto wider = harness.service->inspect_address(harness.session, request);
    check(wider.has_value() && !wider->candidates.empty(),
          "a wider window reaches the aligned base below an unaligned address");
    check(wider && !wider->candidates.empty() && wider->candidates.front().field_offset == 0x594U,
          "field_offset stays the derived distance from the unaligned address");
}

void test_inspect_rejects_limits_before_io() {
    auto harness = make_harness(make_x64_state());
    argos::application::AddressInspectionRequest request = x64_request();
    request.limits.lookbehind_bytes = argos::domain::inspection_max_lookbehind_bytes + 1U;
    auto result = harness.service->inspect_address(harness.session, request);
    check(!result.has_value(), "a lookbehind above the cap is rejected");
    check(!result && result.error().code == argos::domain::DebugErrorCode::limit_exceeded,
          "the rejection is a limit error");
    check(harness.state->reads.load() == 0U, "limits are enforced before any allocation or read");
}

void test_inspect_reference_index_mode_is_unsupported() {
    auto harness = make_harness(make_x64_state());
    argos::application::AddressInspectionRequest request = x64_request();
    request.references.mode = argos::application::ReferenceMode::index;
    auto result = harness.service->inspect_address(harness.session, request);
    check(!result.has_value(), "the index reference mode is not silently downgraded");
    check(!result && result.error().code == argos::domain::DebugErrorCode::unsupported,
          "an unimplemented reference source reports unsupported");
}

void test_inspect_live_scan_references_and_resume() {
    auto state = make_x64_state();
    // A single reference to the inspected address, late in the heap region.
    state->write_pointer(x64_heap_start + 0x1F00ULL, x64_field, 8U);
    auto harness = make_harness(std::move(state));

    argos::application::AddressInspectionRequest complete_request = x64_request();
    complete_request.references.mode = argos::application::ReferenceMode::live_scan;
    complete_request.references.byte_budget = 1024U * 1024U;
    complete_request.references.result_limit = 16U;
    auto complete = harness.service->inspect_address(harness.session, complete_request);
    check(complete.has_value(), "a live reference scan succeeds");
    if (!complete || !complete->references) {
        check(false, "a live reference scan produces a report");
        return;
    }
    check(complete->references->matches.size() == 1U, "the reference is found");
    check(complete->references->matches.front() == x64_heap_start + 0x1F00ULL,
          "the reference address is the storage location, not the target");
    check(complete->references->coverage.complete(), "a full sweep reports complete coverage");
    check(!complete->references->resume_token.has_value(), "a complete sweep offers no continuation");
    check(complete->references->truncation_reasons.empty(), "a complete sweep reports no truncation");

    // The same query under a budget that cannot reach the reference must not
    // look like "there is no reference".
    argos::application::AddressInspectionRequest partial_request = complete_request;
    partial_request.references.byte_budget = 4096U;
    auto partial = harness.service->inspect_address(harness.session, partial_request);
    check(partial.has_value(), "a budgeted slice succeeds");
    if (!partial || !partial->references) {
        check(false, "a budgeted slice produces a report");
        return;
    }
    check(partial->references->matches.empty(), "the budget runs out before the reference");
    check(!partial->references->coverage.complete(), "an exhausted budget is not complete coverage");
    check(partial->references->resume_token.has_value(), "an incomplete slice offers a continuation");
    check(
        std::ranges::find(
            partial->references->truncation_reasons,
            argos::application::ReferenceTruncation::byte_budget_exhausted
        ) != partial->references->truncation_reasons.end(),
        "the truncation reason names the budget"
    );

    // Resuming with the token eventually reaches the reference, and the token
    // from a different query is refused.
    argos::application::AddressInspectionRequest resumed_request = complete_request;
    resumed_request.references.resume_token = *partial->references->resume_token;
    auto resumed = harness.service->inspect_address(harness.session, resumed_request);
    check(resumed.has_value(), "resuming a slice succeeds");
    check(resumed && resumed->references && resumed->references->matches.size() == 1U,
          "the resumed slice finds the reference exactly once");

    argos::application::AddressInspectionRequest foreign = complete_request;
    foreign.address = x64_field + 8U;
    foreign.references.resume_token = *partial->references->resume_token;
    auto rejected = harness.service->inspect_address(harness.session, foreign);
    check(!rejected.has_value(), "a token minted for another target is rejected");
}

void test_inspect_reference_result_limit_paging() {
    auto state = make_x64_state();
    for (std::size_t index = 0; index < 4U; ++index) {
        state->write_pointer(x64_heap_start + 0x100ULL + index * 0x40ULL, x64_field, 8U);
    }
    auto harness = make_harness(std::move(state));

    argos::application::AddressInspectionRequest request = x64_request();
    request.references.mode = argos::application::ReferenceMode::live_scan;
    request.references.byte_budget = 1024U * 1024U;
    request.references.result_limit = 2U;
    auto first = harness.service->inspect_address(harness.session, request);
    check(first.has_value() && first->references, "a result-limited slice succeeds");
    if (!first || !first->references) return;
    check(first->references->matches.size() == 2U, "the result limit caps the page");
    check(!first->references->coverage.complete(), "a capped page is not complete");
    check(first->references->resume_token.has_value(), "a capped page offers a continuation");

    request.references.resume_token = *first->references->resume_token;
    auto second = harness.service->inspect_address(harness.session, request);
    check(second.has_value() && second->references, "the next page succeeds");
    if (!second || !second->references) return;
    check(second->references->matches.size() == 2U, "the next page returns the remaining references");
    check(
        std::ranges::find(second->references->matches, first->references->matches.back()) ==
            second->references->matches.end(),
        "pages do not repeat a reference"
    );
}

void test_inspect_cancellation_stops_before_next_probe() {
    auto state = make_x64_state();
    state->write_pointer(x64_object - 0x100ULL, x64_vtable + 0x100ULL, 8U);
    for (std::size_t entry = 0; entry < 8U; ++entry) {
        state->write_pointer(x64_vtable + 0x100ULL + entry * 8U, x64_text_start + entry * 0x10ULL, 8U);
    }
    auto harness = make_harness(std::move(state));
    // Cancel once the lookbehind read has happened, before the probes.
    harness.state->cancel_after_reads = 1U;

    auto result = harness.service->inspect_address(
        harness.session, x64_request(), harness.state->cancellation.get_token()
    );
    check(!result.has_value(), "a cancelled inspection does not publish a partial answer");
    check(!result && result.error().code == argos::domain::DebugErrorCode::cancelled,
          "cancellation is reported as cancelled");
    check(harness.state->reads.load() <= 2U, "cancellation stops before the remaining probes");
}

}  // namespace

int main() {
    test_region_index_half_open();
    test_module_index_and_rva();
    test_pointer_decode_and_arithmetic();
    test_lookbehind_window_clamps();
    test_inspection_limits_validation();
    test_resume_token_is_bound_to_its_query();

    test_inspect_x64_object_candidate();
    test_inspect_x86_matches_x64_meaning();
    test_inspect_rejects_wide_address_in_x86_mode();
    test_inspect_ranks_multiple_bases();
    test_inspect_ignores_non_executable_vtable_shape();
    test_inspect_reports_short_vtable_read();
    test_inspect_unmapped_and_unreadable_addresses();
    test_inspect_reads_maps_once_and_coalesces_probes();
    test_inspect_handles_unaligned_window_start();
    test_inspect_rejects_limits_before_io();
    test_inspect_reference_index_mode_is_unsupported();
    test_inspect_live_scan_references_and_resume();
    test_inspect_reference_result_limit_paging();
    test_inspect_cancellation_stops_before_next_probe();

    if (failures == 0) {
        std::cout << "All address inspection tests passed\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed\n";
    return 1;
}
