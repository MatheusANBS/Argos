#include "sparse_fake_session.hpp"

#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/disassembly.hpp"
#include "argos_mcp/infrastructure/zydis_disassembler.hpp"
#include "argos_mcp/security/policy.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

using argos::domain::Address;
using argos::domain::CodeReferenceKind;
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

void append_u32(std::vector<std::byte>& code, const std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        code.push_back(static_cast<std::byte>((value >> shift) & 0xFFU));
    }
}

// lea rax, [rip+disp] so that rip+disp resolves to `target`. Instruction is
// 7 bytes (48 8D 05 <disp32>) and rip points at the next instruction.
std::vector<std::byte> make_lea_rip(const Address at, const Address target) {
    std::vector<std::byte> code{std::byte{0x48}, std::byte{0x8D}, std::byte{0x05}};
    append_u32(code, static_cast<std::uint32_t>(target - (at + 7U)));
    return code;
}

// call rel32 (E8 <disp32>), 5 bytes, branching to `target`.
std::vector<std::byte> make_call_rel32(const Address at, const Address target) {
    std::vector<std::byte> code{std::byte{0xE8}};
    append_u32(code, static_cast<std::uint32_t>(target - (at + 5U)));
    return code;
}

// --- infrastructure: the real Zydis decoder --------------------------------

void test_decoder_resolves_rip_relative_and_branch() {
    const auto disassembler = argos::infrastructure::make_zydis_disassembler();

    constexpr Address lea_at = 0x140001000ULL;
    constexpr Address data_target = 0x140002000ULL;
    const auto lea = make_lea_rip(lea_at, data_target);
    auto decoded = disassembler->decode_one(lea, lea_at, TargetPointerWidth::x64, true);
    check(decoded.has_value(), "lea decodes");
    if (decoded) {
        check(decoded->length == 7U, "lea length is 7");
        check(decoded->mnemonic == "lea", "lea mnemonic");
        check(!decoded->text.empty(), "lea formatted text is present");
        check(decoded->references.size() == 1U, "lea has one resolved reference");
        if (!decoded->references.empty()) {
            check(decoded->references[0].target == data_target, "lea target resolves to data");
            check(decoded->references[0].rip_relative, "lea reference is rip-relative");
        }
    }

    constexpr Address call_at = 0x140001100ULL;
    constexpr Address call_target = 0x140005000ULL;
    const auto call = make_call_rel32(call_at, call_target);
    auto decoded_call = disassembler->decode_one(call, call_at, TargetPointerWidth::x64, false);
    check(decoded_call.has_value(), "call decodes");
    if (decoded_call) {
        check(decoded_call->length == 5U, "call length is 5");
        check(decoded_call->mnemonic == "call", "call mnemonic");
        check(decoded_call->text.empty(), "call text skipped when format is false");
        check(decoded_call->references.size() == 1U, "call has one reference");
        if (!decoded_call->references.empty()) {
            check(decoded_call->references[0].target == call_target, "call target resolves");
            check(decoded_call->references[0].kind == CodeReferenceKind::call, "call kind");
        }
    }

    auto garbage = disassembler->decode_one(
        std::span<const std::byte>{}, 0U, TargetPointerWidth::x64, false);
    check(!garbage.has_value(), "empty buffer fails to decode");
}

// --- application: service over the sparse session --------------------------

constexpr Address text_start = 0x140001000ULL;
constexpr Address data_target = 0x140002000ULL;
constexpr Address call_target = 0x140001500ULL;

struct Harness {
    std::shared_ptr<SparseState> state;
    std::unique_ptr<argos::application::MemoryDebugService> service;
    argos::domain::SessionId session{*argos::domain::SessionId::create("harness")};
};

Harness make_harness() {
    auto state = std::make_shared<SparseState>();
    state->regions.push_back({text_start, text_start + 0x1000ULL, true, false, true, false, ".text"});
    state->map_zeroed(text_start, 0x1000U);

    // lea rax,[rip->data_target] ; call call_target ; ret
    auto lea = make_lea_rip(text_start, data_target);
    state->write_bytes(text_start, std::span<const std::byte>{lea});
    const Address call_at = text_start + lea.size();
    auto call = make_call_rel32(call_at, call_target);
    state->write_bytes(call_at, std::span<const std::byte>{call});
    state->write_bytes(call_at + call.size(), std::span<const std::byte>{std::array{std::byte{0xC3}}});

    Harness harness{state, nullptr, *argos::domain::SessionId::create("harness")};
    harness.service = std::make_unique<argos::application::MemoryDebugService>(
        std::make_unique<SparseProvider>(state), argos::security::SecurityPolicy{});
    auto attached = harness.service->attach(4242U, argos::domain::AccessMode::read_only, true);
    if (!attached) {
        check(false, "harness attaches");
        return harness;
    }
    harness.session = attached->id;
    return harness;
}

void test_disassemble_sequence() {
    auto harness = make_harness();
    argos::application::DisassembleRequest request;
    request.address = text_start;
    request.pointer_width = TargetPointerWidth::x64;
    request.instruction_count = 3U;

    auto result = harness.service->disassemble(harness.session, request, {});
    check(result.has_value(), "disassemble succeeds");
    if (result) {
        check(result->instructions.size() == 3U, "three instructions decoded");
        if (result->instructions.size() == 3U) {
            check(result->instructions[0].mnemonic == "lea", "first is lea");
            check(result->instructions[1].mnemonic == "call", "second is call");
            check(result->instructions[2].mnemonic == "ret", "third is ret");
            check(!result->instructions[0].bytes.empty(), "bytes populated when formatting");
        }
    }
}

void test_disassemble_limit_rejected() {
    auto harness = make_harness();
    argos::application::DisassembleRequest request;
    request.address = text_start;
    request.instruction_count = argos::domain::disassemble_max_instructions + 1U;
    auto result = harness.service->disassemble(harness.session, request, {});
    check(!result.has_value(), "instruction count over the cap is rejected");
}

void test_find_code_references_finds_data_load() {
    auto harness = make_harness();
    argos::application::CodeReferenceRequest request;
    request.target = data_target;
    request.pointer_width = TargetPointerWidth::x64;
    request.byte_budget = 0x1000U;
    request.result_limit = 16U;

    auto result = harness.service->find_code_references(harness.session, request, {});
    check(result.has_value(), "find_code_references succeeds for data load");
    if (result) {
        check(result->hits.size() == 1U, "exactly one instruction references the data slot");
        if (!result->hits.empty()) {
            check(result->hits[0].address == text_start, "hit is the lea");
            check(result->hits[0].target == data_target, "hit target matches");
            check(!result->hits[0].text.empty(), "hit carries formatted text");
        }
    }
}

void test_find_code_references_finds_call() {
    auto harness = make_harness();
    argos::application::CodeReferenceRequest request;
    request.target = call_target;
    request.byte_budget = 0x1000U;
    request.result_limit = 16U;

    auto result = harness.service->find_code_references(harness.session, request, {});
    check(result.has_value(), "find_code_references succeeds for call");
    if (result) {
        check(result->hits.size() == 1U, "one call references the target");
        if (!result->hits.empty()) {
            check(result->hits[0].kind == CodeReferenceKind::call, "hit is a call");
        }
    }
}

void test_find_code_references_no_false_positive() {
    auto harness = make_harness();
    argos::application::CodeReferenceRequest request;
    request.target = 0x140009999ULL;  // referenced by nothing
    request.byte_budget = 0x1000U;
    request.result_limit = 16U;
    auto result = harness.service->find_code_references(harness.session, request, {});
    check(result.has_value(), "scan of an unreferenced target succeeds");
    if (result) {
        check(result->hits.empty(), "no hits for an unreferenced address");
        check(result->coverage.complete(), "small range is swept completely");
    }
}

}  // namespace

int main() {
    test_decoder_resolves_rip_relative_and_branch();
    test_disassemble_sequence();
    test_disassemble_limit_rejected();
    test_find_code_references_finds_data_load();
    test_find_code_references_finds_call();
    test_find_code_references_no_false_positive();

    if (failures == 0) {
        std::cout << "all disassembly tests passed\n";
    }
    return failures == 0 ? 0 : 1;
}
