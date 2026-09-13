#pragma once

#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Read-only x86/x64 disassembly (ADR-0029). The domain owns the vocabulary --
// decoded instructions and their resolved references -- while the concrete
// decoder (Zydis) lives behind the Disassembler port in infrastructure. No type
// from the decoder crosses this boundary, and nothing here writes, hooks or
// executes: it decodes bytes the session can already read.
namespace argos::domain {

// What an instruction's resolved target represents. A single instruction can
// carry more than one (e.g. a call through a RIP-relative pointer), so these are
// collected per instruction rather than reduced to one.
enum class CodeReferenceKind : std::uint8_t {
    branch,        // conditional/unconditional jump, loop
    call,          // call
    memory_read,   // RIP-relative memory operand read
    memory_write,  // RIP-relative memory operand written
    memory,        // RIP-relative memory operand, read/write undetermined
};

[[nodiscard]] std::string_view to_string(CodeReferenceKind kind) noexcept;

// One resolved target of a decoded instruction: the absolute address the decoder
// computed for a relative branch or a RIP-relative operand. Immediate constants
// and register-indirect targets are not included -- only targets with a fixed
// absolute address are resolvable without running the code.
struct InstructionReference {
    Address target{};
    CodeReferenceKind kind{CodeReferenceKind::memory};
    bool rip_relative{false};
};

struct DecodedInstruction {
    Address address{};
    std::uint32_t length{};
    std::string mnemonic;
    // Intel-syntax text and raw encoding. Both are only populated when
    // formatting was requested; a bulk reference sweep skips them to avoid
    // copying and formatting every instruction it steps over.
    std::string text;
    std::vector<std::byte> bytes;
    std::vector<InstructionReference> references;
};

// A decoded instruction whose resolved target fell inside the requested window,
// produced by a linear sweep over executable bytes. It is evidence of a
// reference, not proof of a function boundary: a linear sweep can decode
// misaligned bytes in inter-function padding (ADR-0029).
struct CodeReferenceHit {
    Address address{};
    std::uint32_t length{};
    std::string mnemonic;
    std::string text;
    Address target{};
    CodeReferenceKind kind{CodeReferenceKind::memory};
};

// Decoder port. decode_one reports the single instruction at the start of
// `code`, interpreting it as if loaded at `runtime_address` so relative targets
// resolve to absolute addresses. Returns invalid_argument when the bytes do not
// form a valid instruction. `format` controls whether `text` is filled.
class Disassembler {
public:
    virtual ~Disassembler() = default;

    [[nodiscard]] virtual Result<DecodedInstruction> decode_one(
        std::span<const std::byte> code,
        Address runtime_address,
        TargetPointerWidth width,
        bool format
    ) const = 0;
};

// Domain ceilings, mirrored by the configurable policy which may only narrow
// them further.
inline constexpr std::size_t disassemble_max_instructions = 4096U;
inline constexpr std::uint64_t code_ref_max_byte_budget = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t code_ref_max_results = 4096U;

}  // namespace argos::domain
