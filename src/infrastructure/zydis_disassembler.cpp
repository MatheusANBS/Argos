#include "argos_mcp/infrastructure/zydis_disassembler.hpp"

#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/types.hpp"

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace argos::infrastructure {
namespace {

[[nodiscard]] domain::DebugError decode_failed() {
    return domain::DebugError{
        domain::DebugErrorCode::invalid_argument, "bytes do not form a valid instruction"
    };
}

// Classifies one resolvable operand into a domain reference. Only operands with
// a fixed absolute target survive: relative branches/calls and RIP-relative
// memory operands. Register-indirect targets and plain immediates are skipped by
// the caller, since they cannot be resolved without running the code.
[[nodiscard]] domain::CodeReferenceKind classify(
    const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand& operand
) {
    if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        return instruction.mnemonic == ZYDIS_MNEMONIC_CALL
            ? domain::CodeReferenceKind::call
            : domain::CodeReferenceKind::branch;
    }
    // Memory operand: derive read/write from the operand actions rather than
    // guessing from the mnemonic.
    const bool writes = (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
    const bool reads = (operand.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
    if (writes && !reads) return domain::CodeReferenceKind::memory_write;
    if (reads && !writes) return domain::CodeReferenceKind::memory_read;
    return domain::CodeReferenceKind::memory;
}

class ZydisDisassembler final : public domain::Disassembler {
public:
    ZydisDisassembler() {
        ZydisDecoderInit(&decoder_x64_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisDecoderInit(&decoder_x86_, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
    }

    [[nodiscard]] domain::Result<domain::DecodedInstruction> decode_one(
        const std::span<const std::byte> code,
        const domain::Address runtime_address,
        const domain::TargetPointerWidth width,
        const bool format
    ) const override {
        if (code.empty()) {
            return std::unexpected(decode_failed());
        }
        const ZydisDecoder& decoder =
            width == domain::TargetPointerWidth::x64 ? decoder_x64_ : decoder_x86_;

        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        const ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder, code.data(), code.size(), &instruction, operands
        );
        if (!ZYAN_SUCCESS(status)) {
            return std::unexpected(decode_failed());
        }

        domain::DecodedInstruction decoded;
        decoded.address = runtime_address;
        decoded.length = instruction.length;
        decoded.mnemonic = ZydisMnemonicGetString(instruction.mnemonic);

        for (std::uint8_t index = 0; index < instruction.operand_count_visible; ++index) {
            const ZydisDecodedOperand& operand = operands[index];
            if (operand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                operand.type != ZYDIS_OPERAND_TYPE_MEMORY) {
                continue;
            }
            ZyanU64 absolute = 0;
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                    &instruction, &operand, runtime_address, &absolute))) {
                continue;
            }
            const bool rip_relative = operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (operand.mem.base == ZYDIS_REGISTER_RIP || operand.mem.base == ZYDIS_REGISTER_EIP);
            // A plain immediate that is not relative has no fixed code target.
            if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative == ZYAN_FALSE) {
                continue;
            }
            decoded.references.push_back(domain::InstructionReference{
                static_cast<domain::Address>(absolute), classify(instruction, operand), rip_relative
            });
        }

        if (format) {
            decoded.bytes.assign(code.begin(), code.begin() + instruction.length);
            char buffer[256];
            if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
                    &formatter_, &instruction, operands, instruction.operand_count_visible,
                    buffer, sizeof(buffer), runtime_address, ZYAN_NULL))) {
                decoded.text = buffer;
            }
        }
        return decoded;
    }

private:
    ZydisDecoder decoder_x64_{};
    ZydisDecoder decoder_x86_{};
    ZydisFormatter formatter_{};
};

}  // namespace

std::unique_ptr<domain::Disassembler> make_zydis_disassembler() {
    return std::make_unique<ZydisDisassembler>();
}

}  // namespace argos::infrastructure
