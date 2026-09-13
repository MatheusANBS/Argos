#pragma once

#include "argos_mcp/domain/disassembly.hpp"

#include <memory>

// Factory for the Zydis-backed Disassembler (ADR-0029). The concrete class and
// every Zydis header stay in the .cpp so that no decoder type leaks into code
// that only needs the domain port.
namespace argos::infrastructure {

[[nodiscard]] std::unique_ptr<domain::Disassembler> make_zydis_disassembler();

}  // namespace argos::infrastructure
