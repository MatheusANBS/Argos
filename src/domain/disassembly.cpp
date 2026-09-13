#include "argos_mcp/domain/disassembly.hpp"

namespace argos::domain {

std::string_view to_string(const CodeReferenceKind kind) noexcept {
    switch (kind) {
        case CodeReferenceKind::branch: return "branch";
        case CodeReferenceKind::call: return "call";
        case CodeReferenceKind::memory_read: return "memory_read";
        case CodeReferenceKind::memory_write: return "memory_write";
        case CodeReferenceKind::memory: return "memory";
    }
    return "memory";
}

}  // namespace argos::domain
