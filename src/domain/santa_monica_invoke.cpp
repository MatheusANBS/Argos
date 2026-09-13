#include "argos_mcp/domain/santa_monica_invoke.hpp"

#include <optional>
#include <utility>

namespace argos::domain::santamonica {
namespace {

// Maps one SLI type code to its domain kind. Unknown codes make the enclosing
// signature unparseable, which is safer than inventing a marshaling for a code
// this version does not understand.
[[nodiscard]] std::optional<EngineValueKind> kind_from_code(const char code) noexcept {
    switch (code) {
        case 'i':
            return EngineValueKind::integer;
        case 'f':
            return EngineValueKind::floating;
        case 'b':
            return EngineValueKind::boolean;
        case 's':
            return EngineValueKind::text;
        default:
            return std::nullopt;
    }
}

// Parses one '|'-delimited token like "i_si" or "f_ff" or "b". Returns nullopt
// for a variadic token (ending in "...") or any unrecognized code, so the caller
// simply drops it from the invocable overload set.
[[nodiscard]] std::optional<SliOverload> parse_overload(const std::string_view token) {
    if (token.empty()) return std::nullopt;

    const auto return_kind = kind_from_code(token.front());
    if (!return_kind) return std::nullopt;

    SliOverload overload;
    overload.return_kind = *return_kind;

    if (token.size() == 1U) return overload;      // e.g. "i", "b", "s": no args.
    if (token[1] != '_') return std::nullopt;     // Anything else is malformed.

    const std::string_view args = token.substr(2U);
    for (const char code : args) {
        if (code == '.') return std::nullopt;      // Variadic tail: not invocable.
        const auto kind = kind_from_code(code);
        if (!kind) return std::nullopt;
        overload.argument_kinds.push_back(*kind);
    }
    return overload;
}

}  // namespace

bool is_terminal(const EngineOperationState state) noexcept {
    switch (state) {
        case EngineOperationState::completed:
        case EngineOperationState::cancelled:
        case EngineOperationState::failed:
        case EngineOperationState::outcome_unknown:
            return true;
        case EngineOperationState::queued:
        case EngineOperationState::running:
        case EngineOperationState::commit_in_progress:
            return false;
    }
    return false;
}

std::vector<SliOverload> parse_sli_signature(const std::string_view signature) {
    std::vector<SliOverload> overloads;
    std::size_t begin = 0U;
    while (begin <= signature.size()) {
        const std::size_t bar = signature.find('|', begin);
        const std::size_t end = bar == std::string_view::npos ? signature.size() : bar;
        if (auto overload = parse_overload(signature.substr(begin, end - begin))) {
            overloads.push_back(std::move(*overload));
        }
        if (bar == std::string_view::npos) break;
        begin = bar + 1U;
    }
    return overloads;
}

bool valid_idempotency_key(const std::string_view value) noexcept {
    if (value.empty() || value.size() > 128U) return false;
    for (const char ch : value) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' ||
                        ch == ':';
        if (!ok) return false;
    }
    return true;
}

Result<EngineInvokePlan> plan_engine_invoke(
    const SliFunctionRecord& function, const EngineInvokeRequest& request) {
    if (!(function.id == request.function_id)) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_argument, "function does not match request", "function_mismatch"});
    }
    if (!valid_idempotency_key(request.idempotency_key)) {
        return std::unexpected(DebugError{
            DebugErrorCode::invalid_argument, "idempotency key is malformed", "idempotency_key_invalid"});
    }

    const std::vector<SliOverload> overloads = parse_sli_signature(function.signature);
    if (overloads.empty()) {
        return std::unexpected(DebugError{
            DebugErrorCode::unsupported, "function has no invocable overload", "not_invocable"});
    }

    for (const SliOverload& overload : overloads) {
        if (overload.argument_kinds.size() != request.arguments.size()) continue;
        bool matches = true;
        for (std::size_t index = 0U; index < request.arguments.size(); ++index) {
            if (request.arguments[index].kind != overload.argument_kinds[index]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return EngineInvokePlan{request.function_id, overload.return_kind,
                                    request.arguments.size(), request.idempotency_key};
        }
    }

    return std::unexpected(DebugError{
        DebugErrorCode::invalid_argument, "arguments do not match any overload", "signature_mismatch"});
}

std::string_view to_string(const EngineOperationState state) noexcept {
    switch (state) {
        case EngineOperationState::queued:
            return "queued";
        case EngineOperationState::running:
            return "running";
        case EngineOperationState::commit_in_progress:
            return "commit_in_progress";
        case EngineOperationState::completed:
            return "completed";
        case EngineOperationState::cancelled:
            return "cancelled";
        case EngineOperationState::failed:
            return "failed";
        case EngineOperationState::outcome_unknown:
            return "outcome_unknown";
    }
    return "failed";
}

std::string_view to_string(const EngineValueKind kind) noexcept {
    switch (kind) {
        case EngineValueKind::integer:
            return "integer";
        case EngineValueKind::floating:
            return "floating";
        case EngineValueKind::boolean:
            return "boolean";
        case EngineValueKind::text:
            return "text";
    }
    return "integer";
}

}  // namespace argos::domain::santamonica
