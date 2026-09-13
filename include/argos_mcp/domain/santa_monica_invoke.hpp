#pragma once

#include "argos_mcp/domain/santa_monica_runtime.hpp"
#include "argos_mcp/domain/types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Milestone 1 of Spec 0014 stage 4: the domain vocabulary for invoking a single
// allowlisted engine (SLI) function through a main-thread dispatcher. This
// header is pure: it validates a request against a published signature and
// tracks the operation lifecycle, but it never reads memory, holds an address
// or executes anything. The bridge/dispatcher that actually runs the call lives
// in infrastructure and is gated separately (ADR-0022, Spec 0014 §"Execução no
// processo"). Nothing here promises that a function is invocable; that decision
// belongs to a validated build profile, and a request is only ever planned
// against a function the caller has already confirmed as allowlisted.
namespace argos::domain::santamonica {

// Lifecycle of one mutating engine operation (Spec 0014 §"Operações mutáveis e
// recuperação"). `running` permits preparation with no effects; the transition
// to `commit_in_progress` happens before the first possible effect, so a lost
// result after that point is `outcome_unknown`, never a presumed rollback.
enum class EngineOperationState {
    queued,
    running,
    commit_in_progress,
    completed,
    cancelled,
    failed,
    outcome_unknown,
};

// True once no further transition is possible. A terminal state is immutable;
// later reconciliation is separate evidence, not a state change.
[[nodiscard]] bool is_terminal(EngineOperationState state) noexcept;

// The closed argument/return vocabulary. It mirrors exactly the four type codes
// an SLI signature declares (`i`/`f`/`s`/`b`); a raw address, pointer, vararg or
// client-chosen handle never enters the domain (Spec 0014 §"Invocação SLI").
enum class EngineValueKind { integer, floating, boolean, text };

struct EngineArgument {
    EngineValueKind kind{EngineValueKind::integer};
    std::int64_t integer{};  // integer
    double floating{};       // floating
    bool boolean{};          // boolean
    std::string text;        // text
};

// One admitted invocation. `function_id` must be a FunctionKey the profile
// published as invocable; `arguments` are validated against its signature before
// the request is ever queued. `idempotency_key` deduplicates a retried request.
struct EngineInvokeRequest {
    FunctionKey function_id;
    std::vector<EngineArgument> arguments;
    std::string idempotency_key;
};

// The result of a completed invocation: exactly one return slot, whose kind is
// fixed by the signature. `duration_us` is wall time spent in the dispatcher.
struct EngineInvokeResult {
    EngineOperationState state{EngineOperationState::completed};
    EngineValueKind return_kind{EngineValueKind::integer};
    std::int64_t integer{};
    double floating{};
    bool boolean{};
    std::string text;
    std::uint64_t duration_us{};
};

// A validated, ready-to-queue plan. It names the resolved return kind so the
// serializer never has to re-parse the signature after admission.
struct EngineInvokePlan {
    FunctionKey function_id;
    EngineValueKind return_kind{EngineValueKind::integer};
    std::size_t argument_count{};
    std::string idempotency_key;
};

// A single non-vararg SLI overload: a return kind and its ordered argument
// kinds. A signature string may declare several, separated by '|'.
struct SliOverload {
    EngineValueKind return_kind{EngineValueKind::integer};
    std::vector<EngineValueKind> argument_kinds;
};

// Parses an SLI signature (e.g. "i_ii|i_si", "f_ff", "b", "s_i") into its
// invocable overloads. Vararg overloads (those ending in "...") are omitted:
// this version cannot marshal a variadic tail, so such a function is treated as
// having no invocable overload rather than guessing a fixed arity. An
// unrecognized type code makes the whole signature unparseable (empty result).
[[nodiscard]] std::vector<SliOverload> parse_sli_signature(std::string_view signature);

// Bounded opaque token: 1..128 bytes of letters, digits, '-', '_', '.', ':'.
// Deliberately a superset of valid_identity_token so a UUID-with-colons key is
// accepted, while control characters and separators that could confuse the
// operation registry are still rejected.
[[nodiscard]] bool valid_idempotency_key(std::string_view value) noexcept;

// Validates `request` against `function` (which the caller has already
// confirmed is allowlisted for invocation) and returns a plan, or a typed
// error: `invalid_argument`/"function_mismatch" when the id disagrees,
// `invalid_argument`/"idempotency_key_invalid", `unsupported`/"not_invocable"
// when no non-vararg overload exists, and `invalid_argument`/"signature_mismatch"
// when no overload matches the supplied arguments by count and kind.
[[nodiscard]] Result<EngineInvokePlan> plan_engine_invoke(
    const SliFunctionRecord& function, const EngineInvokeRequest& request);

[[nodiscard]] std::string_view to_string(EngineOperationState state) noexcept;
[[nodiscard]] std::string_view to_string(EngineValueKind kind) noexcept;

}  // namespace argos::domain::santamonica
