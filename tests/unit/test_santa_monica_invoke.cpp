#include "argos_mcp/domain/santa_monica_invoke.hpp"

#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

SliFunctionRecord function(const std::uint64_t id, std::string signature) {
    return SliFunctionRecord{FunctionKey{id}, "Synthetic", std::move(signature)};
}

EngineArgument arg_i(const std::int64_t value) {
    return EngineArgument{EngineValueKind::integer, value, 0.0, false, {}};
}
EngineArgument arg_s(std::string value) {
    return EngineArgument{EngineValueKind::text, 0, 0.0, false, std::move(value)};
}
EngineArgument arg_f(const double value) {
    return EngineArgument{EngineValueKind::floating, 0, value, false, {}};
}

EngineInvokeRequest request(const std::uint64_t id, std::vector<EngineArgument> args) {
    return EngineInvokeRequest{FunctionKey{id}, std::move(args), "idem-key-1"};
}

// -- signature parsing -------------------------------------------------------

void test_signature_parsing() {
    const auto overloads = parse_sli_signature("i_ii|i_si");
    check(overloads.size() == 2, "two overloads parsed from a '|' signature");
    check(overloads.size() == 2 && overloads[0].argument_kinds.size() == 2 &&
              overloads[0].argument_kinds[0] == EngineValueKind::integer &&
              overloads[0].argument_kinds[1] == EngineValueKind::integer,
          "first overload is (int,int)");
    check(overloads.size() == 2 && overloads[1].argument_kinds[0] == EngineValueKind::text,
          "second overload takes a string first");

    const auto no_args = parse_sli_signature("b");
    check(no_args.size() == 1 && no_args[0].argument_kinds.empty() &&
              no_args[0].return_kind == EngineValueKind::boolean,
          "'b' parses as a no-arg boolean function");

    const auto floats = parse_sli_signature("f_ff");
    check(floats.size() == 1 && floats[0].return_kind == EngineValueKind::floating &&
              floats[0].argument_kinds.size() == 2,
          "'f_ff' parses as float(float,float)");

    // Variadic overloads are dropped; a signature that is only variadic yields none.
    check(parse_sli_signature("i_i...|i_s...").empty(),
          "purely variadic signature has no invocable overload");
    // A mixed signature keeps only the fixed overload.
    const auto mixed = parse_sli_signature("i_ii|i_s...");
    check(mixed.size() == 1 && mixed[0].argument_kinds.size() == 2,
          "variadic overload dropped, fixed overload kept");

    check(parse_sli_signature("x_zz").empty(), "unknown type codes make a signature unparseable");
}

// -- idempotency key ---------------------------------------------------------

void test_idempotency_key() {
    check(valid_idempotency_key("abc-123_.:X"), "typical opaque key accepted");
    check(!valid_idempotency_key(""), "empty key rejected");
    check(!valid_idempotency_key(std::string(129, 'a')), "over-long key rejected");
    check(!valid_idempotency_key("has space"), "key with space rejected");
    check(!valid_idempotency_key("bad/slash"), "key with separator rejected");
}

// -- planning ----------------------------------------------------------------

void test_plan_success() {
    const auto plan = plan_engine_invoke(function(7, "i_si"), request(7, {arg_s("hello"), arg_i(3)}));
    check(plan.has_value(), "matching (string,int) request is planned");
    check(plan && plan->return_kind == EngineValueKind::integer, "plan reports the int return kind");
    check(plan && plan->argument_count == 2, "plan records the argument count");
}

void test_plan_overload_selection() {
    // Same function, two overloads; the float pair must select the float overload.
    const auto plan = plan_engine_invoke(function(9, "i_ii|f_ff"), request(9, {arg_f(1.0), arg_f(2.0)}));
    check(plan && plan->return_kind == EngineValueKind::floating,
          "float arguments select the float-returning overload");
}

void test_plan_rejections() {
    const auto mismatch_id = plan_engine_invoke(function(1, "i_i"), request(2, {arg_i(0)}));
    check(!mismatch_id && mismatch_id.error().reason == "function_mismatch",
          "request against a different function id is rejected");

    const auto bad_key = plan_engine_invoke(
        function(1, "i_i"), EngineInvokeRequest{FunctionKey{1}, {arg_i(0)}, "bad key"});
    check(!bad_key && bad_key.error().reason == "idempotency_key_invalid",
          "malformed idempotency key is rejected");

    const auto variadic = plan_engine_invoke(function(1, "i_i..."), request(1, {arg_i(0)}));
    check(!variadic && variadic.error().reason == "not_invocable",
          "a purely variadic function is not invocable");

    const auto wrong_arity = plan_engine_invoke(function(1, "i_ii"), request(1, {arg_i(0)}));
    check(!wrong_arity && wrong_arity.error().reason == "signature_mismatch",
          "wrong argument count is a signature mismatch");

    const auto wrong_kind = plan_engine_invoke(function(1, "i_ii"), request(1, {arg_i(0), arg_s("x")}));
    check(!wrong_kind && wrong_kind.error().reason == "signature_mismatch",
          "wrong argument kind is a signature mismatch");
}

void test_state_helpers() {
    check(is_terminal(EngineOperationState::completed), "completed is terminal");
    check(is_terminal(EngineOperationState::outcome_unknown), "outcome_unknown is terminal");
    check(!is_terminal(EngineOperationState::running), "running is not terminal");
    check(!is_terminal(EngineOperationState::commit_in_progress), "commit_in_progress is not terminal");
    check(to_string(EngineOperationState::outcome_unknown) == std::string_view{"outcome_unknown"},
          "state name round-trips");
    check(to_string(EngineValueKind::text) == std::string_view{"text"}, "value kind name round-trips");
}

}  // namespace

int main() {
    test_signature_parsing();
    test_idempotency_key();
    test_plan_success();
    test_plan_overload_selection();
    test_plan_rejections();
    test_state_helpers();
    if (failures != 0) std::cerr << failures << " Santa Monica invoke test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
