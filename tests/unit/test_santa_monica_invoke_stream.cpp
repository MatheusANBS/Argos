#include "argos_mcp/infrastructure/santa_monica_invoke_stream.hpp"

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
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
EngineArgument arg_b(const bool value) {
    return EngineArgument{EngineValueKind::boolean, 0, 0.0, value, {}};
}

void test_command_round_trip() {
    EngineInvokeRequest request;
    request.function_id = FunctionKey{0xABCDEF0123456789ULL};
    request.arguments = {arg_i(-5), arg_s("Muspelheim"), arg_f(1.5), arg_b(true)};
    request.idempotency_key = "op-1:abc";

    const auto encoded = infra::encode_invoke_command(request, 42, 1);
    check(encoded.has_value(), "command encodes");
    if (!encoded) return;

    const auto decoded = infra::decode_invoke_command(*encoded, 42, 1);
    check(decoded.has_value(), "command decodes");
    if (!decoded) return;
    check(decoded->function_id == request.function_id, "function id round-trips");
    check(decoded->idempotency_key == request.idempotency_key, "idempotency key round-trips");
    check(decoded->arguments.size() == 4, "argument count round-trips");
    check(decoded->arguments[0].kind == EngineValueKind::integer && decoded->arguments[0].integer == -5,
          "negative integer argument round-trips");
    check(decoded->arguments[1].kind == EngineValueKind::text && decoded->arguments[1].text == "Muspelheim",
          "text argument round-trips");
    check(decoded->arguments[2].kind == EngineValueKind::floating && decoded->arguments[2].floating == 1.5,
          "float argument round-trips");
    check(decoded->arguments[3].kind == EngineValueKind::boolean && decoded->arguments[3].boolean,
          "boolean argument round-trips");
}

void test_result_round_trip() {
    EngineInvokeResult result;
    result.state = EngineOperationState::completed;
    result.return_kind = EngineValueKind::text;
    result.text = "";  // empty return is legal, unlike a wire::string field.
    result.duration_us = 1234;

    const auto encoded = infra::encode_invoke_result(result, 7, 3);
    check(encoded.has_value(), "result encodes with an empty string return");
    if (!encoded) return;
    const auto decoded = infra::decode_invoke_result(*encoded, 7, 3);
    check(decoded.has_value() && decoded->text.empty() && decoded->duration_us == 1234,
          "empty-string result round-trips with its duration");
    check(decoded && decoded->state == EngineOperationState::completed, "state round-trips");

    EngineInvokeResult unknown;
    unknown.state = EngineOperationState::outcome_unknown;
    unknown.return_kind = EngineValueKind::integer;
    unknown.integer = 99;
    const auto enc2 = infra::encode_invoke_result(unknown, 7, 4);
    const auto dec2 = enc2 ? infra::decode_invoke_result(*enc2, 7, 4) : std::unexpected(enc2.error());
    check(dec2 && dec2->state == EngineOperationState::outcome_unknown && dec2->integer == 99,
          "outcome_unknown result round-trips");
}

void test_header_rejections() {
    EngineInvokeRequest request;
    request.function_id = FunctionKey{1};
    request.idempotency_key = "k";
    const auto frame = infra::encode_invoke_command(request, 10, 2);
    check(frame.has_value(), "baseline frame encodes");
    if (!frame) return;

    check(!infra::decode_invoke_command(*frame, 11, 2), "wrong request id rejected");
    check(!infra::decode_invoke_command(*frame, 10, 3), "wrong sequence rejected");
    check(!infra::decode_invoke_result(*frame, 10, 2), "command frame rejected as a result");

    // Corrupt the reserved field (offset 10-11 in the header) and expect rejection.
    auto corrupt = *frame;
    corrupt[10] = std::byte{0xFF};
    check(!infra::decode_invoke_command(corrupt, 10, 2), "non-zero reserved field rejected");

    // Truncated frame.
    std::vector<std::byte> truncated{frame->begin(), frame->begin() + 20};
    check(!infra::decode_invoke_command(truncated, 10, 2), "truncated frame rejected");

    // Zero request id / sequence refused at encode time.
    check(!infra::encode_invoke_command(request, 0, 1), "zero request id refused");
    check(!infra::encode_invoke_command(request, 1, 0), "zero sequence refused");
}

void test_argument_and_key_limits() {
    EngineInvokeRequest request;
    request.function_id = FunctionKey{1};
    request.idempotency_key = "k";
    request.arguments.assign(infra::max_invoke_arguments + 1, arg_i(0));
    check(!infra::encode_invoke_command(request, 1, 1), "too many arguments refused");

    EngineInvokeRequest bad_key;
    bad_key.function_id = FunctionKey{1};
    bad_key.idempotency_key = "has space";
    check(!infra::encode_invoke_command(bad_key, 1, 1), "malformed idempotency key refused at encode");
}

}  // namespace

int main() {
    test_command_round_trip();
    test_result_round_trip();
    test_header_rejections();
    test_argument_and_key_limits();
    if (failures != 0) std::cerr << failures << " Santa Monica invoke stream test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
