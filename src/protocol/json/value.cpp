#include "argos_mcp/protocol/json/value.hpp"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace argos::protocol::json {
namespace {

class Parser final {
public:
    explicit Parser(std::string_view input) : input_(input) {}

    [[nodiscard]] std::expected<Value, ParseError> run() {
        skip_whitespace();
        auto value = parse_value();
        if (!value) {
            return value;
        }
        skip_whitespace();
        if (position_ != input_.size()) {
            return fail("trailing characters");
        }
        return value;
    }

private:
    [[nodiscard]] std::expected<Value, ParseError> fail(std::string message) const {
        return std::unexpected(ParseError{position_, std::move(message)});
    }

    void skip_whitespace() noexcept {
        while (position_ < input_.size()) {
            const char ch = input_[position_];
            if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
                break;
            }
            ++position_;
        }
    }

    [[nodiscard]] std::expected<Value, ParseError> parse_value(const std::size_t nesting_depth = 0U) {
        if (node_count_ >= max_parse_nodes) {
            return fail("maximum JSON node count exceeded");
        }
        ++node_count_;
        if (position_ >= input_.size()) {
            return fail("unexpected end of input");
        }
        switch (input_[position_]) {
            case 'n': return parse_literal("null", Value{nullptr});
            case 't': return parse_literal("true", Value{true});
            case 'f': return parse_literal("false", Value{false});
            case '"': {
                auto text = parse_string();
                if (!text) {
                    return std::unexpected(text.error());
                }
                return Value{std::move(*text)};
            }
            case '[':
                if (nesting_depth >= max_parse_nesting_depth) {
                    return fail("maximum nesting depth exceeded");
                }
                return parse_array(nesting_depth + 1U);
            case '{':
                if (nesting_depth >= max_parse_nesting_depth) {
                    return fail("maximum nesting depth exceeded");
                }
                return parse_object(nesting_depth + 1U);
            default:
                if (input_[position_] == '-' ||
                    (input_[position_] >= '0' && input_[position_] <= '9')) {
                    return parse_number();
                }
                return fail("unexpected token");
        }
    }

    [[nodiscard]] std::expected<Value, ParseError> parse_literal(
        std::string_view literal,
        Value value
    ) {
        if (input_.substr(position_, literal.size()) != literal) {
            return fail("invalid literal");
        }
        position_ += literal.size();
        return value;
    }

    [[nodiscard]] static int hex_digit(char ch) noexcept {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return -1;
    }

    [[nodiscard]] std::expected<std::uint32_t, ParseError> parse_hex4() {
        if (position_ + 4U > input_.size()) {
            return std::unexpected(ParseError{position_, "incomplete unicode escape"});
        }
        std::uint32_t value = 0;
        for (std::size_t index = 0; index < 4U; ++index) {
            const int digit = hex_digit(input_[position_ + index]);
            if (digit < 0) {
                return std::unexpected(ParseError{position_ + index, "invalid unicode escape"});
            }
            value = (value << 4U) | static_cast<std::uint32_t>(digit);
        }
        position_ += 4U;
        return value;
    }

    static void append_utf8(std::string& output, std::uint32_t codepoint) {
        if (codepoint <= 0x7FU) {
            output.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7FFU) {
            output.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else if (codepoint <= 0xFFFFU) {
            output.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else {
            output.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            output.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        }
    }

    [[nodiscard]] std::expected<std::string, ParseError> parse_string() {
        if (input_[position_] != '"') {
            return std::unexpected(ParseError{position_, "expected string"});
        }
        ++position_;
        std::string output;
        while (position_ < input_.size()) {
            const unsigned char ch = static_cast<unsigned char>(input_[position_++]);
            if (ch == '"') {
                return output;
            }
            if (ch < 0x20U) {
                return std::unexpected(ParseError{position_ - 1U, "control character in string"});
            }
            if (ch != '\\') {
                output.push_back(static_cast<char>(ch));
                continue;
            }
            if (position_ >= input_.size()) {
                return std::unexpected(ParseError{position_, "incomplete escape"});
            }
            const char escaped = input_[position_++];
            switch (escaped) {
                case '"': output.push_back('"'); break;
                case '\\': output.push_back('\\'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u': {
                    auto first = parse_hex4();
                    if (!first) {
                        return std::unexpected(first.error());
                    }
                    std::uint32_t codepoint = *first;
                    if (codepoint >= 0xD800U && codepoint <= 0xDBFFU) {
                        if (position_ + 2U > input_.size() || input_[position_] != '\\' ||
                            input_[position_ + 1U] != 'u') {
                            return std::unexpected(ParseError{position_, "missing low surrogate"});
                        }
                        position_ += 2U;
                        auto second = parse_hex4();
                        if (!second || *second < 0xDC00U || *second > 0xDFFFU) {
                            return std::unexpected(second ? ParseError{position_, "invalid low surrogate"} : second.error());
                        }
                        codepoint = 0x10000U + ((codepoint - 0xD800U) << 10U) + (*second - 0xDC00U);
                    } else if (codepoint >= 0xDC00U && codepoint <= 0xDFFFU) {
                        return std::unexpected(ParseError{position_, "unexpected low surrogate"});
                    }
                    append_utf8(output, codepoint);
                    break;
                }
                default:
                    return std::unexpected(ParseError{position_ - 1U, "invalid escape"});
            }
        }
        return std::unexpected(ParseError{position_, "unterminated string"});
    }

    [[nodiscard]] std::expected<Value, ParseError> parse_number() {
        const std::size_t start = position_;
        if (input_[position_] == '-') {
            ++position_;
        }
        if (position_ >= input_.size()) {
            return fail("incomplete number");
        }
        if (input_[position_] == '0') {
            ++position_;
        } else if (input_[position_] >= '1' && input_[position_] <= '9') {
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
        } else {
            return fail("invalid number");
        }

        bool floating = false;
        if (position_ < input_.size() && input_[position_] == '.') {
            floating = true;
            ++position_;
            const std::size_t digits_start = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
            if (digits_start == position_) {
                return fail("fraction requires digits");
            }
        }
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            floating = true;
            ++position_;
            if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            const std::size_t digits_start = position_;
            while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') {
                ++position_;
            }
            if (digits_start == position_) {
                return fail("exponent requires digits");
            }
        }

        const std::string_view token = input_.substr(start, position_ - start);
        if (!floating) {
            std::int64_t integer = 0;
            const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), integer);
            if (ec == std::errc{} && ptr == token.data() + token.size()) {
                return Value{integer};
            }
        }
        double number = 0.0;
        const auto [ptr, ec] = std::from_chars(token.data(), token.data() + token.size(), number);
        if (ec != std::errc{} || ptr != token.data() + token.size() || !std::isfinite(number)) {
            return fail("invalid or non-finite number");
        }
        return Value{number};
    }

    [[nodiscard]] std::expected<Value, ParseError> parse_array(const std::size_t nesting_depth) {
        ++position_;
        skip_whitespace();
        Value::Array output;
        if (position_ < input_.size() && input_[position_] == ']') {
            ++position_;
            Value result{std::move(output)};
            return result;
        }
        while (true) {
            skip_whitespace();
            auto value = parse_value(nesting_depth);
            if (!value) {
                return value;
            }
            output.push_back(std::move(*value));
            skip_whitespace();
            if (position_ >= input_.size()) {
                return fail("unterminated array");
            }
            if (input_[position_] == ']') {
                ++position_;
                Value result{std::move(output)};
                return result;
            }
            if (input_[position_] != ',') {
                return fail("expected comma in array");
            }
            ++position_;
        }
    }

    [[nodiscard]] std::expected<Value, ParseError> parse_object(const std::size_t nesting_depth) {
        ++position_;
        skip_whitespace();
        Value::Object output;
        if (position_ < input_.size() && input_[position_] == '}') {
            ++position_;
            Value result{std::move(output)};
            return result;
        }
        while (true) {
            skip_whitespace();
            if (position_ >= input_.size() || input_[position_] != '"') {
                return fail("expected object key");
            }
            auto key = parse_string();
            if (!key) {
                return std::unexpected(key.error());
            }
            skip_whitespace();
            if (position_ >= input_.size() || input_[position_] != ':') {
                return fail("expected colon after object key");
            }
            ++position_;
            skip_whitespace();
            auto value = parse_value(nesting_depth);
            if (!value) {
                return value;
            }
            const auto [iterator, inserted] = output.emplace(std::move(*key), std::move(*value));
            if (!inserted) {
                return fail("duplicate object key");
            }
            (void)iterator;
            skip_whitespace();
            if (position_ >= input_.size()) {
                return fail("unterminated object");
            }
            if (input_[position_] == '}') {
                ++position_;
                Value result{std::move(output)};
                return result;
            }
            if (input_[position_] != ',') {
                return fail("expected comma in object");
            }
            ++position_;
        }
    }

    std::string_view input_;
    std::size_t position_{0};
    std::size_t node_count_{0};
};

void dump_string(std::string& output, const std::string_view text) {
    constexpr char hex_digits[] = "0123456789abcdef";
    output.push_back('"');
    for (const char raw_ch : text) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        switch (ch) {
            case '"': output.append("\\\""); break;
            case '\\': output.append("\\\\"); break;
            case '\b': output.append("\\b"); break;
            case '\f': output.append("\\f"); break;
            case '\n': output.append("\\n"); break;
            case '\r': output.append("\\r"); break;
            case '\t': output.append("\\t"); break;
            default:
                if (ch < 0x20U) {
                    output.append("\\u00");
                    output.push_back(hex_digits[ch >> 4U]);
                    output.push_back(hex_digits[ch & 0x0FU]);
                } else {
                    output.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    output.push_back('"');
}

void dump_number(std::string& output, const double number) {
    if (!std::isfinite(number)) {
        output.append("null");
        return;
    }

    char buffer[64]{};
    const auto [end, error] = std::to_chars(
        buffer,
        buffer + sizeof(buffer),
        number,
        std::chars_format::general,
        std::numeric_limits<double>::max_digits10
    );
    if (error != std::errc{}) {
        output.append("null");
        return;
    }
    output.append(buffer, static_cast<std::size_t>(end - buffer));
}

void dump_integer(std::string& output, const std::int64_t number) {
    char buffer[32]{};
    const auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), number);
    if (error != std::errc{}) {
        output.append("null");
        return;
    }
    output.append(buffer, static_cast<std::size_t>(end - buffer));
}

struct ArrayDumpFrame final {
    const Value::Array* values{};
    std::size_t next_index{};
};

struct ObjectDumpFrame final {
    const Value::Object* values{};
    Value::Object::const_iterator next;
};

using DumpFrame = std::variant<ArrayDumpFrame, ObjectDumpFrame>;

void dump_value(std::string& output, const Value& root) {
    std::vector<DumpFrame> stack;
    const Value* value = &root;

    while (value != nullptr) {
        if (value->is_null()) {
            output.append("null");
        } else if (value->is_bool()) {
            output.append(value->as_bool() ? "true" : "false");
        } else if (value->is_integer()) {
            dump_integer(output, value->as_integer());
        } else if (value->is_number()) {
            dump_number(output, value->as_number());
        } else if (value->is_string()) {
            dump_string(output, value->as_string());
        } else if (value->is_array()) {
            output.push_back('[');
            const auto& array = value->as_array();
            if (array.empty()) {
                output.push_back(']');
            } else {
                stack.emplace_back(ArrayDumpFrame{&array, 1U});
                value = &array.front();
                continue;
            }
        } else {
            output.push_back('{');
            const auto& object = value->as_object();
            if (object.empty()) {
                output.push_back('}');
            } else {
                auto current = object.begin();
                dump_string(output, current->first);
                output.push_back(':');
                value = &current->second;
                stack.emplace_back(ObjectDumpFrame{&object, ++current});
                continue;
            }
        }

        value = nullptr;
        while (!stack.empty()) {
            if (auto* array_frame = std::get_if<ArrayDumpFrame>(&stack.back())) {
                if (array_frame->next_index < array_frame->values->size()) {
                    output.push_back(',');
                    value = &(*array_frame->values)[array_frame->next_index++];
                    break;
                }
                output.push_back(']');
                stack.pop_back();
                continue;
            }

            auto& object_frame = std::get<ObjectDumpFrame>(stack.back());
            if (object_frame.next != object_frame.values->end()) {
                output.push_back(',');
                dump_string(output, object_frame.next->first);
                output.push_back(':');
                value = &object_frame.next->second;
                ++object_frame.next;
                break;
            }
            output.push_back('}');
            stack.pop_back();
        }
    }
}

}  // namespace

Value Value::object(std::initializer_list<std::pair<std::string, Value>> values) {
    Object object_value;
    for (const auto& [key, value] : values) {
        object_value.emplace(key, value);
    }
    return Value{std::move(object_value)};
}

Value Value::array(std::initializer_list<Value> values) {
    return Value{Array{values}};
}

bool Value::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(data_); }
bool Value::is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
bool Value::is_integer() const noexcept { return std::holds_alternative<std::int64_t>(data_); }
bool Value::is_number() const noexcept { return is_integer() || std::holds_alternative<double>(data_); }
bool Value::is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
bool Value::is_array() const noexcept { return std::holds_alternative<Array>(data_); }
bool Value::is_object() const noexcept { return std::holds_alternative<Object>(data_); }

bool Value::as_bool() const { return std::get<bool>(data_); }
std::int64_t Value::as_integer() const { return std::get<std::int64_t>(data_); }
double Value::as_number() const {
    return is_integer() ? static_cast<double>(as_integer()) : std::get<double>(data_);
}
const std::string& Value::as_string() const { return std::get<std::string>(data_); }
const Value::Array& Value::as_array() const { return std::get<Array>(data_); }
Value::Array& Value::as_array() { return std::get<Array>(data_); }
const Value::Object& Value::as_object() const { return std::get<Object>(data_); }
Value::Object& Value::as_object() { return std::get<Object>(data_); }

bool Value::contains(std::string_view key) const {
    return find(key) != nullptr;
}

const Value* Value::find(std::string_view key) const noexcept {
    if (!is_object()) {
        return nullptr;
    }
    const auto iterator = as_object().find(key);
    return iterator == as_object().end() ? nullptr : &iterator->second;
}

Value* Value::find(std::string_view key) noexcept {
    if (!is_object()) {
        return nullptr;
    }
    const auto iterator = as_object().find(key);
    return iterator == as_object().end() ? nullptr : &iterator->second;
}

Value& Value::operator[](std::string key) {
    if (!is_object()) {
        data_ = Object{};
    }
    return as_object()[std::move(key)];
}

const Value& Value::at(std::string_view key) const {
    const Value* value = find(key);
    if (value == nullptr) {
        throw std::out_of_range("JSON object key not found");
    }
    return *value;
}

std::string Value::dump() const {
    std::string output;
    output.reserve(256U);
    dump_value(output, *this);
    return output;
}

std::expected<Value, ParseError> parse(std::string_view input) {
    if (input.size() > max_parse_input_bytes) {
        return std::unexpected(ParseError{
            max_parse_input_bytes,
            "maximum input size exceeded"
        });
    }
    return Parser{input}.run();
}

}  // namespace argos::protocol::json
