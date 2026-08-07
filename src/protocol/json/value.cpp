#include "argos_mcp/protocol/json/value.hpp"

#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

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

    [[nodiscard]] std::expected<Value, ParseError> parse_value() {
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
            case '[': return parse_array();
            case '{': return parse_object();
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

    [[nodiscard]] std::expected<Value, ParseError> parse_array() {
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
            auto value = parse_value();
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

    [[nodiscard]] std::expected<Value, ParseError> parse_object() {
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
            auto value = parse_value();
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
};

void dump_string(std::ostringstream& output, std::string_view text) {
    output << '"';
    for (const char raw_ch : text) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        switch (ch) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (ch < 0x20U) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<unsigned int>(ch) << std::dec;
                } else {
                    output << static_cast<char>(ch);
                }
                break;
        }
    }
    output << '"';
}

void dump_value(std::ostringstream& output, const Value& value) {
    if (value.is_null()) {
        output << "null";
    } else if (value.is_bool()) {
        output << (value.as_bool() ? "true" : "false");
    } else if (value.is_integer()) {
        output << value.as_integer();
    } else if (value.is_number()) {
        output << std::setprecision(std::numeric_limits<double>::max_digits10) << value.as_number();
    } else if (value.is_string()) {
        dump_string(output, value.as_string());
    } else if (value.is_array()) {
        output << '[';
        bool first = true;
        for (const auto& item : value.as_array()) {
            if (!first) output << ',';
            first = false;
            dump_value(output, item);
        }
        output << ']';
    } else {
        output << '{';
        bool first = true;
        for (const auto& [key, item] : value.as_object()) {
            if (!first) output << ',';
            first = false;
            dump_string(output, key);
            output << ':';
            dump_value(output, item);
        }
        output << '}';
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
    std::ostringstream output;
    dump_value(output, *this);
    return output.str();
}

std::expected<Value, ParseError> parse(std::string_view input) {
    return Parser{input}.run();
}

}  // namespace argos::protocol::json
