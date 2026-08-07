#pragma once

#include <cstdint>
#include <expected>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace argos::protocol::json {

struct ParseError {
    std::size_t offset{};
    std::string message;
};

class Value final {
public:
    using Array = std::vector<Value>;
    using Object = std::map<std::string, Value, std::less<>>;

    Value() noexcept = default;
    Value(std::nullptr_t) noexcept : data_(nullptr) {}
    Value(bool value) noexcept : data_(value) {}
    Value(std::int64_t value) noexcept : data_(value) {}
    Value(std::int32_t value) noexcept : data_(static_cast<std::int64_t>(value)) {}
    Value(std::uint32_t value) noexcept : data_(static_cast<std::int64_t>(value)) {}
    Value(double value) noexcept : data_(value) {}
    Value(std::string value) : data_(std::move(value)) {}
    Value(std::string_view value) : data_(std::string{value}) {}
    Value(const char* value) : data_(std::string{value == nullptr ? "" : value}) {}
    Value(Array value) : data_(std::move(value)) {}
    Value(Object value) : data_(std::move(value)) {}

    [[nodiscard]] static Value object(
        std::initializer_list<std::pair<std::string, Value>> values = {}
    );
    [[nodiscard]] static Value array(std::initializer_list<Value> values = {});

    [[nodiscard]] bool is_null() const noexcept;
    [[nodiscard]] bool is_bool() const noexcept;
    [[nodiscard]] bool is_integer() const noexcept;
    [[nodiscard]] bool is_number() const noexcept;
    [[nodiscard]] bool is_string() const noexcept;
    [[nodiscard]] bool is_array() const noexcept;
    [[nodiscard]] bool is_object() const noexcept;

    [[nodiscard]] bool as_bool() const;
    [[nodiscard]] std::int64_t as_integer() const;
    [[nodiscard]] double as_number() const;
    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] const Array& as_array() const;
    [[nodiscard]] Array& as_array();
    [[nodiscard]] const Object& as_object() const;
    [[nodiscard]] Object& as_object();

    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] const Value* find(std::string_view key) const noexcept;
    [[nodiscard]] Value* find(std::string_view key) noexcept;

    Value& operator[](std::string key);
    [[nodiscard]] const Value& at(std::string_view key) const;

    [[nodiscard]] std::string dump() const;

private:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;
    Storage data_{nullptr};
};

[[nodiscard]] std::expected<Value, ParseError> parse(std::string_view input);

}  // namespace argos::protocol::json
