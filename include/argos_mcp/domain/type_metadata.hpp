#pragma once

#include "argos_mcp/domain/types.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace argos::domain {

struct TypeField {
    std::string name;
    std::string type_name;
    std::int64_t offset{};
    std::uint64_t size{};
};

struct TypeMetadata {
    std::string type_name;
    std::uint64_t size{};
    std::vector<TypeField> fields;
    std::string source;
    std::string confidence;
    bool truncated{false};
};

struct ReflectionSymbol {
    std::string name;
    std::string kind;
    std::uint64_t relative_address{};
};

struct ReflectionMetadata {
    std::string engine;
    std::string source;
    std::string confidence;
    std::vector<ReflectionSymbol> symbols;
    bool truncated{false};
};

struct TypeSummary {
    std::string name;
    std::string kind;
    std::uint64_t size{};
};

struct TypeCatalog {
    std::vector<TypeSummary> types;
    std::string source;
    std::string confidence;
    bool truncated{false};
};

class TypeMetadataProvider {
public:
    virtual ~TypeMetadataProvider() = default;

    [[nodiscard]] virtual Result<TypeMetadata> inspect_pdb(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const = 0;

    [[nodiscard]] virtual Result<TypeMetadata> inspect_unity(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const = 0;

    [[nodiscard]] virtual Result<TypeMetadata> inspect_unreal_type(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const = 0;

    [[nodiscard]] virtual Result<ReflectionMetadata> inspect_unreal_reflection(
        std::string_view module_path,
        std::size_t max_symbols
    ) const = 0;

    [[nodiscard]] virtual Result<TypeCatalog> list_pdb_types(
        std::string_view module_path,
        std::string_view name_filter,
        std::string_view kind_filter,
        std::size_t max_symbols
    ) const = 0;
};

}  // namespace argos::domain
