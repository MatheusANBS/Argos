#pragma once

#include "argos_mcp/domain/type_metadata.hpp"

#include <mutex>

namespace argos::infrastructure {

class PdbTypeMetadataProvider final : public domain::TypeMetadataProvider {
public:
    [[nodiscard]] domain::Result<domain::TypeMetadata> inspect_pdb(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const override;

    [[nodiscard]] domain::Result<domain::TypeMetadata> inspect_unity(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const override;

    [[nodiscard]] domain::Result<domain::TypeMetadata> inspect_unreal_type(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const override;

    [[nodiscard]] domain::Result<domain::ReflectionMetadata> inspect_unreal_reflection(
        std::string_view module_path,
        std::size_t max_symbols
    ) const override;

private:
    // DbgHelp keeps symbol state per process and is not reentrant across
    // concurrent callers. The MCP currently serializes tools, but the port
    // remains safe if that transport policy changes.
    mutable std::mutex mutex_;
};

}  // namespace argos::infrastructure
