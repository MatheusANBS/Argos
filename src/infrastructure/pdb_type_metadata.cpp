#include "argos_mcp/infrastructure/pdb_type_metadata.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifndef _NO_CVCONST_H
#define _NO_CVCONST_H
#endif
#include <dbghelp.h>
#endif

namespace argos::infrastructure {
namespace {

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

struct Il2CppMetadataHeader final {
    std::int32_t version{};
    std::int32_t string_offset{};
    std::int32_t string_count{};
    std::int32_t fields_offset{};
    std::int32_t fields_count{};
    std::int32_t type_definitions_offset{};
    std::int32_t type_definitions_count{};
};

struct Il2CppTypeDefinitionView final {
    std::int32_t name_index{};
    std::int32_t namespace_index{};
    std::int32_t field_start{};
    std::uint16_t field_count{};
};

struct Il2CppFieldDefinitionView final {
    std::int32_t name_index{};
    std::int32_t type_index{};
};

struct Il2CppMetadataLayout final {
    std::size_t type_definition_size{};
    std::size_t field_definition_size{};
    std::size_t field_start_offset{};
    std::size_t field_count_offset{};
};

[[nodiscard]] bool read_u32(
    const std::vector<std::byte>& bytes,
    const std::size_t offset,
    std::uint32_t& output
) noexcept {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(std::uint32_t)) return false;
    output = 0U;
    for (std::size_t index = 0U; index < sizeof(std::uint32_t); ++index) {
        output |= static_cast<std::uint32_t>(std::to_integer<unsigned int>(bytes[offset + index])) << (index * 8U);
    }
    return true;
}

[[nodiscard]] bool read_i32(
    const std::vector<std::byte>& bytes,
    const std::size_t offset,
    std::int32_t& output
) noexcept {
    std::uint32_t value = 0U;
    if (!read_u32(bytes, offset, value)) return false;
    output = static_cast<std::int32_t>(value);
    return true;
}

[[nodiscard]] bool read_u16(
    const std::vector<std::byte>& bytes,
    const std::size_t offset,
    std::uint16_t& output
) noexcept {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(std::uint16_t)) return false;
    output = static_cast<std::uint16_t>(std::to_integer<unsigned int>(bytes[offset])) |
        static_cast<std::uint16_t>(std::to_integer<unsigned int>(bytes[offset + 1U]) << 8U);
    return true;
}

[[nodiscard]] bool valid_table(
    const std::vector<std::byte>& bytes,
    const std::int32_t offset,
    const std::int32_t count,
    const std::size_t element_size
) noexcept {
    if (offset < 0 || count < 0 || element_size == 0U) return false;
    const auto start = static_cast<std::size_t>(offset);
    const auto length = static_cast<std::size_t>(count);
    return start <= bytes.size() && length <= bytes.size() - start && length % element_size == 0U;
}

[[nodiscard]] bool parse_il2cpp_header(
    const std::vector<std::byte>& bytes,
    Il2CppMetadataHeader& header
) noexcept {
    std::uint32_t sanity = 0U;
    std::int32_t version = 0;
    if (!read_u32(bytes, 0U, sanity) || sanity != 0xFAB11BAFU || !read_i32(bytes, 4U, version)) {
        return false;
    }
    if (version < 24 || version > 31) return false;
    header.version = version;
    return read_i32(bytes, 24U, header.string_offset) &&
        read_i32(bytes, 28U, header.string_count) &&
        read_i32(bytes, 96U, header.fields_offset) &&
        read_i32(bytes, 100U, header.fields_count) &&
        read_i32(bytes, 160U, header.type_definitions_offset) &&
        read_i32(bytes, 164U, header.type_definitions_count);
}

[[nodiscard]] std::string metadata_string(
    const std::vector<std::byte>& bytes,
    const Il2CppMetadataHeader& header,
    const std::int32_t index
) {
    if (index < 0 || header.string_offset < 0 || header.string_count < 0 || index >= header.string_count) return {};
    const auto start = static_cast<std::size_t>(header.string_offset) + static_cast<std::size_t>(index);
    const auto end = static_cast<std::size_t>(header.string_offset) + static_cast<std::size_t>(header.string_count);
    if (start >= end || end > bytes.size()) return {};
    std::string output;
    output.reserve(std::min<std::size_t>(256U, end - start));
    for (std::size_t cursor = start; cursor < end && output.size() < 4096U; ++cursor) {
        const auto character = static_cast<char>(std::to_integer<unsigned int>(bytes[cursor]));
        if (character == '\0') break;
        output.push_back(character);
    }
    return output;
}

[[nodiscard]] std::optional<std::filesystem::path> find_unity_metadata(
    const std::string_view module_path
) {
    const std::filesystem::path module{std::string{module_path}};
    const auto parent = module.parent_path();
    std::vector<std::filesystem::path> candidates{
        parent / "global-metadata.dat",
        parent / "metadata" / "global-metadata.dat",
        parent / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    };
    std::error_code iterator_error;
    for (const auto& entry : std::filesystem::directory_iterator(parent, iterator_error)) {
        if (iterator_error || !entry.is_directory(iterator_error)) continue;
        const auto name = entry.path().filename().string();
        if (name.size() > 5U && name.ends_with("_Data")) {
            candidates.push_back(entry.path() / "il2cpp_data" / "Metadata" / "global-metadata.dat");
        }
    }
    std::optional<std::filesystem::path> found;
    for (const auto& candidate : candidates) {
        std::error_code file_error;
        if (!std::filesystem::is_regular_file(candidate, file_error)) continue;
        if (found && *found != candidate) {
            return std::nullopt;
        }
        found = candidate;
    }
    return found;
}

[[nodiscard]] domain::Result<std::vector<std::byte>> load_metadata_file(
    const std::filesystem::path& path
) {
    std::error_code file_error;
    const auto file_size = std::filesystem::file_size(path, file_error);
    constexpr std::uintmax_t max_metadata_size = 512U * 1024U * 1024U;
    if (file_error || file_size == 0U || file_size > max_metadata_size) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "Unity metadata file is unavailable or too large"));
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(error(domain::DebugErrorCode::io_error, "Unity metadata file could not be opened"));
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(file_size));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!input || static_cast<std::size_t>(input.gcount()) != bytes.size()) {
        return std::unexpected(error(domain::DebugErrorCode::io_error, "Unity metadata file could not be read"));
    }
    return bytes;
}

[[nodiscard]] std::optional<Il2CppTypeDefinitionView> read_type_definition(
    const std::vector<std::byte>& bytes,
    const Il2CppMetadataHeader& header,
    const std::size_t index,
    const Il2CppMetadataLayout& layout
) {
    const auto base = static_cast<std::size_t>(header.type_definitions_offset) + index * layout.type_definition_size;
    Il2CppTypeDefinitionView type;
    if (!read_i32(bytes, base, type.name_index) || !read_i32(bytes, base + 4U, type.namespace_index)) return std::nullopt;
    if (!read_i32(bytes, base + layout.field_start_offset, type.field_start)) return std::nullopt;
    if (!read_u16(bytes, base + layout.field_count_offset, type.field_count)) return std::nullopt;
    return type;
}

[[nodiscard]] std::optional<Il2CppFieldDefinitionView> read_field_definition(
    const std::vector<std::byte>& bytes,
    const Il2CppMetadataHeader& header,
    const std::size_t index,
    const Il2CppMetadataLayout& layout
) {
    const auto base = static_cast<std::size_t>(header.fields_offset) + index * layout.field_definition_size;
    Il2CppFieldDefinitionView field;
    if (!read_i32(bytes, base, field.name_index) || !read_i32(bytes, base + 4U, field.type_index)) return std::nullopt;
    return field;
}

[[nodiscard]] std::optional<Il2CppMetadataLayout> choose_il2cpp_layout(
    const std::vector<std::byte>& bytes,
    const Il2CppMetadataHeader& header
) {
    const std::vector<Il2CppMetadataLayout> candidates = header.version >= 27
        ? std::vector<Il2CppMetadataLayout>{{88U, 12U, 32U, 68U}}
        : std::vector<Il2CppMetadataLayout>{{88U, 12U, 32U, 68U}, {92U, 16U, 40U, 72U}, {100U, 16U, 48U, 80U}};

    std::optional<Il2CppMetadataLayout> selected;
    std::size_t selected_score = 0U;
    for (const auto& candidate : candidates) {
        if (!valid_table(bytes, header.type_definitions_offset, header.type_definitions_count, candidate.type_definition_size) ||
            !valid_table(bytes, header.fields_offset, header.fields_count, candidate.field_definition_size)) {
            continue;
        }
        const auto type_count = static_cast<std::size_t>(header.type_definitions_count) / candidate.type_definition_size;
        const auto field_count = static_cast<std::size_t>(header.fields_count) / candidate.field_definition_size;
        std::size_t score = 1U;
        const auto sample_count = std::min<std::size_t>(type_count, 64U);
        for (std::size_t index = 0U; index < sample_count; ++index) {
            const auto type = read_type_definition(bytes, header, index, candidate);
            if (!type || type->field_start < 0 || static_cast<std::size_t>(type->field_start) > field_count ||
                static_cast<std::size_t>(type->field_count) > field_count - static_cast<std::size_t>(type->field_start)) {
                continue;
            }
            const auto name = metadata_string(bytes, header, type->name_index);
            if (!name.empty()) ++score;
        }
        if (!selected || score > selected_score) {
            selected = candidate;
            selected_score = score;
        }
    }
    return selected;
}

[[nodiscard]] bool contains_case_insensitive(const std::string_view text, const std::string_view needle) {
    if (needle.empty()) return true;
    const auto lower = [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); };
    std::string haystack{text};
    std::string pattern{needle};
    std::ranges::transform(haystack, haystack.begin(), lower);
    std::ranges::transform(pattern, pattern.begin(), lower);
    return haystack.find(pattern) != std::string::npos;
}

#ifdef _WIN32

[[nodiscard]] std::wstring utf8_to_wide(const std::string_view input) {
    if (input.empty()) return {};
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return {};
    const auto input_size = static_cast<int>(input.size());
    const int size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), input_size, nullptr, 0
    );
    if (size <= 0) return {};
    std::wstring output(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), input_size, output.data(), size) != size) {
        return {};
    }
    return output;
}

[[nodiscard]] std::string wide_to_utf8(const std::wstring_view input) {
    if (input.empty()) return {};
    if (input.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return {};
    const auto input_size = static_cast<int>(input.size());
    const int size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), input_size, nullptr, 0, nullptr, nullptr
    );
    if (size <= 0) return {};
    std::string output(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), input_size,
            output.data(), size, nullptr, nullptr
        ) != size) {
        return {};
    }
    return output;
}

struct LocalFreeDeleter {
    void operator()(wchar_t* value) const noexcept {
        if (value != nullptr) static_cast<void>(LocalFree(value));
    }
};

class DbgHelpSession final {
public:
    explicit DbgHelpSession(const std::wstring& search_path) noexcept
        : process_(GetCurrentProcess()) {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
        initialized_ = SymInitializeW(process_, search_path.empty() ? nullptr : search_path.c_str(), FALSE) != FALSE;
    }

    DbgHelpSession(const DbgHelpSession&) = delete;
    DbgHelpSession& operator=(const DbgHelpSession&) = delete;

    ~DbgHelpSession() {
        if (initialized_) static_cast<void>(SymCleanup(process_));
    }

    [[nodiscard]] bool initialized() const noexcept { return initialized_; }
    [[nodiscard]] HANDLE process() const noexcept { return process_; }

    [[nodiscard]] DWORD64 load_module(const std::wstring& image_path) noexcept {
        if (!initialized_) return 0U;
        base_ = SymLoadModuleExW(
            process_, nullptr, image_path.c_str(), nullptr, 0U, 0U, nullptr, 0U
        );
        return base_;
    }

    [[nodiscard]] DWORD64 base() const noexcept { return base_; }

private:
    HANDLE process_{};
    DWORD64 base_{};
    bool initialized_{false};
};

[[nodiscard]] std::string type_name(
    HANDLE process,
    const DWORD64 module_base,
    const ULONG type_id
) {
    PWSTR raw_name = nullptr;
    if (!SymGetTypeInfo(process, module_base, type_id, TI_GET_SYMNAME, &raw_name) || raw_name == nullptr) {
        return {};
    }
    std::unique_ptr<wchar_t, LocalFreeDeleter> name{raw_name};
    return wide_to_utf8(name.get());
}

[[nodiscard]] std::string basic_type_name(const ULONG basic_type, const ULONG64 size) {
    switch (basic_type) {
    case 1U: return "void";
    case 2U: return "char";
    case 3U: return "wchar_t";
    case 6U: return size == 8U ? "int64" : "int32";
    case 7U: return size == 8U ? "uint64" : "uint32";
    case 8U: return size == 8U ? "double" : "float";
    case 10U: return "bool";
    case 13U: return size == 8U ? "int64" : "long";
    case 14U: return size == 8U ? "uint64" : "unsigned long";
    case 32U: return "char16_t";
    case 33U: return "char32_t";
    case 34U: return "char8_t";
    default: return {};
    }
}

template <typename T>
[[nodiscard]] bool type_info(
    HANDLE process,
    const DWORD64 module_base,
    const ULONG type_id,
    const IMAGEHLP_SYMBOL_TYPE_INFO request,
    T& output
) noexcept {
    return SymGetTypeInfo(process, module_base, type_id, request, &output) != FALSE;
}

[[nodiscard]] std::optional<ULONG> find_type(
    HANDLE process,
    const DWORD64 module_base,
    const std::wstring& requested_name
) {
    std::vector<std::wstring> candidates;
    candidates.push_back(requested_name);
    if (!requested_name.starts_with(L"struct ")) candidates.push_back(L"struct " + requested_name);
    if (!requested_name.starts_with(L"class ")) candidates.push_back(L"class " + requested_name);

    for (const auto& candidate : candidates) {
        constexpr ULONG max_name = MAX_SYM_NAME;
        const auto words = (sizeof(SYMBOL_INFOW) + (max_name + 1U) * sizeof(wchar_t) + sizeof(std::uint64_t) - 1U)
            / sizeof(std::uint64_t);
        std::vector<std::uint64_t> storage(words);
        auto* symbol = reinterpret_cast<PSYMBOL_INFOW>(storage.data());
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = max_name;
        if (SymGetTypeFromNameW(process, module_base, candidate.c_str(), symbol) != FALSE) {
            return symbol->TypeIndex;
        }
    }
    return std::nullopt;
}

struct UnrealReflectionContext final {
    DWORD64 module_base{};
    std::size_t max_symbols{};
    std::vector<domain::ReflectionSymbol> symbols;
    bool truncated{false};
};

BOOL CALLBACK unreal_symbol_callback(
    PSYMBOL_INFOW symbol,
    ULONG,
    PVOID context
) {
    auto* output = static_cast<UnrealReflectionContext*>(context);
    if (output == nullptr || symbol == nullptr) return FALSE;
    if (output->symbols.size() >= output->max_symbols) {
        output->truncated = true;
        return FALSE;
    }
    const std::wstring name{symbol->Name, symbol->NameLen};
    const auto is_class = name.find(L"::StaticClass") != std::wstring::npos;
    const auto is_struct = name.find(L"::StaticStruct") != std::wstring::npos;
    if (!is_class && !is_struct) return TRUE;
    const auto utf8_name = wide_to_utf8(name);
    if (utf8_name.empty()) return TRUE;
    output->symbols.push_back(domain::ReflectionSymbol{
        utf8_name,
        is_class ? "UCLASS" : "USTRUCT",
        symbol->Address >= output->module_base ? symbol->Address - output->module_base : 0U
    });
    return TRUE;
}

[[nodiscard]] std::string udt_kind_name(const ULONG udt_kind) {
    switch (udt_kind) {
    case 0U: return "struct";
    case 1U: return "class";
    case 2U: return "union";
    default: return "unknown";
    }
}

struct TypeCatalogContext final {
    HANDLE process{};
    DWORD64 module_base{};
    std::string name_filter;
    std::string kind_filter;
    std::size_t max_symbols{};
    std::vector<domain::TypeSummary> types;
    bool truncated{false};
};

BOOL CALLBACK type_catalog_callback(
    PSYMBOL_INFOW symbol,
    ULONG,
    PVOID context
) {
    auto* output = static_cast<TypeCatalogContext*>(context);
    if (output == nullptr || symbol == nullptr) return TRUE;
    if (output->types.size() >= output->max_symbols) {
        output->truncated = true;
        return FALSE;
    }
    ULONG tag = 0U;
    if (!type_info(output->process, output->module_base, symbol->TypeIndex, TI_GET_SYMTAG, tag)) {
        return TRUE;
    }
    std::string kind;
    if (tag == SymTagUDT) {
        ULONG udt_kind = 0U;
        if (!type_info(output->process, output->module_base, symbol->TypeIndex, TI_GET_UDTKIND, udt_kind)) {
            return TRUE;
        }
        kind = udt_kind_name(udt_kind);
    } else if (tag == SymTagEnum) {
        kind = "enum";
    } else {
        return TRUE;
    }
    if (!output->kind_filter.empty() && kind != output->kind_filter) {
        return TRUE;
    }
    const std::wstring wide_name{symbol->Name, symbol->NameLen};
    const auto name = wide_to_utf8(wide_name);
    if (name.empty()) return TRUE;
    if (!output->name_filter.empty() && !contains_case_insensitive(name, output->name_filter)) {
        return TRUE;
    }
    ULONG64 size = 0U;
    static_cast<void>(type_info(output->process, output->module_base, symbol->TypeIndex, TI_GET_LENGTH, size));
    output->types.push_back(domain::TypeSummary{name, kind, size});
    return TRUE;
}

#endif

}  // namespace

domain::Result<domain::TypeMetadata> PdbTypeMetadataProvider::inspect_pdb(
    const std::string_view module_path,
    const std::string_view requested_type_name,
    const std::size_t max_fields
) const {
    if (module_path.empty() || requested_type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module_path and type_name are required"));
    }
    if (max_fields == 0U || max_fields > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "max_fields must be between 1 and 4096"));
    }

#ifndef _WIN32
    static_cast<void>(max_fields);
    return std::unexpected(error(domain::DebugErrorCode::unsupported, "PDB type metadata requires Windows DbgHelp"));
#else
    const std::filesystem::path image_path{std::string{module_path}};
    std::error_code filesystem_error;
    if (!std::filesystem::is_regular_file(image_path, filesystem_error)) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "module image is unavailable"));
    }
    const auto wide_image_path = image_path.wstring();
    const auto wide_type_name = utf8_to_wide(requested_type_name);
    if (wide_image_path.empty() || wide_type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module or type name is not valid UTF-8"));
    }

    std::scoped_lock lock{mutex_};
    const auto search_path = image_path.parent_path().wstring();
    DbgHelpSession symbols{search_path};
    if (!symbols.initialized()) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "DbgHelp symbol session could not be initialized"));
    }
    if (symbols.load_module(wide_image_path) == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "matching PDB symbols were not found"));
    }

    const auto type_id = find_type(symbols.process(), symbols.base(), wide_type_name);
    if (!type_id) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "type was not found in the matching PDB"));
    }

    ULONG64 type_size = 0U;
    if (!type_info(symbols.process(), symbols.base(), *type_id, TI_GET_LENGTH, type_size)) {
        return std::unexpected(error(domain::DebugErrorCode::parse_error, "PDB type size is unavailable"));
    }
    ULONG child_count = 0U;
    if (!type_info(symbols.process(), symbols.base(), *type_id, TI_GET_CHILDRENCOUNT, child_count)) {
        return std::unexpected(error(domain::DebugErrorCode::parse_error, "PDB type fields are unavailable"));
    }

    domain::TypeMetadata metadata;
    metadata.type_name = std::string{requested_type_name};
    metadata.size = type_size;
    metadata.source = "pdb:dbghelp";
    metadata.confidence = "high";
    metadata.truncated = static_cast<std::size_t>(child_count) > max_fields;

    const auto field_count = std::min<std::size_t>(child_count, max_fields);
    if (field_count == 0U) return metadata;
    const auto storage_words = (sizeof(TI_FINDCHILDREN_PARAMS) + (field_count - 1U) * sizeof(ULONG) + sizeof(ULONG) - 1U)
        / sizeof(ULONG);
    std::vector<ULONG> child_storage(storage_words);
    auto* children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(child_storage.data());
    children->Count = static_cast<ULONG>(field_count);
    children->Start = 0U;
    if (!type_info(symbols.process(), symbols.base(), *type_id, TI_FINDCHILDREN, *children)) {
        return std::unexpected(error(domain::DebugErrorCode::parse_error, "PDB field enumeration failed"));
    }

    metadata.fields.reserve(field_count);
    for (ULONG index = 0U; index < children->Count; ++index) {
        const ULONG field_id = children->ChildId[index];
        ULONG tag = 0U;
        if (!type_info(symbols.process(), symbols.base(), field_id, TI_GET_SYMTAG, tag)) continue;
        if (tag != SymTagData && tag != SymTagBaseClass) continue;

        auto field_name = type_name(symbols.process(), symbols.base(), field_id);
        if (field_name.empty()) continue;
        ULONG type_id_for_field = 0U;
        ULONG64 field_size = 0U;
        LONG field_offset = 0;
        if (!type_info(symbols.process(), symbols.base(), field_id, TI_GET_TYPEID, type_id_for_field)) {
            static_cast<void>(type_info(symbols.process(), symbols.base(), field_id, TI_GET_TYPE, type_id_for_field));
        }
        if (!type_info(symbols.process(), symbols.base(), field_id, TI_GET_LENGTH, field_size) && type_id_for_field != 0U) {
            static_cast<void>(type_info(symbols.process(), symbols.base(), type_id_for_field, TI_GET_LENGTH, field_size));
        }
        static_cast<void>(type_info(symbols.process(), symbols.base(), field_id, TI_GET_OFFSET, field_offset));

        auto field_type_name = type_name(symbols.process(), symbols.base(), type_id_for_field);
        if (field_type_name.empty()) {
            ULONG basic_type = 0U;
            const bool has_basic_type = type_info(symbols.process(), symbols.base(), field_id, TI_GET_BASETYPE, basic_type) ||
                (type_id_for_field != 0U && type_info(
                    symbols.process(), symbols.base(), type_id_for_field, TI_GET_BASETYPE, basic_type
                ));
            if (has_basic_type) {
                field_type_name = basic_type_name(basic_type, field_size);
            }
        }

        metadata.fields.push_back(domain::TypeField{
            std::move(field_name),
            std::move(field_type_name),
            static_cast<std::int64_t>(field_offset),
            field_size
        });
    }
    return metadata;
#endif
}

domain::Result<domain::TypeMetadata> PdbTypeMetadataProvider::inspect_unity(
    const std::string_view module_path,
    const std::string_view requested_type_name,
    const std::size_t max_fields
) const {
    if (module_path.empty() || requested_type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module and type are required"));
    }
    if (max_fields == 0U || max_fields > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "max_fields must be between 1 and 4096"));
    }
    const auto metadata_path = find_unity_metadata(module_path);
    if (!metadata_path) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "Unity global-metadata.dat was not found beside the loaded module"));
    }
    auto bytes_result = load_metadata_file(*metadata_path);
    if (!bytes_result) return std::unexpected(bytes_result.error());

    Il2CppMetadataHeader header;
    if (!parse_il2cpp_header(*bytes_result, header)) {
        return std::unexpected(error(domain::DebugErrorCode::parse_error, "Unity IL2CPP metadata header is invalid or unsupported"));
    }
    const auto layout = choose_il2cpp_layout(*bytes_result, header);
    if (!layout) {
        return std::unexpected(error(domain::DebugErrorCode::parse_error, "Unity IL2CPP metadata table layout is unsupported"));
    }
    const auto type_count = static_cast<std::size_t>(header.type_definitions_count) / layout->type_definition_size;
    const auto field_count = static_cast<std::size_t>(header.fields_count) / layout->field_definition_size;

    std::optional<Il2CppTypeDefinitionView> selected_type;
    std::string selected_full_name;
    for (std::size_t index = 0U; index < type_count; ++index) {
        const auto type = read_type_definition(*bytes_result, header, index, *layout);
        if (!type || type->field_start < 0 || static_cast<std::size_t>(type->field_start) > field_count ||
            static_cast<std::size_t>(type->field_count) > field_count - static_cast<std::size_t>(type->field_start)) {
            continue;
        }
        const auto name = metadata_string(*bytes_result, header, type->name_index);
        const auto name_space = metadata_string(*bytes_result, header, type->namespace_index);
        if (name.empty()) continue;
        const auto full_name = name_space.empty() ? name : name_space + "." + name;
        if (full_name == requested_type_name || name == requested_type_name) {
            selected_type = type;
            selected_full_name = full_name;
            break;
        }
    }
    if (!selected_type) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "Unity type was not found in global-metadata.dat"));
    }

    domain::TypeMetadata metadata;
    metadata.type_name = selected_full_name;
    metadata.source = "unity:il2cpp-global-metadata";
    metadata.confidence = "medium";
    metadata.truncated = static_cast<std::size_t>(selected_type->field_count) > max_fields;
    const auto fields_to_read = std::min<std::size_t>(selected_type->field_count, max_fields);
    metadata.fields.reserve(fields_to_read);
    for (std::size_t index = 0U; index < fields_to_read; ++index) {
        const auto field_index = static_cast<std::size_t>(selected_type->field_start) + index;
        const auto field = read_field_definition(*bytes_result, header, field_index, *layout);
        if (!field) {
            return std::unexpected(error(domain::DebugErrorCode::parse_error, "Unity field definition is outside the metadata table"));
        }
        const auto field_name = metadata_string(*bytes_result, header, field->name_index);
        if (field_name.empty()) {
            return std::unexpected(error(domain::DebugErrorCode::parse_error, "Unity field name is outside the metadata string table"));
        }
        metadata.fields.push_back(domain::TypeField{
            field_name,
            "il2cpp_type_index:" + std::to_string(field->type_index),
            -1,
            0U
        });
    }

    // When Unity preserved native debug symbols, PDB gives the actual native
    // layout. Keep the metadata names as the fallback for stripped builds.
    auto pdb_result = inspect_pdb(module_path, selected_full_name, max_fields);
    if (!pdb_result && selected_full_name != requested_type_name) {
        // A PDB may retain the caller's short name while metadata supplied the
        // namespace-qualified spelling. Try both exact spellings before using
        // the metadata-only result.
        pdb_result = inspect_pdb(module_path, requested_type_name, max_fields);
    }
    if (pdb_result) {
        pdb_result->source = "unity:il2cpp-global-metadata+pdb";
        pdb_result->confidence = "high";
        return pdb_result;
    }
    return metadata;
}

domain::Result<domain::TypeMetadata> PdbTypeMetadataProvider::inspect_unreal_type(
    const std::string_view module_path,
    const std::string_view requested_type_name,
    const std::size_t max_fields
) const {
    if (module_path.empty() || requested_type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module and type are required"));
    }
    if (max_fields == 0U || max_fields > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "max_fields must be between 1 and 4096"));
    }
    const char first = requested_type_name.front();
    if (first != 'A' && first != 'U' && first != 'F' && first != 'E' && first != 'I') {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "Unreal type must be a reflected A/U/F/E/I type"));
    }
    auto result = inspect_pdb(module_path, requested_type_name, max_fields);
    if (!result) return std::unexpected(result.error());
    result->source = "unreal:uht-pdb";
    result->confidence = "high";
    return result;
}

domain::Result<domain::ReflectionMetadata> PdbTypeMetadataProvider::inspect_unreal_reflection(
    const std::string_view module_path,
    const std::size_t max_symbols
) const {
    if (module_path.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module is required"));
    }
    if (max_symbols == 0U || max_symbols > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "max_symbols must be between 1 and 4096"));
    }
#ifndef _WIN32
    static_cast<void>(max_symbols);
    return std::unexpected(error(domain::DebugErrorCode::unsupported, "Unreal PDB reflection requires Windows DbgHelp"));
#else
    const std::filesystem::path image_path{std::string{module_path}};
    std::error_code filesystem_error;
    if (!std::filesystem::is_regular_file(image_path, filesystem_error)) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "module image is unavailable"));
    }
    const auto wide_image_path = image_path.wstring();
    if (wide_image_path.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module path is not valid"));
    }

    std::scoped_lock lock{mutex_};
    DbgHelpSession symbols{image_path.parent_path().wstring()};
    if (!symbols.initialized()) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "DbgHelp symbol session could not be initialized"));
    }
    if (symbols.load_module(wide_image_path) == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "matching Unreal PDB symbols were not found"));
    }

    UnrealReflectionContext context{symbols.base(), max_symbols};
    static_cast<void>(SymEnumSymbolsW(
        symbols.process(), symbols.base(), L"*StaticClass*", unreal_symbol_callback, &context
    ));
    if (!context.truncated) {
        static_cast<void>(SymEnumSymbolsW(
            symbols.process(), symbols.base(), L"*StaticStruct*", unreal_symbol_callback, &context
        ));
    }
    if (context.symbols.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "Unreal UHT reflection symbols were not found in the matching PDB"));
    }

    domain::ReflectionMetadata metadata;
    metadata.engine = "unreal";
    metadata.source = "unreal:uht-pdb-reflection";
    metadata.confidence = "high";
    metadata.symbols = std::move(context.symbols);
    metadata.truncated = context.truncated;
    return metadata;
#endif
}

domain::Result<domain::TypeCatalog> PdbTypeMetadataProvider::list_pdb_types(
    const std::string_view module_path,
    const std::string_view name_filter,
    const std::string_view kind_filter,
    const std::size_t max_symbols
) const {
    if (module_path.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module_path is required"));
    }
    if (max_symbols == 0U || max_symbols > 65536U) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "max_symbols must be between 1 and 65536"));
    }
    if (!kind_filter.empty() && kind_filter != "class" && kind_filter != "struct" &&
        kind_filter != "enum" && kind_filter != "union") {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "kind_filter must be class, struct, enum or union"
        ));
    }
#ifndef _WIN32
    static_cast<void>(name_filter);
    return std::unexpected(error(domain::DebugErrorCode::unsupported, "PDB type metadata requires Windows DbgHelp"));
#else
    const std::filesystem::path image_path{std::string{module_path}};
    std::error_code filesystem_error;
    if (!std::filesystem::is_regular_file(image_path, filesystem_error)) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "module image is unavailable"));
    }
    const auto wide_image_path = image_path.wstring();
    if (wide_image_path.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module path is not valid"));
    }

    std::scoped_lock lock{mutex_};
    const auto search_path = image_path.parent_path().wstring();
    DbgHelpSession symbols{search_path};
    if (!symbols.initialized()) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "DbgHelp symbol session could not be initialized"));
    }
    if (symbols.load_module(wide_image_path) == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "matching PDB symbols were not found"));
    }

    TypeCatalogContext context{
        symbols.process(), symbols.base(), std::string{name_filter}, std::string{kind_filter}, max_symbols
    };
    const BOOL enumerated = SymEnumTypesW(symbols.process(), symbols.base(), type_catalog_callback, &context);
    if (!enumerated && context.types.empty() && !context.truncated) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "no PDB types were found in the matching module"));
    }

    domain::TypeCatalog catalog;
    catalog.types = std::move(context.types);
    catalog.source = "pdb:dbghelp";
    catalog.confidence = "high";
    catalog.truncated = context.truncated;
    return catalog;
#endif
}

}  // namespace argos::infrastructure
