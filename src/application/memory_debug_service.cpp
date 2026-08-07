#include "argos_mcp/application/memory_debug_service.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

[[nodiscard]] domain::Result<domain::Address> add_offset(
    const domain::Address address,
    const std::int64_t offset
) {
    if (offset >= 0) {
        const auto positive = static_cast<std::uint64_t>(offset);
        if (positive > std::numeric_limits<domain::Address>::max() - address) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "address overflow"));
        }
        return address + positive;
    }
    const auto magnitude = static_cast<std::uint64_t>(-(offset + 1)) + 1U;
    if (magnitude > address) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "address underflow"));
    }
    return address - magnitude;
}

[[nodiscard]] std::uint64_t decode_pointer(std::span<const std::byte> bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        const auto byte_value = static_cast<std::uint64_t>(std::to_integer<unsigned int>(bytes[index]));
        value |= byte_value << (index * 8U);
    }
    return value;
}

}  // namespace

MemoryDebugService::MemoryDebugService(
    std::unique_ptr<domain::ProcessMemoryProvider> provider,
    security::SecurityPolicy policy,
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider
) : provider_(std::move(provider)), metadata_provider_(std::move(metadata_provider)), policy_(policy) {}

domain::Result<std::vector<domain::ProcessInfo>> MemoryDebugService::list_processes(
    const std::string_view filter,
    const std::size_t limit
) const {
    if (!provider_) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "process provider is unavailable"));
    }
    return provider_->list_processes(filter, limit);
}

domain::Result<domain::SessionInfo> MemoryDebugService::attach(
    const domain::ProcessId pid,
    const domain::AccessMode access,
    const bool authorized
) {
    auto authorization = policy_.authorize_attach(authorized, access);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    if (!provider_) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "process provider is unavailable"));
    }
    auto session = provider_->attach(pid, access);
    if (!session) {
        return std::unexpected(session.error());
    }
    return sessions_.add(std::move(*session));
}

domain::Result<void> MemoryDebugService::detach(const domain::SessionId& id) {
    return sessions_.remove(id);
}

std::vector<domain::SessionInfo> MemoryDebugService::list_sessions() const {
    return sessions_.list();
}

domain::Result<std::vector<domain::MemoryRegion>> MemoryDebugService::regions(
    const domain::SessionId& id
) const {
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    return (*session)->regions();
}

domain::Result<std::vector<domain::ModuleInfo>> MemoryDebugService::modules(
    const domain::SessionId& id
) const {
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    return (*session)->modules();
}

domain::Result<std::string> MemoryDebugService::module_path(
    const domain::SessionId& id,
    const std::string_view module_name
) const {
    if (module_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module is required"));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto module_result = (*session)->modules();
    if (!module_result) {
        return std::unexpected(module_result.error());
    }
    const auto module = std::find_if(
        module_result->begin(), module_result->end(),
        [module_name](const domain::ModuleInfo& candidate) {
            return candidate.name == module_name || candidate.path == module_name;
        }
    );
    if (module == module_result->end()) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "module is not loaded in the session"));
    }
    return module->path;
}

domain::Result<domain::TypeMetadata> MemoryDebugService::pdb_type(
    const domain::SessionId& id,
    const std::string_view module_name,
    const std::string_view type_name,
    const std::size_t max_fields
) const {
    if (module_name.empty() || type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "module and type are required"));
    }
    if (!metadata_provider_) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "PDB metadata provider is unavailable"));
    }
    auto path = module_path(id, module_name);
    if (!path) return std::unexpected(path.error());
    return metadata_provider_->inspect_pdb(*path, type_name, max_fields);
}

domain::Result<domain::TypeMetadata> MemoryDebugService::unity_type(
    const domain::SessionId& id,
    const std::string_view module_name,
    const std::string_view type_name,
    const std::size_t max_fields
) const {
    if (type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "type is required"));
    }
    if (!metadata_provider_) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "engine metadata provider is unavailable"));
    }
    auto path = module_path(id, module_name);
    if (!path) return std::unexpected(path.error());
    return metadata_provider_->inspect_unity(*path, type_name, max_fields);
}

domain::Result<domain::TypeMetadata> MemoryDebugService::unreal_type(
    const domain::SessionId& id,
    const std::string_view module_name,
    const std::string_view type_name,
    const std::size_t max_fields
) const {
    if (type_name.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "type is required"));
    }
    if (!metadata_provider_) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "engine metadata provider is unavailable"));
    }
    auto path = module_path(id, module_name);
    if (!path) return std::unexpected(path.error());
    return metadata_provider_->inspect_unreal_type(*path, type_name, max_fields);
}

domain::Result<domain::ReflectionMetadata> MemoryDebugService::unreal_reflection(
    const domain::SessionId& id,
    const std::string_view module_name,
    const std::size_t max_symbols
) const {
    if (!metadata_provider_) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "engine metadata provider is unavailable"));
    }
    auto path = module_path(id, module_name);
    if (!path) return std::unexpected(path.error());
    return metadata_provider_->inspect_unreal_reflection(*path, max_symbols);
}

domain::Result<std::vector<std::byte>> MemoryDebugService::read_memory(
    const domain::SessionId& id,
    const domain::Address address,
    const std::size_t size
) const {
    auto authorization = policy_.authorize_read(size);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    std::vector<std::byte> output(size);
    auto read = (*session)->read(address, output);
    if (!read) {
        return std::unexpected(read.error());
    }
    output.resize(*read);
    return output;
}

domain::Result<std::vector<BatchReadResult>> MemoryDebugService::read_batch(
    const domain::SessionId& id,
    const std::span<const BatchReadItem> items
) const {
    if (items.empty() || items.size() > 256U) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded,
            "batch must contain between 1 and 256 reads"
        ));
    }
    std::size_t total = 0;
    for (const auto& item : items) {
        if (item.size > policy_.max_read_bytes - std::min(total, policy_.max_read_bytes)) {
            return std::unexpected(error(domain::DebugErrorCode::limit_exceeded, "batch byte limit exceeded"));
        }
        total += item.size;
    }
    auto authorization = policy_.authorize_read(total);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    std::vector<BatchReadResult> output;
    output.reserve(items.size());
    for (const auto& item : items) {
        BatchReadResult result;
        result.address = item.address;
        result.bytes.resize(item.size);
        auto read = (*session)->read(item.address, result.bytes);
        if (read) {
            result.bytes.resize(*read);
            result.success = true;
        } else {
            result.bytes.clear();
            result.error = read.error().safe_message;
        }
        output.push_back(std::move(result));
    }
    return output;
}

domain::Result<std::size_t> MemoryDebugService::write_memory(
    const domain::SessionId& id,
    const domain::Address address,
    const std::span<const std::byte> bytes,
    const std::string_view confirmation
) {
    auto authorization = policy_.authorize_write(bytes.size(), confirmation);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    return (*session)->write(address, bytes);
}

domain::Result<ScanResult> MemoryDebugService::scan_exact(
    const domain::SessionId& id,
    const std::span<const std::byte> pattern,
    const std::size_t alignment,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) const {
    if (pattern.empty() || pattern.size() > 4096U) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "pattern size must be between 1 and 4096 bytes"
        ));
    }
    if (alignment == 0U || alignment > 4096U || !std::has_single_bit(alignment)) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "alignment must be a power of two between 1 and 4096"
        ));
    }
    if (start_address && end_address && *end_address <= *start_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "end_address must be greater than start_address"
        ));
    }
    auto authorization = policy_.authorize_scan(byte_budget, result_limit);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto region_result = (*session)->regions();
    if (!region_result) {
        return std::unexpected(region_result.error());
    }

    constexpr std::size_t chunk_size = 64U * 1024U;
    ScanResult result;
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + pattern.size());

    for (const auto& region : *region_result) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
        }
        if (!region.readable || (writable_only && !region.writable) || region.size() == 0U) {
            continue;
        }
        const domain::Address scan_start = std::max(region.start, start_address.value_or(region.start));
        const domain::Address scan_end = std::min(region.end, end_address.value_or(region.end));
        if (scan_end <= scan_start) {
            continue;
        }
        domain::Address cursor = scan_start;
        std::vector<std::byte> carry;
        while (cursor < scan_end && result.bytes_scanned < byte_budget) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
            }
            const auto remaining_region = scan_end - cursor;
            const auto remaining_budget = byte_budget - result.bytes_scanned;
            const auto request_u64 = std::min<std::uint64_t>(
                {remaining_region, static_cast<std::uint64_t>(remaining_budget), static_cast<std::uint64_t>(chunk_size)}
            );
            const auto request = static_cast<std::size_t>(request_u64);
            if (request == 0U) {
                break;
            }
            std::vector<std::byte> chunk(request);
            auto read = (*session)->read(cursor, chunk);
            if (!read || *read == 0U) {
                break;
            }
            chunk.resize(*read);
            result.bytes_scanned += chunk.size();

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());

            if (buffer.size() >= pattern.size()) {
                for (std::size_t index = 0; index + pattern.size() <= buffer.size(); ++index) {
                    const domain::Address candidate = buffer_base + static_cast<domain::Address>(index);
                    if ((candidate % alignment) != 0U) {
                        continue;
                    }
                    if (std::equal(pattern.begin(), pattern.end(), buffer.begin() + static_cast<std::ptrdiff_t>(index))) {
                        result.matches.push_back(domain::ScanMatch{candidate});
                        if (result.matches.size() >= result_limit) {
                            result.truncated = true;
                            return result;
                        }
                    }
                }
            }

            const std::size_t carry_size = std::min(pattern.size() - 1U, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size), buffer.end());
            cursor += static_cast<domain::Address>(chunk.size());
        }
        if (result.bytes_scanned >= byte_budget) {
            result.truncated = true;
            break;
        }
    }
    return result;
}

domain::Result<domain::Address> MemoryDebugService::resolve_pointer_chain(
    const domain::SessionId& id,
    const domain::Address base,
    const std::span<const std::int64_t> offsets,
    const std::size_t pointer_size
) const {
    if (offsets.empty() || offsets.size() > 64U) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "pointer chain must contain between 1 and 64 offsets"
        ));
    }
    if (pointer_size != 4U && pointer_size != 8U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "pointer_size must be 4 or 8"));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }

    domain::Address current = base;
    std::array<std::byte, 8> pointer_bytes{};
    for (std::size_t index = 0; index < offsets.size(); ++index) {
        auto adjusted = add_offset(current, offsets[index]);
        if (!adjusted) {
            return std::unexpected(adjusted.error());
        }
        if (index + 1U == offsets.size()) {
            return *adjusted;
        }
        auto read = (*session)->read(*adjusted, std::span<std::byte>{pointer_bytes}.first(pointer_size));
        if (!read || *read != pointer_size) {
            return std::unexpected(read ? error(
                domain::DebugErrorCode::io_error, "short pointer read"
            ) : read.error());
        }
        current = decode_pointer(std::span<const std::byte>{pointer_bytes}.first(pointer_size));
        if (current == 0U) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "null pointer in chain"));
        }
    }
    return std::unexpected(error(domain::DebugErrorCode::invalid_state, "unreachable pointer chain state"));
}

}  // namespace argos::application
