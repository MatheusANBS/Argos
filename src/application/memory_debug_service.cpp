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

enum class Ordering { less, equal, greater };

[[nodiscard]] Ordering compare_scan_values(
    const domain::ScanValueType type,
    const std::span<const std::byte> lhs,
    const std::span<const std::byte> rhs
) {
    const auto lhs_raw = decode_pointer(lhs);
    const auto rhs_raw = decode_pointer(rhs);
    switch (type) {
    case domain::ScanValueType::u8:
    case domain::ScanValueType::u16:
    case domain::ScanValueType::u32:
    case domain::ScanValueType::u64:
        return lhs_raw < rhs_raw ? Ordering::less : (lhs_raw > rhs_raw ? Ordering::greater : Ordering::equal);
    case domain::ScanValueType::i8: {
        const auto l = static_cast<std::int8_t>(static_cast<std::uint8_t>(lhs_raw));
        const auto r = static_cast<std::int8_t>(static_cast<std::uint8_t>(rhs_raw));
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    case domain::ScanValueType::i16: {
        const auto l = static_cast<std::int16_t>(static_cast<std::uint16_t>(lhs_raw));
        const auto r = static_cast<std::int16_t>(static_cast<std::uint16_t>(rhs_raw));
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    case domain::ScanValueType::i32: {
        const auto l = static_cast<std::int32_t>(static_cast<std::uint32_t>(lhs_raw));
        const auto r = static_cast<std::int32_t>(static_cast<std::uint32_t>(rhs_raw));
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    case domain::ScanValueType::i64: {
        const auto l = static_cast<std::int64_t>(lhs_raw);
        const auto r = static_cast<std::int64_t>(rhs_raw);
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    case domain::ScanValueType::f32: {
        const auto l = std::bit_cast<float>(static_cast<std::uint32_t>(lhs_raw));
        const auto r = std::bit_cast<float>(static_cast<std::uint32_t>(rhs_raw));
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    case domain::ScanValueType::f64: {
        const auto l = std::bit_cast<double>(lhs_raw);
        const auto r = std::bit_cast<double>(rhs_raw);
        return l < r ? Ordering::less : (l > r ? Ordering::greater : Ordering::equal);
    }
    }
    return Ordering::equal;
}

[[nodiscard]] bool matches_delta(
    const domain::ScanValueType type,
    const std::span<const std::byte> old_bytes,
    const std::span<const std::byte> new_bytes,
    const std::span<const std::byte> delta_bytes,
    const bool increase
) {
    const auto old_raw = decode_pointer(old_bytes);
    const auto new_raw = decode_pointer(new_bytes);
    const auto delta_raw = decode_pointer(delta_bytes);
    switch (type) {
    case domain::ScanValueType::u8: {
        const auto o = static_cast<std::uint8_t>(old_raw);
        const auto d = static_cast<std::uint8_t>(delta_raw);
        const auto n = static_cast<std::uint8_t>(new_raw);
        return static_cast<std::uint8_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::u16: {
        const auto o = static_cast<std::uint16_t>(old_raw);
        const auto d = static_cast<std::uint16_t>(delta_raw);
        const auto n = static_cast<std::uint16_t>(new_raw);
        return static_cast<std::uint16_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::u32: {
        const auto o = static_cast<std::uint32_t>(old_raw);
        const auto d = static_cast<std::uint32_t>(delta_raw);
        const auto n = static_cast<std::uint32_t>(new_raw);
        return static_cast<std::uint32_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::u64: {
        return (increase ? old_raw + delta_raw : old_raw - delta_raw) == new_raw;
    }
    case domain::ScanValueType::i8: {
        const auto o = static_cast<std::int8_t>(static_cast<std::uint8_t>(old_raw));
        const auto d = static_cast<std::int8_t>(static_cast<std::uint8_t>(delta_raw));
        const auto n = static_cast<std::int8_t>(static_cast<std::uint8_t>(new_raw));
        return static_cast<std::int8_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::i16: {
        const auto o = static_cast<std::int16_t>(static_cast<std::uint16_t>(old_raw));
        const auto d = static_cast<std::int16_t>(static_cast<std::uint16_t>(delta_raw));
        const auto n = static_cast<std::int16_t>(static_cast<std::uint16_t>(new_raw));
        return static_cast<std::int16_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::i32: {
        const auto o = static_cast<std::int32_t>(static_cast<std::uint32_t>(old_raw));
        const auto d = static_cast<std::int32_t>(static_cast<std::uint32_t>(delta_raw));
        const auto n = static_cast<std::int32_t>(static_cast<std::uint32_t>(new_raw));
        return static_cast<std::int32_t>(increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::i64: {
        const auto o = static_cast<std::int64_t>(old_raw);
        const auto d = static_cast<std::int64_t>(delta_raw);
        const auto n = static_cast<std::int64_t>(new_raw);
        return (increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::f32: {
        const auto o = std::bit_cast<float>(static_cast<std::uint32_t>(old_raw));
        const auto d = std::bit_cast<float>(static_cast<std::uint32_t>(delta_raw));
        const auto n = std::bit_cast<float>(static_cast<std::uint32_t>(new_raw));
        return (increase ? o + d : o - d) == n;
    }
    case domain::ScanValueType::f64: {
        const auto o = std::bit_cast<double>(old_raw);
        const auto d = std::bit_cast<double>(delta_raw);
        const auto n = std::bit_cast<double>(new_raw);
        return (increase ? o + d : o - d) == n;
    }
    }
    return false;
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

domain::Result<void> MemoryDebugService::detach(const domain::SessionId& id, const bool terminate) {
    if (terminate) {
        auto session = sessions_.get(id);
        if (!session) {
            return std::unexpected(session.error());
        }
        auto* launched = dynamic_cast<domain::LaunchedProcessSession*>(session->get());
        if (launched == nullptr || !launched->owned()) {
            return std::unexpected(error(
                domain::DebugErrorCode::access_denied,
                "terminate is only allowed for sessions created by memory_debug.launch"
            ));
        }
        auto terminated = launched->terminate();
        if (!terminated) {
            return std::unexpected(terminated.error());
        }
    }
    auto removed = sessions_.remove(id);
    if (!removed) {
        return removed;
    }
    scan_sessions_.remove_owned_by(id);
    return removed;
}

std::vector<domain::SessionInfo> MemoryDebugService::list_sessions() const {
    return sessions_.list();
}

domain::Result<domain::SessionInfo> MemoryDebugService::launch(
    const domain::LaunchSpec& spec,
    const domain::AccessMode access,
    const bool authorized
) {
    auto launch_authorization = policy_.authorize_launch(authorized, spec.executable);
    if (!launch_authorization) {
        return std::unexpected(launch_authorization.error());
    }
    auto access_authorization = policy_.authorize_attach(authorized, access);
    if (!access_authorization) {
        return std::unexpected(access_authorization.error());
    }
    if (!provider_) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "process provider is unavailable"));
    }
    const auto owned_count = sessions_.count_if([](const domain::ProcessSession& session) {
        const auto* launched = dynamic_cast<const domain::LaunchedProcessSession*>(&session);
        return launched != nullptr && launched->owned();
    });
    if (owned_count >= policy_.max_launched_processes) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "maximum number of launched processes reached"
        ));
    }
    auto launched_session = provider_->launch(spec, access);
    if (!launched_session) {
        return std::unexpected(launched_session.error());
    }
    return sessions_.add(std::move(*launched_session));
}

domain::Result<domain::OutputChunk> MemoryDebugService::read_output(
    const domain::SessionId& id,
    const std::uint64_t since_cursor,
    const std::size_t max_bytes
) const {
    if (max_bytes == 0U || max_bytes > policy_.max_captured_output_bytes) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_bytes exceeds configured captured output limit"
        ));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto* launched = dynamic_cast<domain::LaunchedProcessSession*>(session->get());
    if (launched == nullptr) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "session was not created by memory_debug.launch"
        ));
    }
    return launched->read_output(since_cursor, max_bytes);
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

domain::Result<domain::TypeCatalog> MemoryDebugService::pdb_list_types(
    const domain::SessionId& id,
    const std::string_view module_name,
    const std::string_view name_filter,
    const std::string_view kind_filter,
    const std::size_t max_symbols
) const {
    if (!metadata_provider_) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "PDB metadata provider is unavailable"));
    }
    auto path = module_path(id, module_name);
    if (!path) return std::unexpected(path.error());
    return metadata_provider_->list_pdb_types(*path, name_filter, kind_filter, max_symbols);
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
    return scan_pattern(
        id, pattern, alignment, byte_budget, result_limit, writable_only,
        start_address, end_address, cancellation
    );
}

domain::Result<ScanResult> MemoryDebugService::scan_pointers_to(
    const domain::SessionId& id,
    const domain::Address target,
    const std::size_t pointer_size,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) const {
    if (pointer_size != 4U && pointer_size != 8U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "pointer_size must be 4 or 8"));
    }
    if (target == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "target_address must not be zero"));
    }
    std::array<std::byte, 8> pattern_bytes{};
    for (std::size_t index = 0; index < pointer_size; ++index) {
        pattern_bytes[index] = static_cast<std::byte>((target >> (index * 8U)) & 0xFFU);
    }
    return scan_pattern(
        id, std::span<const std::byte>{pattern_bytes}.first(pointer_size), pointer_size,
        byte_budget, result_limit, writable_only, start_address, end_address, cancellation
    );
}

domain::Result<ScanResult> MemoryDebugService::scan_pattern(
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

domain::Result<StringScanResult> MemoryDebugService::extract_strings(
    const domain::SessionId& id,
    const std::size_t min_length,
    const std::string_view encoding,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) const {
    if (min_length == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "min_length must be positive"));
    }
    const bool utf16 = encoding == "utf16le";
    if (!utf16 && encoding != "ascii") {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "encoding must be ascii or utf16le"));
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
    const std::size_t unit = utf16 ? 2U : 1U;
    const std::string encoding_label = utf16 ? "utf16le" : "ascii";
    StringScanResult result;

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

        bool in_run = false;
        domain::Address run_start = 0;
        std::uint64_t run_length = 0;
        std::string run_text;
        bool truncated_by_limit = false;

        const auto flush_run = [&]() {
            if (in_run && run_length >= min_length) {
                result.matches.push_back(StringMatch{run_start, run_text, encoding_label});
                if (result.matches.size() >= result_limit) {
                    result.truncated = true;
                    truncated_by_limit = true;
                }
            }
            in_run = false;
            run_length = 0;
            run_text.clear();
        };

        while (cursor < scan_end && result.bytes_scanned < byte_budget && !truncated_by_limit) {
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

            std::vector<std::byte> buffer;
            buffer.reserve(carry.size() + chunk.size());
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());

            std::size_t index = 0;
            while (index + unit <= buffer.size() && !truncated_by_limit) {
                const domain::Address byte_address = buffer_base + static_cast<domain::Address>(index);
                bool printable = false;
                unsigned char printable_char = 0;
                if (utf16) {
                    const auto low = std::to_integer<unsigned char>(buffer[index]);
                    const auto high = std::to_integer<unsigned char>(buffer[index + 1U]);
                    printable = high == 0U && low >= 0x20U && low <= 0x7EU;
                    printable_char = low;
                } else {
                    const auto value = std::to_integer<unsigned char>(buffer[index]);
                    printable = value >= 0x20U && value <= 0x7EU;
                    printable_char = value;
                }
                if (printable) {
                    if (!in_run) {
                        in_run = true;
                        run_start = byte_address;
                        run_length = 0;
                        run_text.clear();
                    }
                    ++run_length;
                    if (run_text.size() < policy_.max_string_result_length) {
                        run_text.push_back(static_cast<char>(printable_char));
                    }
                } else {
                    flush_run();
                }
                index += unit;
            }

            const std::size_t leftover = buffer.size() - index;
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(leftover), buffer.end());
            cursor += static_cast<domain::Address>(chunk.size());
        }
        flush_run();
        if (truncated_by_limit) {
            return result;
        }
        if (result.bytes_scanned >= byte_budget) {
            result.truncated = true;
            break;
        }
    }
    return result;
}

domain::Result<domain::ScanSessionInfo> MemoryDebugService::scan_first(
    const domain::SessionId& id,
    const domain::ScanValueType value_type,
    const domain::ScanComparison comparison,
    std::optional<std::vector<std::byte>> value,
    std::optional<std::pair<std::vector<std::byte>, std::vector<std::byte>>> range,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) const {
    if (comparison != domain::ScanComparison::exact && comparison != domain::ScanComparison::unknown &&
        comparison != domain::ScanComparison::in_range) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "scan_first comparison must be exact, unknown or in_range"
        ));
    }
    const auto value_size = domain::scan_value_size(value_type);
    if (value_size == 0U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "unsupported value_type"));
    }
    if (comparison == domain::ScanComparison::exact && (!value || value->size() != value_size)) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "exact comparison requires a value matching value_type size"
        ));
    }
    if (comparison == domain::ScanComparison::in_range &&
        (!range || range->first.size() != value_size || range->second.size() != value_size)) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "in_range comparison requires low and high values matching value_type size"
        ));
    }
    if (start_address && end_address && *end_address <= *start_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "end_address must be greater than start_address"
        ));
    }
    auto authorization = policy_.authorize_scan_session(byte_budget, result_limit);
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
    std::vector<ScanCandidate> candidates;
    std::size_t bytes_scanned = 0;
    bool truncated_by_limit = false;

    for (const auto& region : *region_result) {
        if (truncated_by_limit) {
            break;
        }
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
        while (cursor < scan_end && bytes_scanned < byte_budget && !truncated_by_limit) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
            }
            const auto remaining_region = scan_end - cursor;
            const auto remaining_budget = byte_budget - bytes_scanned;
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
            bytes_scanned += chunk.size();

            std::vector<std::byte> buffer;
            buffer.reserve(carry.size() + chunk.size());
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.end());
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());

            if (buffer.size() >= value_size) {
                for (std::size_t index = 0; index + value_size <= buffer.size(); ++index) {
                    const domain::Address candidate_address = buffer_base + static_cast<domain::Address>(index);
                    if ((candidate_address % value_size) != 0U) {
                        continue;
                    }
                    const std::span<const std::byte> window{buffer.data() + index, value_size};
                    bool matches = false;
                    if (comparison == domain::ScanComparison::unknown) {
                        matches = true;
                    } else if (comparison == domain::ScanComparison::exact) {
                        matches = std::equal(window.begin(), window.end(), value->begin());
                    } else {
                        matches = compare_scan_values(value_type, window, range->first) != Ordering::less &&
                            compare_scan_values(value_type, window, range->second) != Ordering::greater;
                    }
                    if (matches) {
                        candidates.push_back(ScanCandidate{
                            candidate_address, std::vector<std::byte>(window.begin(), window.end())
                        });
                        if (candidates.size() >= result_limit) {
                            truncated_by_limit = true;
                            break;
                        }
                    }
                }
            }

            const std::size_t carry_size = std::min(value_size - 1U, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size), buffer.end());
            cursor += static_cast<domain::Address>(chunk.size());
        }
    }

    return scan_sessions_.create(id, value_type, std::move(candidates), policy_.max_scan_sessions_per_session);
}

domain::Result<domain::ScanSessionInfo> MemoryDebugService::scan_next(
    const domain::ScanSessionId& scan_id,
    const domain::ScanComparison comparison,
    std::optional<std::vector<std::byte>> value,
    std::optional<std::vector<std::byte>> delta,
    const std::stop_token cancellation
) const {
    if (comparison == domain::ScanComparison::unknown || comparison == domain::ScanComparison::in_range) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "scan_next does not support unknown or in_range (no range parameter is available on this call)"
        ));
    }
    auto snapshot = scan_sessions_.snapshot(scan_id);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    const auto value_size = domain::scan_value_size(snapshot->value_type);
    if (comparison == domain::ScanComparison::exact && (!value || value->size() != value_size)) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "exact comparison requires a value matching value_type size"
        ));
    }
    if ((comparison == domain::ScanComparison::increased_by || comparison == domain::ScanComparison::decreased_by) &&
        (!delta || delta->size() != value_size)) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "increased_by/decreased_by comparisons require a delta matching value_type size"
        ));
    }

    auto session = sessions_.get(snapshot->owner);
    if (!session) {
        return std::unexpected(session.error());
    }

    std::vector<ScanCandidate> survivors;
    survivors.reserve(snapshot->candidates.size());
    std::vector<std::byte> buffer(value_size);
    for (const auto& candidate : snapshot->candidates) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
        }
        auto read = (*session)->read(candidate.address, buffer);
        if (!read || *read != value_size) {
            continue;
        }
        bool matches = false;
        switch (comparison) {
        case domain::ScanComparison::exact:
            matches = std::equal(buffer.begin(), buffer.end(), value->begin());
            break;
        case domain::ScanComparison::changed:
            matches = !std::equal(buffer.begin(), buffer.end(), candidate.value.begin());
            break;
        case domain::ScanComparison::unchanged:
            matches = std::equal(buffer.begin(), buffer.end(), candidate.value.begin());
            break;
        case domain::ScanComparison::increased:
            matches = compare_scan_values(snapshot->value_type, buffer, candidate.value) == Ordering::greater;
            break;
        case domain::ScanComparison::decreased:
            matches = compare_scan_values(snapshot->value_type, buffer, candidate.value) == Ordering::less;
            break;
        case domain::ScanComparison::increased_by:
            matches = matches_delta(snapshot->value_type, candidate.value, buffer, *delta, true);
            break;
        case domain::ScanComparison::decreased_by:
            matches = matches_delta(snapshot->value_type, candidate.value, buffer, *delta, false);
            break;
        default:
            break;
        }
        if (matches) {
            survivors.push_back(ScanCandidate{candidate.address, std::vector<std::byte>(buffer.begin(), buffer.end())});
        }
    }

    return scan_sessions_.replace(scan_id, std::move(survivors));
}

domain::Result<std::vector<domain::ScanMatch>> MemoryDebugService::scan_results(
    const domain::ScanSessionId& scan_id,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || limit > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "limit must be between 1 and 4096"));
    }
    return scan_sessions_.results(scan_id, offset, limit);
}

domain::Result<void> MemoryDebugService::scan_reset(const domain::ScanSessionId& scan_id) {
    auto result = scan_sessions_.reset(scan_id);
    if (!result) {
        return std::unexpected(result.error());
    }
    return {};
}

}  // namespace argos::application
