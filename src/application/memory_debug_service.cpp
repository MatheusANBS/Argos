#include "argos_mcp/application/memory_debug_service.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstring>
#include <limits>
#include <random>
#include <type_traits>
#include <unordered_set>
#include <utility>

namespace argos::application {
namespace {

[[nodiscard]] domain::DebugError error(domain::DebugErrorCode code, std::string message) {
    return domain::DebugError{code, std::move(message)};
}

[[nodiscard]] bool ascii_case_equal(const std::string_view lhs, const std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    for (std::size_t index = 0U; index < lhs.size(); ++index) {
        const auto lower = [](const char value) noexcept {
            return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
        };
        if (lower(lhs[index]) != lower(rhs[index])) return false;
    }
    return true;
}

[[nodiscard]] bool requested_module_matches(
    const domain::ModuleInfo& module,
    const std::string_view requested
) noexcept {
    return requested.empty() || ascii_case_equal(module.name, requested) || module.path == requested;
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

template <typename UInt>
[[nodiscard]] bool matches_modular_integer_delta(
    const std::uint64_t old_raw,
    const std::uint64_t new_raw,
    const std::uint64_t delta_raw,
    const bool increase
) noexcept {
    static_assert(std::is_unsigned_v<UInt>);
    const auto old_value = static_cast<UInt>(old_raw);
    const auto delta_value = static_cast<UInt>(delta_raw);
    const auto expected = static_cast<UInt>(
        increase
            ? static_cast<std::uint64_t>(old_value) + static_cast<std::uint64_t>(delta_value)
            : static_cast<std::uint64_t>(old_value) - static_cast<std::uint64_t>(delta_value)
    );
    return expected == static_cast<UInt>(new_raw);
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
    // Delta comparisons use the stored N-bit representation. Unsigned
    // arithmetic makes the intended two's-complement modulo-2^N behavior
    // explicit for both signed and unsigned scan types, including extrema.
    case domain::ScanValueType::u8:
    case domain::ScanValueType::i8:
        return matches_modular_integer_delta<std::uint8_t>(old_raw, new_raw, delta_raw, increase);
    case domain::ScanValueType::u16:
    case domain::ScanValueType::i16:
        return matches_modular_integer_delta<std::uint16_t>(old_raw, new_raw, delta_raw, increase);
    case domain::ScanValueType::u32:
    case domain::ScanValueType::i32:
        return matches_modular_integer_delta<std::uint32_t>(old_raw, new_raw, delta_raw, increase);
    case domain::ScanValueType::u64:
    case domain::ScanValueType::i64:
        return matches_modular_integer_delta<std::uint64_t>(old_raw, new_raw, delta_raw, increase);
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

[[nodiscard]] domain::Result<ScanResult> scan_pattern_over_regions(
    const domain::ProcessSession& session,
    const std::span<const domain::MemoryRegion> regions,
    const std::span<const std::byte> pattern,
    const std::size_t alignment,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) {
    constexpr std::size_t chunk_size = 64U * 1024U;
    ScanResult result;
    result.matches.reserve(result_limit);
    std::array<std::byte, chunk_size> chunk{};
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + pattern.size());
    std::vector<std::byte> carry;
    carry.reserve(pattern.size() - 1U);

    for (const auto& region : regions) {
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
        carry.clear();
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
            auto read = session.read(cursor, std::span<std::byte>{chunk}.first(request));
            if (!read || *read == 0U) {
                break;
            }
            if (*read > request) {
                return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
            }
            result.bytes_scanned += *read;

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*read));
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());

            if (buffer.size() >= pattern.size()) {
                const auto misalignment = static_cast<std::size_t>(buffer_base & (alignment - 1U));
                std::size_t index = (alignment - misalignment) & (alignment - 1U);
                for (; index + pattern.size() <= buffer.size(); index += alignment) {
                    const domain::Address candidate = buffer_base + static_cast<domain::Address>(index);
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
            cursor += static_cast<domain::Address>(*read);
        }
        if (result.bytes_scanned >= byte_budget) {
            result.truncated = true;
            break;
        }
    }
    return result;
}

// Reverse-pointer BFS needs to find references to every address in the current
// frontier. Scanning once per address multiplies process I/O by fanout and can
// consume the entire shared budget before the second hop. This variant decodes
// each aligned pointer once and tests it against the whole frontier.
[[nodiscard]] domain::Result<ScanResult> scan_pointer_frontier_over_regions(
    const domain::ProcessSession& session,
    const std::span<const domain::MemoryRegion> regions,
    const std::span<const domain::Address> frontier,
    const std::size_t pointer_size,
    const std::size_t byte_budget,
    const std::size_t result_limit,
    const bool writable_only,
    const std::optional<domain::Address> start_address,
    const std::optional<domain::Address> end_address,
    const std::stop_token cancellation
) {
    constexpr std::size_t chunk_size = 64U * 1024U;
    std::unordered_set<domain::Address> targets;
    targets.reserve(frontier.size());
    for (const auto address : frontier) {
        if (pointer_size == 8U || address <= std::numeric_limits<std::uint32_t>::max()) {
            targets.insert(address);
        }
    }

    ScanResult result;
    if (targets.empty()) {
        return result;
    }

    std::array<std::byte, chunk_size> chunk{};
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + pointer_size - 1U);
    std::vector<std::byte> carry;
    carry.reserve(pointer_size - 1U);

    for (const auto& region : regions) {
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
        carry.clear();
        while (cursor < scan_end && result.bytes_scanned < byte_budget) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
            }
            const auto request_u64 = std::min<std::uint64_t>({
                scan_end - cursor,
                static_cast<std::uint64_t>(byte_budget - result.bytes_scanned),
                static_cast<std::uint64_t>(chunk_size)
            });
            const auto request = static_cast<std::size_t>(request_u64);
            if (request == 0U) {
                break;
            }
            auto read = session.read(cursor, std::span<std::byte>{chunk}.first(request));
            if (!read || *read == 0U) {
                break;
            }
            if (*read > request) {
                return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
            }
            result.bytes_scanned += *read;

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*read));
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());
            const auto misalignment = static_cast<std::size_t>(buffer_base & (pointer_size - 1U));
            std::size_t index = (pointer_size - misalignment) & (pointer_size - 1U);
            for (; index + pointer_size <= buffer.size(); index += pointer_size) {
                const std::span<const std::byte> encoded{buffer.data() + index, pointer_size};
                if (!targets.contains(decode_pointer(encoded))) {
                    continue;
                }
                result.matches.push_back(domain::ScanMatch{
                    buffer_base + static_cast<domain::Address>(index)
                });
                if (result.matches.size() >= result_limit) {
                    result.truncated = true;
                    return result;
                }
            }

            const auto carry_size = std::min(pointer_size - 1U, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size), buffer.end());
            cursor += static_cast<domain::Address>(*read);
        }
        if (result.bytes_scanned >= byte_budget) {
            result.truncated = true;
            break;
        }
    }
    return result;
}

}  // namespace

MemoryDebugService::MemoryDebugService(
    std::unique_ptr<domain::ProcessMemoryProvider> provider,
    security::SecurityPolicy policy,
    std::unique_ptr<domain::TypeMetadataProvider> metadata_provider
) : provider_(std::move(provider)), metadata_provider_(std::move(metadata_provider)), policy_(policy) {
    std::random_device device;
    resume_key_ = (static_cast<std::uint64_t>(device()) << 32U) ^ static_cast<std::uint64_t>(device());
    // A zero key would make every token forgeable by anyone who knows the
    // format, so refuse to start with one rather than degrade quietly.
    if (resume_key_ == 0U) {
        resume_key_ = 0x9E3779B97F4A7C15ULL;
    }
}

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
    // Runtime contexts die with the session that authorized them: an id left
    // behind would outlive the authorization it was built under.
    unreal_contexts_.remove_owned_by(id);
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

domain::Result<domain::RegionPage> MemoryDebugService::regions_page(
    const domain::SessionId& id,
    const domain::RegionFilter& filter,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || limit > 4096U) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "limit must be between 1 and 4096"
        ));
    }
    if (filter.start_address && filter.end_address && *filter.end_address <= *filter.start_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "end_address must be greater than start_address"
        ));
    }
    if (filter.max_size && *filter.max_size < filter.min_size) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "max_size must be greater than or equal to min_size"
        ));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto all = (*session)->regions();
    if (!all) {
        return std::unexpected(all.error());
    }
    return domain::filter_regions(*all, filter, offset, limit);
}

domain::Result<domain::AddressSpaceSummary> MemoryDebugService::address_space_summary(
    const domain::SessionId& id
) const {
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto all = (*session)->regions();
    if (!all) {
        return std::unexpected(all.error());
    }
    return domain::summarize_address_space(*all);
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
    if (*read > output.size()) {
        return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
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
        if (item.size == 0U) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "batch read size must be positive"));
        }
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
    std::vector<BatchReadResult> output(items.size());
    for (std::size_t index = 0; index < items.size(); ++index) {
        output[index].address = items[index].address;
    }

    const auto read_one = [&](const std::size_t index) {
        const auto& item = items[index];
        auto& result = output[index];
        result.bytes.resize(item.size);
        auto read = (*session)->read(item.address, result.bytes);
        if (read) {
            if (*read <= item.size) {
                result.bytes.resize(*read);
                result.success = true;
            } else {
                result.bytes.clear();
                result.error = "memory backend returned an oversized read";
            }
        } else {
            result.bytes.clear();
            result.error = read.error().safe_message;
        }
    };

    std::vector<std::size_t> order(items.size());
    for (std::size_t index = 0; index < order.size(); ++index) {
        order[index] = index;
    }
    std::ranges::sort(order, [&](const std::size_t left, const std::size_t right) {
        if (items[left].address != items[right].address) {
            return items[left].address < items[right].address;
        }
        return items[left].size < items[right].size;
    });

    // Merge only adjacent or overlapping requests. No unrequested gap is read,
    // output order stays identical to the input, and a failed/short coalesced
    // read falls back to the previous per-item behavior.
    std::size_t run_begin = 0U;
    while (run_begin < order.size()) {
        const auto first_index = order[run_begin];
        const auto& first = items[first_index];
        if (first.size > std::numeric_limits<domain::Address>::max() - first.address) {
            read_one(first_index);
            ++run_begin;
            continue;
        }

        const domain::Address run_address = first.address;
        domain::Address run_end_address = first.address + static_cast<domain::Address>(first.size);
        std::size_t run_end = run_begin + 1U;
        while (run_end < order.size()) {
            const auto next_index = order[run_end];
            const auto& next = items[next_index];
            if (next.size > std::numeric_limits<domain::Address>::max() - next.address ||
                next.address > run_end_address) {
                break;
            }
            run_end_address = std::max(
                run_end_address, next.address + static_cast<domain::Address>(next.size)
            );
            ++run_end;
        }

        if (run_end == run_begin + 1U) {
            read_one(first_index);
            run_begin = run_end;
            continue;
        }

        const auto run_size = static_cast<std::size_t>(run_end_address - run_address);
        std::vector<std::byte> run_bytes(run_size);
        auto read = (*session)->read(run_address, run_bytes);
        if (!read || *read != run_size) {
            for (std::size_t position = run_begin; position < run_end; ++position) {
                read_one(order[position]);
            }
            run_begin = run_end;
            continue;
        }

        for (std::size_t position = run_begin; position < run_end; ++position) {
            const auto index = order[position];
            const auto& item = items[index];
            auto& result = output[index];
            const auto offset = static_cast<std::size_t>(item.address - run_address);
            result.bytes.assign(
                run_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                run_bytes.begin() + static_cast<std::ptrdiff_t>(offset + item.size)
            );
            result.success = true;
        }
        run_begin = run_end;
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
    if (pointer_size == 4U && target > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "target_address does not fit in a 32-bit pointer"
        ));
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
    return scan_pattern_over_regions(
        **session, *region_result, pattern, alignment, byte_budget, result_limit, writable_only,
        start_address, end_address, cancellation
    );
}

domain::Result<PointerChainScanResult> MemoryDebugService::scan_pointer_chains(
    const domain::SessionId& id,
    const domain::Address target,
    const std::size_t pointer_size,
    const std::size_t max_depth,
    const std::size_t max_fanout,
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
    if (pointer_size == 4U && target > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "target_address does not fit in a 32-bit pointer"
        ));
    }
    if (start_address && end_address && *end_address <= *start_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "end_address must be greater than start_address"
        ));
    }
    auto authorization = policy_.authorize_pointer_chain_scan(byte_budget, result_limit, max_depth, max_fanout);
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
    auto module_result = (*session)->modules();
    if (!module_result) {
        return std::unexpected(module_result.error());
    }

    const auto find_owning_module = [&module_result](const domain::Address address) -> const domain::ModuleInfo* {
        const auto module = std::find_if(
            module_result->begin(), module_result->end(),
            [address](const domain::ModuleInfo& candidate) {
                return candidate.size != 0U && candidate.base <= address && address - candidate.base < candidate.size;
            }
        );
        return module == module_result->end() ? nullptr : &(*module);
    };

    if (find_owning_module(target) != nullptr) {
        return PointerChainScanResult{};
    }

    PointerChainScanResult result;
    std::size_t total_bytes = 0;
    std::unordered_set<domain::Address> visited{target};
    std::vector<domain::Address> frontier{target};

    for (std::size_t depth = 1; depth <= max_depth; ++depth) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
        }
        if (frontier.size() > max_fanout) {
            frontier.resize(max_fanout);
            result.truncated = true;
        }
        if (total_bytes >= byte_budget) {
            result.truncated = true;
            break;
        }
        const auto remaining_depths = max_depth - depth + 1U;
        const auto remaining_budget = byte_budget - total_bytes;
        const auto level_budget = std::max<std::size_t>(1U, remaining_budget / remaining_depths);
        auto partial = scan_pointer_frontier_over_regions(
            **session, *region_result, frontier, pointer_size, level_budget, max_fanout,
            writable_only, start_address, end_address, cancellation
        );
        if (!partial) {
            return std::unexpected(partial.error());
        }
        total_bytes += partial->bytes_scanned;
        result.truncated = result.truncated || partial->truncated;

        std::vector<domain::Address> next_frontier;
        next_frontier.reserve(partial->matches.size());
        bool result_limit_reached = false;
        for (const auto& match : partial->matches) {
            if (!visited.insert(match.address).second) {
                continue;
            }
            const auto* owning = find_owning_module(match.address);
            if (owning == nullptr) {
                next_frontier.push_back(match.address);
                continue;
            }
            std::vector<std::int64_t> hop_offsets(depth, 0);
            hop_offsets.front() = static_cast<std::int64_t>(match.address - owning->base);
            auto resolved = resolve_pointer_chain(id, owning->base, hop_offsets, pointer_size);
            if (!resolved) {
                continue;
            }
            result.candidates.push_back(PointerChainCandidate{
                owning->name, owning->base, std::move(hop_offsets), *resolved
            });
            if (result.candidates.size() >= result_limit) {
                result.truncated = true;
                result_limit_reached = true;
                break;
            }
        }
        if (result_limit_reached) {
            break;
        }
        if (next_frontier.empty()) {
            break;
        }
        if (depth == max_depth && !next_frontier.empty()) {
            result.truncated = true;
        }
        frontier = std::move(next_frontier);
    }

    result.bytes_scanned = total_bytes;
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
    result.matches.reserve(result_limit);
    std::array<std::byte, chunk_size> chunk{};
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + unit - 1U);
    std::vector<std::byte> carry;
    carry.reserve(unit - 1U);

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
        carry.clear();

        bool in_run = false;
        domain::Address run_start = 0;
        std::uint64_t run_length = 0;
        std::string run_text;
        run_text.reserve(policy_.max_string_result_length);
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
            auto read = (*session)->read(cursor, std::span<std::byte>{chunk}.first(request));
            if (!read || *read == 0U) {
                break;
            }
            if (*read > request) {
                return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
            }
            result.bytes_scanned += *read;

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*read));
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
            cursor += static_cast<domain::Address>(*read);
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

domain::Result<MemoryDebugService::ScanFirstResult> MemoryDebugService::scan_first(
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
    if (value_size == 0U || value_size > ScanCandidate::max_value_size) {
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

    // Measured before the sweep so the caller can tell a conclusive empty
    // result from one that merely exhausted the budget.
    const auto [bytes_eligible, regions_eligible] =
        domain::eligible_scan_bytes(*region_result, writable_only, start_address, end_address);
    const auto bounded_scan_bytes =
        std::min<std::uint64_t>(bytes_eligible, static_cast<std::uint64_t>(byte_budget));
    const auto candidates_by_bytes = bounded_scan_bytes == std::numeric_limits<std::uint64_t>::max()
        ? bounded_scan_bytes
        : bounded_scan_bytes / value_size + 1U;
    const auto candidate_upper_bound = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(result_limit), candidates_by_bytes
    );
    const auto reserve_count = comparison == domain::ScanComparison::unknown
        ? candidate_upper_bound
        : std::min<std::uint64_t>(candidate_upper_bound, chunk_size / value_size);
    candidates.reserve(static_cast<std::size_t>(reserve_count));

    // Reuse the scan buffers for the whole sweep. The old implementation
    // allocated both vectors for every 64 KiB read and tested every byte with
    // a modulo operation even though only naturally aligned addresses qualify.
    std::array<std::byte, chunk_size> chunk{};
    std::vector<std::byte> carry;
    carry.reserve(value_size - 1U);
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + value_size - 1U);
    std::size_t regions_scanned = 0;

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
        if (bytes_scanned >= byte_budget) {
            break;
        }
        ++regions_scanned;
        domain::Address cursor = scan_start;
        carry.clear();
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
            auto read = (*session)->read(cursor, std::span<std::byte>{chunk.data(), request});
            if (!read || *read == 0U) {
                break;
            }
            if (*read > request) {
                return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
            }
            bytes_scanned += *read;

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*read));
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());

            if (buffer.size() >= value_size) {
                const auto alignment_mask = static_cast<domain::Address>(value_size - 1U);
                std::size_t index = static_cast<std::size_t>(
                    (static_cast<domain::Address>(value_size) - (buffer_base & alignment_mask)) & alignment_mask
                );
                for (; index + value_size <= buffer.size(); index += value_size) {
                    const domain::Address candidate_address = buffer_base + static_cast<domain::Address>(index);
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
                        candidates.emplace_back(candidate_address, window);
                        if (candidates.size() >= result_limit) {
                            truncated_by_limit = true;
                            break;
                        }
                    }
                }
            }

            const std::size_t carry_size = std::min(value_size - 1U, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size), buffer.end());
            cursor += static_cast<domain::Address>(*read);
        }
    }

    domain::ScanCoverage coverage{};
    coverage.bytes_scanned = static_cast<std::uint64_t>(bytes_scanned);
    coverage.bytes_eligible = bytes_eligible;
    coverage.regions_scanned = regions_scanned;
    coverage.regions_eligible = regions_eligible;
    coverage.truncated_by_result_limit = truncated_by_limit;
    // Only the budget being the binding constraint counts as budget truncation.
    // A short sweep caused by an unreadable region shows up as a coverage_ratio
    // below 1.0 instead of as a false budget flag.
    coverage.truncated_by_budget = bytes_scanned >= byte_budget &&
        static_cast<std::uint64_t>(bytes_scanned) < bytes_eligible;

    auto info = scan_sessions_.create(
        id, value_type, std::move(candidates), policy_.max_scan_sessions_per_session
    );
    if (!info) {
        return std::unexpected(info.error());
    }
    return ScanFirstResult{std::move(*info), coverage};
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
    const auto value_type = snapshot->value_type();
    const auto candidates = snapshot->candidates();
    const auto value_size = domain::scan_value_size(value_type);
    if (value_size == 0U || value_size > ScanCandidate::max_value_size) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "scan session has an unsupported value_type"));
    }
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

    auto session = sessions_.get(snapshot->owner());
    if (!session) {
        return std::unexpected(session.error());
    }

    std::vector<ScanCandidate> survivors;
    survivors.reserve(candidates.size());

    const auto retain_if_matching = [&](const ScanCandidate& candidate, const std::span<const std::byte> bytes) {
        const auto previous_value = candidate.value_bytes(value_size);
        bool matches = false;
        switch (comparison) {
        case domain::ScanComparison::exact:
            matches = std::equal(bytes.begin(), bytes.end(), value->begin());
            break;
        case domain::ScanComparison::changed:
            matches = !std::equal(bytes.begin(), bytes.end(), previous_value.begin());
            break;
        case domain::ScanComparison::unchanged:
            matches = std::equal(bytes.begin(), bytes.end(), previous_value.begin());
            break;
        case domain::ScanComparison::increased:
            matches = compare_scan_values(value_type, bytes, previous_value) == Ordering::greater;
            break;
        case domain::ScanComparison::decreased:
            matches = compare_scan_values(value_type, bytes, previous_value) == Ordering::less;
            break;
        case domain::ScanComparison::increased_by:
            matches = matches_delta(value_type, previous_value, bytes, *delta, true);
            break;
        case domain::ScanComparison::decreased_by:
            matches = matches_delta(value_type, previous_value, bytes, *delta, false);
            break;
        default:
            break;
        }
        if (matches) {
            survivors.emplace_back(candidate.address, bytes);
        }
    };

    // scan_first emits candidates in ascending address order and scan_next
    // preserves that order. Read strictly contiguous candidates as one bounded
    // run instead of issuing one native syscall per value. A failed/short run
    // falls back to individual reads for the unread suffix, preserving the
    // previous soft-skip behavior for inaccessible candidates.
    const std::size_t max_candidates_per_run = policy_.max_read_bytes / value_size;
    std::vector<std::byte> run_buffer;
    if (max_candidates_per_run > 1U) {
        run_buffer.reserve(max_candidates_per_run * value_size);
    }
    std::array<std::byte, 8> single_buffer{};

    std::size_t run_begin = 0U;
    while (run_begin < candidates.size()) {
        if (cancellation.stop_requested()) {
            return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
        }

        std::size_t run_end = run_begin + 1U;
        while (max_candidates_per_run > 1U && run_end < candidates.size() &&
               run_end - run_begin < max_candidates_per_run) {
            const auto previous_address = candidates[run_end - 1U].address;
            if (previous_address > std::numeric_limits<domain::Address>::max() - value_size ||
                candidates[run_end].address != previous_address + value_size) {
                break;
            }
            ++run_end;
        }

        const std::size_t run_count = run_end - run_begin;
        if (run_count == 1U) {
            const auto bytes = std::span<std::byte>{single_buffer}.first(value_size);
            auto read = (*session)->read(candidates[run_begin].address, bytes);
            if (read && *read > value_size) {
                return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
            }
            if (read && *read == value_size) {
                retain_if_matching(candidates[run_begin], bytes);
            }
            run_begin = run_end;
            continue;
        }

        const std::size_t run_size = run_count * value_size;
        run_buffer.resize(run_size);
        auto run_read = (*session)->read(candidates[run_begin].address, run_buffer);
        if (run_read && *run_read > run_size) {
            return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
        }
        const std::size_t complete_prefix = run_read
            ? std::min(run_count, *run_read / value_size)
            : 0U;

        for (std::size_t index = 0U; index < complete_prefix; ++index) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
            }
            retain_if_matching(
                candidates[run_begin + index],
                std::span<const std::byte>{run_buffer}.subspan(index * value_size, value_size)
            );
        }

        if (!run_read || *run_read < run_size) {
            for (std::size_t index = complete_prefix; index < run_count; ++index) {
                if (cancellation.stop_requested()) {
                    return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
                }
                const auto bytes = std::span<std::byte>{single_buffer}.first(value_size);
                auto read = (*session)->read(candidates[run_begin + index].address, bytes);
                if (read && *read > value_size) {
                    return std::unexpected(error(domain::DebugErrorCode::io_error, "memory backend returned an oversized read"));
                }
                if (read && *read == value_size) {
                    retain_if_matching(candidates[run_begin + index], bytes);
                }
            }
        }
        run_begin = run_end;
    }

    return scan_sessions_.replace(scan_id, *snapshot, std::move(survivors));
}

domain::Result<domain::ScanValueType> MemoryDebugService::scan_value_type(
    const domain::ScanSessionId& scan_id
) const {
    auto snapshot = scan_sessions_.snapshot(scan_id);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    return snapshot->value_type();
}

domain::Result<std::vector<domain::ScanMatch>> MemoryDebugService::scan_results(
    const domain::ScanSessionId& scan_id,
    const std::size_t offset,
    const std::size_t limit
) const {
    auto page = scan_results_page(scan_id, offset, limit);
    if (!page) {
        return std::unexpected(page.error());
    }
    return std::move(page->matches);
}

domain::Result<ScanResultsPage> MemoryDebugService::scan_results_page(
    const domain::ScanSessionId& scan_id,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || limit > 4096U) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "limit must be between 1 and 4096"));
    }
    auto snapshot = scan_sessions_.snapshot(scan_id);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    const auto candidates = snapshot->candidates();
    std::vector<domain::ScanMatch> matches;
    if (offset < candidates.size()) {
        const auto count = std::min(limit, candidates.size() - offset);
        matches.reserve(count);
        for (std::size_t index = offset; index < offset + count; ++index) {
            matches.push_back(domain::ScanMatch{candidates[index].address});
        }
    }
    const bool truncated = offset < candidates.size() && matches.size() < candidates.size() - offset;
    return ScanResultsPage{
        domain::ScanSessionInfo{
            scan_id,
            snapshot->owner(),
            snapshot->value_type(),
            candidates.size(),
            snapshot->generation()
        },
        offset,
        std::move(matches),
        truncated
    };
}

domain::Result<void> MemoryDebugService::scan_reset(const domain::ScanSessionId& scan_id) {
    auto result = scan_sessions_.reset(scan_id);
    if (!result) {
        return std::unexpected(result.error());
    }
    return {};
}

std::string_view to_string(const ReferenceTruncation reason) noexcept {
    switch (reason) {
        case ReferenceTruncation::byte_budget_exhausted: return "byte_budget_exhausted";
        case ReferenceTruncation::result_limit_reached: return "result_limit_reached";
        case ReferenceTruncation::region_read_failed: return "region_read_failed";
    }
    return "unknown";
}

domain::Result<ReferenceReport> MemoryDebugService::scan_references(
    const domain::SessionId& id,
    const domain::ProcessSession& session,
    const std::span<const domain::MemoryRegion> sorted_regions,
    const domain::Address target,
    const domain::TargetPointerWidth width,
    const ReferenceQuery& query,
    const std::stop_token cancellation
) const {
    const auto pointer_size = domain::pointer_width_bytes(width);
    if (target == 0U) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "reference target must not be zero"
        ));
    }
    if (width == domain::TargetPointerWidth::x86 && target > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "address does not fit in a 32-bit pointer"
        ));
    }
    if (query.start_address && query.end_address && *query.end_address <= *query.start_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "end_address must be greater than start_address"
        ));
    }
    auto authorization = policy_.authorize_scan(query.byte_budget, query.result_limit);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }

    const auto binding = domain::resume_token::binding(
        id.value(), target, width, query.writable_only, query.start_address, query.end_address
    );
    std::optional<domain::Address> range_start = query.start_address;
    if (!query.resume_token.empty()) {
        const auto resumed = domain::resume_token::decode(query.resume_token, resume_key_, binding);
        if (!resumed) {
            // A token that does not verify may belong to another session, target
            // or filter set. Continuing anyway would silently sweep a different
            // range than the caller believes it is resuming.
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument,
                "resume_token does not belong to this session and query"
            ));
        }
        range_start = std::max(*resumed, query.start_address.value_or(0U));
    }

    // Measured over the range this slice may still sweep, so `complete` means
    // "reached the end of what was left", not "reached the end of the process".
    const auto [bytes_eligible, regions_eligible] = domain::eligible_scan_bytes(
        sorted_regions, query.writable_only, range_start, query.end_address
    );

    std::array<std::byte, 8> needle{};
    for (std::size_t index = 0; index < pointer_size; ++index) {
        needle[index] = static_cast<std::byte>((target >> (index * 8U)) & 0xFFU);
    }

    constexpr std::size_t chunk_size = 64U * 1024U;
    std::array<std::byte, chunk_size> chunk{};
    std::vector<std::byte> buffer;
    buffer.reserve(chunk_size + pointer_size);
    std::vector<std::byte> carry;
    carry.reserve(pointer_size - 1U);

    std::vector<domain::Address> matches;
    matches.reserve(std::min<std::size_t>(query.result_limit, 64U));
    std::uint64_t bytes_scanned = 0;
    std::size_t regions_scanned = 0;
    std::optional<domain::Address> next_address;
    bool budget_exhausted = false;
    bool limit_reached = false;
    bool read_failed = false;
    bool stop = false;

    for (const auto& region : sorted_regions) {
        if (stop) {
            break;
        }
        if (cancellation.stop_requested()) {
            return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
        }
        if (!region.readable || (query.writable_only && !region.writable) || region.size() == 0U) {
            continue;
        }
        const domain::Address scan_start = std::max(region.start, range_start.value_or(region.start));
        const domain::Address scan_end = std::min(region.end, query.end_address.value_or(region.end));
        if (scan_end <= scan_start) {
            continue;
        }
        ++regions_scanned;
        domain::Address cursor = scan_start;
        carry.clear();
        while (cursor < scan_end) {
            if (cancellation.stop_requested()) {
                return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
            }
            if (bytes_scanned >= query.byte_budget) {
                budget_exhausted = true;
                // Resume at the aligned position at or below the cursor: any
                // pointer that started earlier was already fully read, and any
                // pointer straddling the cursor gets a complete second look.
                next_address = cursor & ~static_cast<domain::Address>(pointer_size - 1U);
                stop = true;
                break;
            }
            const auto request_u64 = std::min<std::uint64_t>({
                scan_end - cursor,
                query.byte_budget - bytes_scanned,
                static_cast<std::uint64_t>(chunk_size)
            });
            const auto request = static_cast<std::size_t>(request_u64);
            if (request == 0U) {
                break;
            }
            auto read = session.read(cursor, std::span<std::byte>{chunk}.first(request));
            if (!read || *read == 0U) {
                // Skip the remainder of this region instead of retrying: the
                // sweep stays bounded and the gap shows up as coverage below 1.
                read_failed = true;
                break;
            }
            if (*read > request) {
                return std::unexpected(error(
                    domain::DebugErrorCode::io_error, "memory backend returned an oversized read"
                ));
            }
            bytes_scanned += *read;

            buffer.clear();
            buffer.insert(buffer.end(), carry.begin(), carry.end());
            buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*read));
            const domain::Address buffer_base = cursor - static_cast<domain::Address>(carry.size());
            const auto misalignment = static_cast<std::size_t>(buffer_base & (pointer_size - 1U));
            std::size_t index = (pointer_size - misalignment) & (pointer_size - 1U);
            for (; index + pointer_size <= buffer.size(); index += pointer_size) {
                if (!std::equal(needle.begin(), needle.begin() + static_cast<std::ptrdiff_t>(pointer_size),
                                buffer.begin() + static_cast<std::ptrdiff_t>(index))) {
                    continue;
                }
                const auto match = buffer_base + static_cast<domain::Address>(index);
                matches.push_back(match);
                if (matches.size() >= query.result_limit) {
                    limit_reached = true;
                    next_address = match + pointer_size;
                    stop = true;
                    break;
                }
            }
            if (stop) {
                break;
            }
            const auto carry_size = std::min(pointer_size - 1U, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size), buffer.end());
            cursor += static_cast<domain::Address>(*read);
        }
    }

    ReferenceReport report;
    report.mode = ReferenceMode::live_scan;
    report.budget = ReferenceBudget{
        static_cast<std::uint64_t>(query.byte_budget), query.result_limit, "live_scan"
    };
    report.matches = std::move(matches);
    report.coverage.bytes_scanned = bytes_scanned;
    report.coverage.bytes_eligible = bytes_eligible;
    report.coverage.regions_scanned = regions_scanned;
    report.coverage.regions_eligible = regions_eligible;
    report.coverage.truncated_by_budget = budget_exhausted;
    report.coverage.truncated_by_result_limit = limit_reached;
    if (budget_exhausted) report.truncation_reasons.push_back(ReferenceTruncation::byte_budget_exhausted);
    if (limit_reached) report.truncation_reasons.push_back(ReferenceTruncation::result_limit_reached);
    if (read_failed) report.truncation_reasons.push_back(ReferenceTruncation::region_read_failed);
    if (next_address) {
        report.resume_token = domain::resume_token::encode(resume_key_, binding, *next_address);
        report.next_start_address = next_address;
    }
    return report;
}

domain::Result<AddressInspection> MemoryDebugService::inspect_address(
    const domain::SessionId& id,
    const AddressInspectionRequest& request,
    const std::stop_token cancellation
) const {
    // Everything that can be rejected without touching the target is rejected
    // here, before a single byte is allocated or read.
    auto authorization = policy_.authorize_inspection(request.limits);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    if (request.pointer_width == domain::TargetPointerWidth::x86 &&
        request.address > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "address does not fit in a 32-bit pointer"
        ));
    }
    if (request.references.mode == ReferenceMode::index) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported,
            "reference mode index requires the persistent pointer index, which is not implemented"
        ));
    }

    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    // One snapshot of each map per inspection: nothing below re-enumerates them
    // per candidate.
    auto region_result = (*session)->regions();
    if (!region_result) {
        return std::unexpected(region_result.error());
    }
    auto module_result = (*session)->modules();
    if (!module_result) {
        return std::unexpected(module_result.error());
    }
    const auto regions = domain::RegionIndex::create(*region_result);
    const auto modules = domain::ModuleIndex::create(*module_result);
    const auto pointer_size = domain::pointer_width_bytes(request.pointer_width);
    const auto& limits = request.limits;

    AddressInspection inspection;
    inspection.address = request.address;
    inspection.pointer_width = request.pointer_width;
    inspection.sampled_at_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    inspection.analysis.lookbehind_bytes_requested = limits.lookbehind_bytes;

    const auto note = [&inspection, &limits](
        const domain::InspectionLimitation limitation,
        const bool degrades_analysis
    ) {
        if (inspection.analysis.limitations.size() < limits.max_limitations) {
            inspection.analysis.limitations.push_back(limitation);
        }
        if (degrades_analysis) {
            inspection.analysis.complete = false;
        }
    };

    const auto* region = regions.find(request.address);
    if (region != nullptr) {
        inspection.region = *region;
    }
    if (const auto owner = modules.reference(request.address)) {
        const auto* module = modules.at(owner->module_index);
        if (module != nullptr) {
            inspection.module = InspectedModule{module->name, module->base, owner->rva};
        }
    }

    if (region == nullptr) {
        note(domain::InspectionLimitation::address_not_mapped, true);
    } else if (!region->readable) {
        // No speculative read: an unreadable mapping is an answer, not a reason
        // to try anyway.
        note(domain::InspectionLimitation::region_not_readable, true);
    } else {
        auto window = domain::compute_lookbehind_window(
            request.address, request.pointer_width, limits.lookbehind_bytes, *region
        );
        if (!window) {
            note(domain::InspectionLimitation::region_not_readable, true);
        } else {
            if (window->clamped_by_region) {
                note(domain::InspectionLimitation::lookbehind_clamped_to_region, true);
            }
            std::vector<std::byte> sample(static_cast<std::size_t>(window->size()));
            auto read = (*session)->read(window->start, sample);
            if (!read || *read == 0U) {
                note(domain::InspectionLimitation::lookbehind_short_read, true);
            } else if (*read > sample.size()) {
                return std::unexpected(error(
                    domain::DebugErrorCode::io_error, "memory backend returned an oversized read"
                ));
            } else {
                if (*read < sample.size()) {
                    // Never zero-filled: the missing tail simply removes the
                    // bases it would have covered.
                    note(domain::InspectionLimitation::lookbehind_short_read, true);
                    sample.resize(*read);
                }
                inspection.analysis.lookbehind_bytes_read = static_cast<std::uint64_t>(sample.size());

                const auto bases = domain::collect_base_candidates(
                    request.address, request.pointer_width, window->start, sample, regions, modules, limits
                );
                if (bases.base_limit_reached) {
                    note(domain::InspectionLimitation::base_scan_limit_reached, true);
                }
                if (bases.probe_limit_reached) {
                    note(domain::InspectionLimitation::vtable_probe_limit_reached, true);
                }

                const auto probe_bytes = limits.vtable_entries * pointer_size;
                std::vector<std::byte> probe_buffer(probe_bytes);
                std::vector<domain::VtableProbe> probes;
                probes.reserve(bases.bases.size());
                // Distinct bases frequently store the same vptr; reading it once
                // keeps the probe budget meaningful.
                std::vector<std::pair<domain::Address, std::size_t>> probed;
                probed.reserve(bases.bases.size());

                for (const auto& base : bases.bases) {
                    if (cancellation.stop_requested()) {
                        return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled"));
                    }
                    const auto cached = std::ranges::find(probed, base.vtable_address, &std::pair<domain::Address, std::size_t>::first);
                    if (cached != probed.end()) {
                        auto reused = probes[cached->second];
                        probes.push_back(std::move(reused));
                        continue;
                    }

                    domain::VtableProbe probe;
                    probe.vtable_address = base.vtable_address;
                    probe.requested_entries = static_cast<std::uint32_t>(limits.vtable_entries);
                    const auto* vtable_region = regions.find(base.vtable_address);
                    const std::uint64_t available = vtable_region == nullptr
                        ? 0U
                        : vtable_region->end - base.vtable_address;
                    const auto want = static_cast<std::size_t>(
                        std::min<std::uint64_t>(static_cast<std::uint64_t>(probe_bytes), available)
                    );
                    ++inspection.analysis.vtable_probes_attempted;
                    if (want >= pointer_size) {
                        auto probe_read = (*session)->read(
                            base.vtable_address, std::span<std::byte>{probe_buffer}.first(want)
                        );
                        if (probe_read && *probe_read >= pointer_size && *probe_read <= want) {
                            const auto complete_entries = *probe_read / pointer_size;
                            probe.entries.reserve(complete_entries);
                            for (std::size_t entry = 0; entry < complete_entries; ++entry) {
                                probe.entries.push_back(domain::decode_target_pointer(
                                    std::span<const std::byte>{probe_buffer}.subspan(entry * pointer_size, pointer_size),
                                    request.pointer_width
                                ));
                            }
                            if (complete_entries == limits.vtable_entries) {
                                ++inspection.analysis.vtable_probes_complete;
                            }
                        }
                    }
                    probe.short_read = probe.entries.size() < limits.vtable_entries;
                    probed.emplace_back(base.vtable_address, probes.size());
                    probes.push_back(std::move(probe));
                }

                auto classified = domain::classify_object_candidates(
                    bases.bases, probes, regions, modules, limits
                );
                if (classified.short_vtable_read) {
                    note(domain::InspectionLimitation::vtable_short_read, true);
                }
                if (classified.truncated) {
                    note(domain::InspectionLimitation::candidate_limit_reached, true);
                }
                inspection.candidates_total = classified.candidates_total;
                inspection.candidates_truncated = classified.truncated;
                inspection.candidates.reserve(classified.candidates.size());
                for (auto& candidate : classified.candidates) {
                    InspectedCandidate resolved;
                    resolved.object_address = candidate.object_address;
                    resolved.field_offset = candidate.field_offset;
                    resolved.vtable.address = candidate.vtable_address;
                    if (candidate.vtable_module) {
                        const auto* module = modules.at(candidate.vtable_module->module_index);
                        if (module != nullptr) {
                            resolved.vtable.module = InspectedModule{
                                module->name, module->base, candidate.vtable_module->rva
                            };
                        }
                    }
                    resolved.confidence = candidate.confidence;
                    resolved.evidence = std::move(candidate.evidence);
                    resolved.provenance = std::move(candidate.provenance);
                    inspection.candidates.push_back(std::move(resolved));
                }
            }
        }
    }

    if (request.references.mode == ReferenceMode::live_scan) {
        auto references = scan_references(
            id, **session, regions.all(), request.address, request.pointer_width,
            request.references, cancellation
        );
        if (!references) {
            return std::unexpected(references.error());
        }
        if (!references->coverage.complete()) {
            // The references block already carries its own coverage; the
            // limitation only makes the whole answer auditable from one place.
            note(domain::InspectionLimitation::references_incomplete, false);
        }
        inspection.references = std::move(*references);
    }

    return inspection;
}

domain::RuntimeLimits MemoryDebugService::runtime_limits() const {
    domain::RuntimeLimits limits;
    limits.max_slots_visited = policy_.max_unreal_slots_visited;
    limits.max_objects_stored = policy_.max_unreal_objects_stored;
    limits.max_classes_stored = policy_.max_unreal_classes_stored;
    limits.max_properties_per_type = policy_.max_unreal_properties_per_type;
    limits.max_super_depth = policy_.max_unreal_super_depth;
    limits.max_property_nodes = policy_.max_unreal_property_nodes;
    limits.max_name_bytes = policy_.max_unreal_name_bytes;
    limits.max_page_retries = policy_.max_unreal_page_retries;
    return limits;
}

UnrealProvenance MemoryDebugService::provenance_of(const UnrealRuntimeContext& context) const {
    UnrealProvenance provenance;
    provenance.profile_id = context.profile_id;
    provenance.process_fingerprint = context.process_fingerprint;
    provenance.root_origin = context.roots.origin;
    provenance.confidence = context.confidence;
    provenance.evidence = context.evidence;
    provenance.failed_invariants = context.failed_invariants;
    provenance.snapshot_status = context.snapshot_status;
    return provenance;
}

domain::Result<MemoryDebugService::RuntimeQueryScope> MemoryDebugService::open_runtime_scope(
    const domain::SessionId& id,
    const domain::RuntimeId& runtime_id
) const {
    // The gate is re-checked on every query: turning the feature off must stop
    // contexts published while it was on.
    if (!policy_.enable_unreal_runtime) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported, "unreal runtime reflection is disabled"
        ));
    }
    auto context = unreal_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    if ((*session)->pid() != (*context)->pid) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state, "stale_context"));
    }
    const auto* profile = domain::find_unreal_profile((*context)->profile_id);
    if (profile == nullptr) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "unsupported_profile"));
    }
    RuntimeQueryScope scope;
    scope.session = *session;
    scope.context = *context;
    scope.view = std::make_shared<SessionRuntimeMemoryView>(scope.session);
    auto snapshot = scope.view->refresh();
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }
    scope.snapshot = *snapshot;
    scope.profile = profile;
    return scope;
}

domain::Result<UnrealDiscoverResult> MemoryDebugService::unreal_runtime_discover(
    const domain::SessionId& id,
    const UnrealDiscoverRequest& request,
    const std::stop_token cancellation
) {
    auto gate = policy_.authorize_unreal_runtime(request.profile_id);
    if (!gate) {
        return std::unexpected(gate.error());
    }
    const auto* profile = domain::find_unreal_profile(request.profile_id);
    if (profile == nullptr) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported, "unsupported_profile"));
    }
    if (request.mode == domain::DiscoveryMode::auto_discovery) {
        // Check the independent gate before validating mode-specific input, so
        // a disabled capability reveals no details about what it would accept.
        auto auto_gate = policy_.authorize_unreal_auto_discovery();
        if (!auto_gate) {
            return std::unexpected(auto_gate.error());
        }
    }

    const bool has_rva = request.gu_object_array_rva.has_value() || request.fname_pool_rva.has_value();
    const bool has_address =
        request.gu_object_array_address.has_value() || request.fname_pool_address.has_value();
    const bool complete_rva =
        request.gu_object_array_rva.has_value() && request.fname_pool_rva.has_value();
    const bool complete_address =
        request.gu_object_array_address.has_value() && request.fname_pool_address.has_value();
    if (request.mode == domain::DiscoveryMode::explicit_roots) {
        // oneOf, not precedence: mixing the two forms or supplying half of one
        // is rejected instead of resolved silently.
        if (has_rva == has_address || (has_rva && !complete_rva) || (has_address && !complete_address)) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument,
                "conflicting_roots: supply either both RVAs or both absolute addresses"
            ));
        }
    } else if (has_rva || has_address) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument,
            "conflicting_roots: profile and auto modes do not accept client-supplied roots"
        ));
    }

    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto view = std::make_shared<SessionRuntimeMemoryView>(*session);
    auto snapshot = view->refresh();
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }

    domain::UnrealRuntimeRoots roots;
    std::string module_name = request.module_name;
    std::uint64_t fingerprint = resume_key_;
    bool matched_build_profile = false;
    if (request.mode == domain::DiscoveryMode::build_profile ||
        request.mode == domain::DiscoveryMode::auto_discovery) {
        // Auto may use a registered, exact build fingerprint without a
        // multipattern scan. Its independent gate was checked before input
        // validation because the client did not name a specific build mapping.
        if (!policy_.unreal_build_profiles_valid) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument,
                "invalid_build_profile_config: ARGOS_MCP_UNREAL_BUILD_PROFILES is invalid"
            ));
        }

        struct Match {
            const security::UnrealBuildProfile* profile{};
            const domain::ModuleInfo* module{};
        };
        std::vector<Match> matches;
        bool profile_was_registered = false;
        for (const auto& configured : policy_.unreal_build_profiles) {
            if (configured.profile_id != request.profile_id) continue;
            profile_was_registered = true;
            for (const auto& module : (*snapshot)->modules.all()) {
                if (!ascii_case_equal(module.name, configured.module_name) ||
                    !requested_module_matches(module, request.module_name) ||
                    module.size != configured.module_size) {
                    continue;
                }
                const auto signature_address = domain::checked_add(module.base, configured.signature_rva);
                const auto signature_end = domain::checked_add(
                    configured.signature_rva, configured.signature.size()
                );
                if (!signature_address || !signature_end || *signature_end > module.size) continue;

                std::vector<std::byte> observed(configured.signature.size());
                auto read = view->read(*signature_address, observed, cancellation);
                if (!read || *read != observed.size()) continue;
                if (std::ranges::equal(observed, configured.signature)) {
                    matches.push_back(Match{&configured, &module});
                }
            }
        }
        if (matches.empty()) {
            if (request.mode == domain::DiscoveryMode::auto_discovery && !profile_was_registered) {
                return std::unexpected(error(
                    domain::DebugErrorCode::unsupported,
                    "auto_discovery_unavailable: no build profile is registered and multipattern discovery is not implemented"
                ));
            }
            return std::unexpected(error(
                domain::DebugErrorCode::not_found,
                "no_build_profile: no registered module fingerprint matched the target"
            ));
        }
        if (matches.size() != 1U) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument,
                "ambiguous_build_profile: more than one registered fingerprint matched the target"
            ));
        }
        const auto& selected = matches.front();
        const auto object_array = domain::checked_add(
            selected.module->base, selected.profile->gu_object_array_rva
        );
        const auto name_pool = domain::checked_add(
            selected.module->base, selected.profile->fname_pool_rva
        );
        if (!object_array || !name_pool) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "build profile root overflow"));
        }
        roots.gu_object_array = *object_array;
        roots.fname_pool = *name_pool;
        roots.origin = domain::RootOrigin::build_profile;
        module_name = selected.module->name;
        fingerprint = domain::resume_token::digest(selected.profile->build_id, fingerprint);
        fingerprint = domain::resume_token::digest(selected.module->name, fingerprint);
        fingerprint = domain::resume_token::combine(fingerprint, selected.module->size);
        matched_build_profile = true;
    } else if (complete_rva) {
        if (request.module_name.empty()) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "module is required when roots are RVAs"
            ));
        }
        const domain::ModuleInfo* module = nullptr;
        for (const auto& candidate : (*snapshot)->modules.all()) {
            if (candidate.name == request.module_name || candidate.path == request.module_name) {
                module = &candidate;
                break;
            }
        }
        if (module == nullptr) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "module is not loaded"));
        }
        const auto object_array = domain::checked_add(module->base, *request.gu_object_array_rva);
        const auto name_pool = domain::checked_add(module->base, *request.fname_pool_rva);
        if (!object_array || !name_pool ||
            *request.gu_object_array_rva >= module->size || *request.fname_pool_rva >= module->size) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "root RVA is outside the module"
            ));
        }
        roots.gu_object_array = *object_array;
        roots.fname_pool = *name_pool;
        roots.origin = domain::RootOrigin::explicit_rva;
        module_name = module->name;
        fingerprint = domain::resume_token::digest(module->name, fingerprint);
        fingerprint = domain::resume_token::combine(fingerprint, module->size);
    } else {
        roots.gu_object_array = *request.gu_object_array_address;
        roots.fname_pool = *request.fname_pool_address;
        // Absolute addresses are valid for this session only and are never
        // recorded as a reusable build profile.
        roots.origin = domain::RootOrigin::explicit_address;
        if (const auto* owner = (*snapshot)->modules.find(roots.gu_object_array); owner != nullptr) {
            module_name = owner->name;
            fingerprint = domain::resume_token::digest(owner->name, fingerprint);
            fingerprint = domain::resume_token::combine(fingerprint, owner->size);
        }
    }
    fingerprint = domain::resume_token::digest((*snapshot)->process_name, fingerprint);
    fingerprint = domain::resume_token::combine(fingerprint, (*snapshot)->pid);

    const auto limits = runtime_limits();
    const domain::UnrealRuntimeReader reader{*view, *snapshot, *profile, limits, roots};
    auto validation = reader.validate_roots(cancellation);
    if (!validation) {
        return std::unexpected(validation.error());
    }
    if (matched_build_profile) {
        validation->evidence.insert(validation->evidence.begin(), domain::RuntimeEvidence::module_fingerprint);
    }
    auto catalog = reader.build_class_catalog(cancellation);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }

    std::size_t retained = catalog->classes.size() * sizeof(domain::UnrealClassSummary);
    for (const auto& summary : catalog->classes) {
        retained += summary.name.size() + summary.super_name.value_or(std::string{}).size();
    }
    if (retained > policy_.max_unreal_context_bytes) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "derived catalog exceeds the retained byte limit"
        ));
    }

    UnrealRuntimeContext context{
        id,
        (*session)->pid(),
        profile->id,
        module_name,
        roots,
        validation->confidence,
        validation->evidence,
        validation->failed_invariants,
        std::string{},
        std::make_shared<const domain::ClassCatalog>(std::move(*catalog)),
        domain::SnapshotStatus::stable,
        std::chrono::steady_clock::now(),
        std::chrono::steady_clock::now() + std::chrono::seconds{policy_.unreal_context_ttl_seconds},
        retained
    };
    // Non-reversible and stable for comparison inside this server run; never a
    // dump of a path or of module bytes.
    context.process_fingerprint = "fp-" + std::to_string(fingerprint);

    auto published = unreal_contexts_.publish(
        std::move(context), policy_.max_unreal_contexts_per_session, policy_.max_unreal_contexts_total
    );
    if (!published) {
        return std::unexpected(published.error());
    }

    UnrealDiscoverResult result;
    result.runtime_id = published->id.value();
    result.module_name = published->context->module_name;
    result.roots = published->context->roots;
    result.provenance = provenance_of(*published->context);
    result.class_count = published->context->catalog->classes.size();
    result.classes_truncated = published->context->catalog->truncated;
    result.progress = published->context->catalog->progress;
    result.expires_in_ms = static_cast<std::uint64_t>(policy_.unreal_context_ttl_seconds) * 1000U;
    return result;
}

domain::Result<UnrealClassPage> MemoryDebugService::unreal_runtime_classes(
    const domain::SessionId& id,
    const domain::RuntimeId& runtime_id,
    const std::string_view name_contains,
    const std::size_t limit,
    const std::string_view page_token
) const {
    if (limit == 0U || limit > policy_.max_scan_results) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "limit exceeds the configured result limit"
        ));
    }
    if (!policy_.enable_unreal_runtime) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported, "unreal runtime reflection is disabled"
        ));
    }
    auto context = unreal_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }

    // The token is bound to the context and to the filter, so it cannot be
    // replayed against a different query and is never a bare client index.
    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(name_contains, binding);
    std::size_t offset = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "page_token does not belong to this query"
            ));
        }
        offset = static_cast<std::size_t>(*decoded);
    }

    const auto& classes = (*context)->catalog->classes;
    UnrealClassPage page;
    page.offset = offset;
    page.provenance = provenance_of(**context);
    for (std::size_t index = 0; index < classes.size(); ++index) {
        const auto& summary = classes[index];
        if (!name_contains.empty() && summary.name.find(name_contains) == std::string::npos) {
            continue;
        }
        ++page.total_matched;
        if (page.total_matched <= offset) {
            continue;
        }
        if (page.classes.size() < limit) {
            page.classes.push_back(summary);
        } else if (!page.next_page_token) {
            page.next_page_token = domain::resume_token::encode(
                resume_key_, binding, static_cast<domain::Address>(offset + page.classes.size())
            );
        }
    }
    return page;
}

domain::Result<UnrealTypeResult> MemoryDebugService::unreal_runtime_type(
    const domain::SessionId& id,
    const domain::RuntimeId& runtime_id,
    const std::optional<domain::Address> class_address,
    const std::string_view class_name,
    const bool include_inherited,
    const std::size_t max_properties,
    const std::size_t max_super_depth,
    const std::stop_token cancellation
) const {
    if (class_address.has_value() == !class_name.empty()) {
        return std::unexpected(error(
            domain::DebugErrorCode::invalid_argument, "supply either class_address or class_name"
        ));
    }
    if (max_properties == 0U || max_properties > policy_.max_unreal_properties_per_type) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_properties exceeds the configured limit"
        ));
    }
    if (max_super_depth == 0U || max_super_depth > policy_.max_unreal_super_depth) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_super_depth exceeds the configured limit"
        ));
    }
    auto scope = open_runtime_scope(id, runtime_id);
    if (!scope) {
        return std::unexpected(scope.error());
    }

    // Only addresses that the validated catalog already contains are accepted;
    // an arbitrary address would turn this into a generic memory parser.
    const auto& classes = scope->context->catalog->classes;
    domain::Address resolved = 0;
    if (class_address) {
        const auto found = std::ranges::find(classes, *class_address, &domain::UnrealClassSummary::class_address);
        if (found == classes.end()) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "class is not in the catalog"));
        }
        resolved = found->class_address;
    } else {
        std::size_t matches = 0;
        for (const auto& summary : classes) {
            if (summary.name == class_name) {
                ++matches;
                resolved = summary.class_address;
            }
        }
        if (matches == 0U) {
            return std::unexpected(error(domain::DebugErrorCode::not_found, "class is not in the catalog"));
        }
        if (matches > 1U) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "ambiguous: class_name matches more than one class"
            ));
        }
    }

    const domain::UnrealRuntimeReader reader{
        *scope->view, scope->snapshot, *scope->profile, runtime_limits(), scope->context->roots
    };
    auto type = reader.read_type(resolved, include_inherited, max_properties, max_super_depth, cancellation);
    if (!type) {
        return std::unexpected(type.error());
    }

    UnrealTypeResult result;
    result.provenance = provenance_of(*scope->context);
    if (!type->failed_invariants.empty()) {
        result.provenance.failed_invariants.insert(
            result.provenance.failed_invariants.end(),
            type->failed_invariants.begin(), type->failed_invariants.end()
        );
        result.provenance.confidence = domain::RuntimeConfidence::low;
    }
    result.type = std::move(*type);
    return result;
}

domain::Result<UnrealObjectsPage> MemoryDebugService::unreal_runtime_objects(
    const domain::SessionId& id,
    const domain::RuntimeId& runtime_id,
    const std::string_view class_name,
    const bool include_derived,
    const std::size_t max_objects,
    const std::string_view page_token,
    const std::stop_token cancellation
) const {
    if (max_objects == 0U || max_objects > policy_.max_unreal_objects_stored) {
        return std::unexpected(error(
            domain::DebugErrorCode::limit_exceeded, "max_objects exceeds the configured limit"
        ));
    }
    auto scope = open_runtime_scope(id, runtime_id);
    if (!scope) {
        return std::unexpected(scope.error());
    }

    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(class_name, binding);
    binding = domain::resume_token::combine(binding, include_derived ? 1U : 0U);
    std::uint64_t start_slot = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(
                domain::DebugErrorCode::invalid_argument, "page_token does not belong to this query"
            ));
        }
        start_slot = *decoded;
    }

    const domain::UnrealRuntimeReader reader{
        *scope->view, scope->snapshot, *scope->profile, runtime_limits(), scope->context->roots
    };
    auto page = reader.enumerate_objects(
        class_name, include_derived, start_slot, max_objects, cancellation
    );
    if (!page) {
        return std::unexpected(page.error());
    }

    UnrealObjectsPage result;
    result.objects = std::move(page->objects);
    result.progress = page->progress;
    result.truncated = page->truncated;
    result.provenance = provenance_of(*scope->context);
    result.provenance.snapshot_status = page->status;
    // Continuation follows the sweep position, so a page whose filter matched
    // nothing still advances and a page cut short does not skip slots.
    if (page->truncated && page->next_slot > start_slot) {
        result.next_page_token = domain::resume_token::encode(resume_key_, binding, page->next_slot);
    }
    return result;
}

domain::Result<void> MemoryDebugService::unreal_runtime_release(
    const domain::SessionId& id,
    const domain::RuntimeId& runtime_id
) {
    if (!policy_.enable_unreal_runtime) {
        return std::unexpected(error(
            domain::DebugErrorCode::unsupported, "unreal runtime reflection is disabled"
        ));
    }
    return unreal_contexts_.release(id, runtime_id);
}

}  // namespace argos::application
