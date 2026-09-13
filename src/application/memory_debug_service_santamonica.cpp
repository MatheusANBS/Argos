#include "argos_mcp/application/memory_debug_service.hpp"

#include "argos_mcp/domain/address_inspection.hpp"
#include "argos_mcp/domain/santa_monica_bridge.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_channel.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_crypto.hpp"
#include "argos_mcp/infrastructure/santa_monica_bridge_peer.hpp"
#include "argos_mcp/infrastructure/santa_monica_inventory_reader.hpp"
#include "argos_mcp/infrastructure/santa_monica_native_reader.hpp"

#include <algorithm>
#include <bit>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <array>
#include <chrono>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace argos::application {
namespace {

namespace reflection = domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

[[nodiscard]] domain::DebugError error(
    const domain::DebugErrorCode code, std::string message, std::string reason = {}) {
    return domain::DebugError{code, std::move(message), std::move(reason)};
}

// Session-scoped identity of one controlled discovery. Both sides bind to it,
// so a snapshot from another run can never be presented as this one.
[[nodiscard]] std::string identity_token(const std::string_view prefix, const std::uint64_t value) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string token{prefix};
    for (int shift = 60; shift >= 0; shift -= 4) {
        token.push_back(digits[(value >> static_cast<unsigned>(shift)) & 0xFULL]);
    }
    return token;
}

[[nodiscard]] std::string consistency_name(const reflection::Consistency value) {
    switch (value) {
        case reflection::Consistency::stable: return "stable";
        case reflection::Consistency::unstable: return "unstable";
        case reflection::Consistency::validated_best_effort: break;
    }
    return "validated_best_effort";
}

template <typename T>
[[nodiscard]] std::vector<const T*> collect(const reflection::ReflectionCatalog& catalog) {
    std::vector<const T*> entries;
    for (const auto& record : catalog.records()) {
        if (const auto* value = std::get_if<T>(&record)) entries.push_back(value);
    }
    return entries;
}

// Canonical text of a build profile. The digest of this string is the profile
// identity, so editing any field changes the identity of every snapshot read
// under it.
[[nodiscard]] std::string canonical_profile(const security::SantaMonicaBuildProfile& profile) {
    std::string text = profile.build_id;
    text += '|';
    text += profile.profile_id;
    text += '|';
    text += profile.module_name;
    text += '|';
    text += std::to_string(profile.module_size);
    for (const auto value : {profile.table_begin_rva, profile.table_end_rva,
                             profile.names_begin_rva, profile.names_end_rva,
                             profile.attribute_begin_rva, profile.attribute_end_rva,
                             profile.enum_begin_rva, profile.enum_end_rva,
                             profile.sli_begin_rva, profile.sli_end_rva,
                             profile.resources_root_rva}) {
        text += '|';
        text += std::to_string(value);
    }
    text += '|';
    constexpr std::string_view hex = "0123456789abcdef";
    for (const auto byte : profile.module_digest) {
        const auto value = std::to_integer<unsigned>(byte);
        text.push_back(hex[value >> 4U]);
        text.push_back(hex[value & 15U]);
    }
    return text;
}

[[nodiscard]] bool ascii_case_equal(const std::string_view left, const std::string_view right) {
    if (left.size() != right.size()) return false;
    const auto lower = [](const char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (lower(left[index]) != lower(right[index])) return false;
    }
    return true;
}

[[nodiscard]] std::string hex_token(const std::string_view prefix, const std::uint64_t value) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string token{prefix};
    bool leading = true;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = (value >> static_cast<unsigned>(shift)) & 0xFULL;
        if (nibble == 0 && leading && shift != 0) continue;
        leading = false;
        token.push_back(digits[nibble]);
    }
    return token;
}

[[nodiscard]] bool matches(const std::string_view name, const std::string_view filter) {
    return filter.empty() || name.find(filter) != std::string_view::npos;
}

[[nodiscard]] bool contains_ascii_case_insensitive(const std::string_view text, const std::string_view needle) {
    if (needle.empty()) return true;
    if (needle.size() > text.size()) return false;
    const auto lower = [](const char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    };
    for (std::size_t start = 0; start + needle.size() <= text.size(); ++start) {
        std::size_t index = 0;
        while (index < needle.size() && lower(text[start + index]) == lower(needle[index])) ++index;
        if (index == needle.size()) return true;
    }
    return false;
}

[[nodiscard]] infra::ResourceStoreRequest resource_request(
    const SantaMonicaResourceTarget& target, const security::SecurityPolicy& policy) {
    infra::ResourceStoreRequest request;
    request.profile_id = target.profile_id;
    request.module_name = target.module_name;
    request.module_size = target.module_size;
    request.root_rva = target.root_rva;
    request.max_duration = std::chrono::milliseconds{
        static_cast<std::int64_t>(std::min<std::size_t>(policy.max_santamonica_session_ms, 5000U))};
    return request;
}

[[nodiscard]] domain::Result<void> read_exact(
    const domain::RuntimeMemoryView& memory, const domain::Address address,
    const std::span<std::byte> output, const std::stop_token cancellation) {
    std::size_t done = 0;
    while (done < output.size()) {
        auto got = memory.read(address + done, output.subspan(done), cancellation);
        if (!got || *got == 0 || *got > output.size() - done) {
            return std::unexpected(error(domain::DebugErrorCode::io_error,
                                         "a resource slot could not be read", "resource_read_failed"));
        }
        done += *got;
    }
    return {};
}

[[nodiscard]] std::uint64_t little_endian(const std::span<const std::byte> bytes) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= std::to_integer<std::uint64_t>(bytes[index]) << (8U * index);
    }
    return value;
}

// Returns the cached snapshot unless a refresh is requested or none exists. The
// read runs without the cache lock; only the swap is serialized.
[[nodiscard]] domain::Result<std::shared_ptr<const reflection::ResourceSnapshot>> resource_snapshot(
    const std::shared_ptr<domain::ProcessSession>& session, const SantaMonicaRuntimeContext& context,
    const security::SecurityPolicy& policy, const bool refresh, const std::stop_token cancellation) {
    auto& state = *context.inventory;
    if (!refresh) {
        std::scoped_lock lock(state.mutex);
        if (state.snapshot) return state.snapshot;
    }
    if (session->pid() != context.peer_pid) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state,
                                     "the session no longer matches the snapshot's process",
                                     "runtime_process_mismatch"));
    }
    SessionRuntimeMemoryView view{session};
    if (auto space = view.refresh(); !space) {
        return std::unexpected(space.error());
    }
    auto read = infra::read_resource_inventory(view, resource_request(*context.resources, policy), cancellation);
    if (!read) {
        return std::unexpected(read.error());
    }
    auto fresh = std::make_shared<reflection::ResourceSnapshot>(std::move(*read));
    std::scoped_lock lock(state.mutex);
    fresh->generation = ++state.generation;
    state.snapshot = fresh;
    return std::shared_ptr<const reflection::ResourceSnapshot>{std::move(fresh)};
}

}  // namespace

domain::Result<SantaMonicaDiscoverResult> MemoryDebugService::santamonica_runtime_discover(
    const domain::SessionId& id, const std::stop_token cancellation) {
    auto gate = policy_.authorize_santamonica_runtime();
    if (!gate) {
        return std::unexpected(gate.error());
    }
    // The session is the ownership anchor for quotas, release and cleanup. The
    // controlled peer of ADR-0025 is not the attached process.
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }

    // A profiled build is read natively, straight from the authorized session:
    // no bridge, no peer, no code in the target. The controlled peer stays as
    // the path for a target that has no profile.
    std::unique_ptr<const reflection::ReflectionCatalog> admitted;
    std::string source_label;
    domain::ProcessId source_pid = 0;
    std::optional<SantaMonicaResourceTarget> resources;

    reflection::ReflectionLimits limits;
    limits.max_records = policy_.max_santamonica_records;
    limits.max_string_bytes = policy_.max_santamonica_string_bytes;
    limits.max_retained_bytes = policy_.max_santamonica_retained_bytes;

    if (!policy_.santamonica_build_profiles.empty()) {
        auto view = std::make_shared<SessionRuntimeMemoryView>(*session);
        auto snapshot = view->refresh();
        if (!snapshot) {
            return std::unexpected(snapshot.error());
        }
        for (const auto& configured : policy_.santamonica_build_profiles) {
            if (infra::find_native_type_table_layout(configured.profile_id) == nullptr) continue;
            const domain::ModuleInfo* module = nullptr;
            for (const auto& candidate : (*snapshot)->modules.all()) {
                if (ascii_case_equal(candidate.name, configured.module_name) &&
                    candidate.size == configured.module_size) {
                    module = &candidate;
                    break;
                }
            }
            if (module == nullptr) continue;

            const auto canonical = canonical_profile(configured);
            auto profile_digest = infra::sha256(std::as_bytes(std::span{canonical}));
            if (!profile_digest) {
                return std::unexpected(profile_digest.error());
            }
            infra::NativeTypeTableRequest request;
            request.profile_id = configured.profile_id;
            request.module_name = configured.module_name;
            request.module_size = configured.module_size;
            std::copy_n(configured.module_digest.begin(),
                        std::min(configured.module_digest.size(), request.module_digest.bytes.size()),
                        request.module_digest.bytes.begin());
            request.profile_digest = *profile_digest;
            request.table_begin_rva = configured.table_begin_rva;
            request.table_end_rva = configured.table_end_rva;
            request.names_begin_rva = configured.names_begin_rva;
            request.names_end_rva = configured.names_end_rva;
            request.attribute_begin_rva = configured.attribute_begin_rva;
            request.attribute_end_rva = configured.attribute_end_rva;
            request.enum_begin_rva = configured.enum_begin_rva;
            request.enum_end_rva = configured.enum_end_rva;
            request.sli_begin_rva = configured.sli_begin_rva;
            request.sli_end_rva = configured.sli_end_rva;
            request.max_duration = std::chrono::milliseconds{policy_.max_santamonica_session_ms};
            // The instance covers base as well as pid, so a relaunched target
            // is a different instance even if the pid is reused.
            request.process_instance =
                hex_token("proc-", (*snapshot)->pid) + hex_token("-at-", module->base);
            request.bridge_epoch = "native-" + configured.build_id;
            request.generation = 1;

            auto expected = infra::native_profile_identity(request);
            if (!expected) {
                return std::unexpected(expected.error());
            }
            infra::NativeTypeTableReader reader{*view, request};
            auto read = reflection::ReflectionCatalog::read(reader, *expected, limits, cancellation);
            if (!read) {
                return std::unexpected(read.error());
            }
            admitted = std::move(*read);
            source_label = "native-type-table";
            source_pid = (*snapshot)->pid;
            if (configured.resources_root_rva != 0U &&
                infra::find_resource_store_layout(configured.profile_id) != nullptr) {
                resources = SantaMonicaResourceTarget{configured.profile_id, configured.module_name,
                                                      configured.module_size, configured.resources_root_rva};
            }
            break;
        }
    }

    if (!admitted) {
    auto peer_gate = policy_.authorize_santamonica_peer();
    if (!peer_gate) {
        return std::unexpected(peer_gate.error());
    }
    auto random = infra::create_system_random();
    if (!random) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime requires the system crypto provider"));
    }
    std::array<std::byte, 32> secret_bytes{};
    std::array<std::byte, 16> identity_bytes{};
    if (!(*random)->fill(secret_bytes) || !(*random)->fill(identity_bytes)) {
        reflection::secure_zero(secret_bytes);
        return std::unexpected(error(domain::DebugErrorCode::io_error,
                                     "santa monica session material is unavailable"));
    }
    std::uint64_t request_id = 0;
    std::uint64_t instance_seed = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        request_id |= static_cast<std::uint64_t>(static_cast<unsigned char>(identity_bytes[index]))
            << (8U * index);
        instance_seed |=
            static_cast<std::uint64_t>(static_cast<unsigned char>(identity_bytes[index + 8]))
            << (8U * index);
    }
    if (request_id == 0) request_id = 1;

    const auto process_instance = identity_token("peer-", instance_seed);
    const auto bridge_epoch = identity_token("epoch-", request_id);
    const auto binding = infra::controlled_peer_binding(process_instance, bridge_epoch, request_id);

    const std::chrono::milliseconds budget{policy_.max_santamonica_session_ms};
    infra::ChannelLimits channel_limits;
    channel_limits.connect_timeout = budget;
    channel_limits.io_timeout = budget;

    auto channel = infra::LocalBridgeChannel::listen(**random, channel_limits);
    if (!channel) {
        reflection::secure_zero(secret_bytes);
        return std::unexpected(channel.error());
    }
    const infra::PeerLaunch launch{(*channel)->endpoint(), process_instance, bridge_epoch, request_id};
    auto peer = infra::BridgePeerProcess::spawn(policy_.santamonica_peer_path, launch, secret_bytes);
    if (!peer) {
        reflection::secure_zero(secret_bytes);
        return std::unexpected(peer.error());
    }

    const auto deadline = infra::LocalBridgeChannel::Clock::now() + budget;
    if (auto accepted = (*channel)->accept((*peer)->pid(), deadline, cancellation); !accepted) {
        reflection::secure_zero(secret_bytes);
        return std::unexpected(accepted.error());
    }

    auto secret = reflection::BridgeSecret::create(secret_bytes);
    reflection::secure_zero(secret_bytes);
    if (!secret) {
        return std::unexpected(secret.error());
    }

    auto catalog = infra::read_bridge_snapshot(**channel, std::move(*secret), binding,
                                               infra::controlled_peer_profile(), limits, deadline,
                                               cancellation);
    if (!catalog) {
        return std::unexpected(catalog.error());
    }
    admitted = std::move(*catalog);
    source_label = "controlled-synthetic";
    source_pid = (*peer)->pid();
    }

    const auto now = std::chrono::steady_clock::now();
    SantaMonicaRuntimeContext context{
        id, source_pid, std::shared_ptr<const reflection::ReflectionCatalog>{std::move(admitted)},
        now, now + std::chrono::seconds{policy_.santamonica_context_ttl_seconds}};
    context.resources = std::move(resources);

    auto published = santamonica_contexts_.publish(std::move(context),
                                                   policy_.max_santamonica_contexts_per_session,
                                                   policy_.max_santamonica_contexts_total);
    if (!published) {
        return std::unexpected(published.error());
    }

    const auto& published_catalog = *published->context->catalog;
    SantaMonicaDiscoverResult result;
    result.source = source_label;
    result.runtime_id = published->id.value();
    result.profile_id = published_catalog.identity().profile.profile_id;
    result.process_instance = published_catalog.identity().process_instance;
    result.bridge_epoch = published_catalog.identity().bridge_epoch;
    result.generation = published_catalog.identity().generation;
    result.consistency = consistency_name(published_catalog.consistency());
    result.coverage_complete = published_catalog.coverage_complete();
    result.retained_bytes = published_catalog.retained_bytes();
    result.expires_in_ms = static_cast<std::uint64_t>(policy_.santamonica_context_ttl_seconds) * 1000U;
    result.resources_published = published->context->resources.has_value();
    for (const auto& record : published_catalog.records()) {
        std::visit([&result](const auto& value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, reflection::TypeRecord>) ++result.type_count;
            else if constexpr (std::is_same_v<T, reflection::FieldRecord>) ++result.field_count;
            else if constexpr (std::is_same_v<T, reflection::EnumRecord>) ++result.enum_count;
            else if constexpr (std::is_same_v<T, reflection::EnumValueRecord>) ++result.enum_value_count;
            else ++result.function_count;
        }, record);
    }
    return result;
}

domain::Result<SantaMonicaTypePage> MemoryDebugService::santamonica_runtime_types(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id,
    const std::string_view name_contains, const std::size_t limit,
    const std::string_view page_token) const {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    if (limit == 0U || limit > policy_.max_scan_results) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "limit exceeds the configured result limit"));
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& catalog = *(*context)->catalog;

    // The token is bound to context, session, generation and filter, so it can
    // never be replayed against another query or another snapshot.
    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(catalog.identity().bridge_epoch, binding);
    binding = domain::resume_token::digest(name_contains, binding);
    binding = domain::resume_token::digest("types", binding);
    std::size_t offset = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                         "page_token does not belong to this query",
                                         "stale_snapshot"));
        }
        offset = static_cast<std::size_t>(*decoded);
    }

    SantaMonicaTypePage page;
    page.offset = offset;
    page.generation = catalog.identity().generation;
    for (const auto* type : collect<reflection::TypeRecord>(catalog)) {
        if (!matches(type->name, name_contains)) continue;
        ++page.total_matched;
        if (page.total_matched <= offset) continue;
        if (page.types.size() < limit) {
            page.types.push_back(*type);
        } else if (!page.next_page_token) {
            page.next_page_token = domain::resume_token::encode(
                resume_key_, binding, static_cast<domain::Address>(offset + page.types.size()));
        }
    }
    return page;
}

domain::Result<SantaMonicaTypeResult> MemoryDebugService::santamonica_runtime_type(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id, const std::uint64_t type_id,
    const bool include_inherited, const std::size_t max_fields) const {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    if (type_id == 0) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument, "type_id is required"));
    }
    if (max_fields == 0U || max_fields > policy_.max_santamonica_fields_per_type) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "max_fields exceeds the configured limit"));
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& catalog = *(*context)->catalog;
    const auto types = collect<reflection::TypeRecord>(catalog);
    const auto find = [&types](const std::uint64_t value) -> const reflection::TypeRecord* {
        const auto found = std::ranges::find_if(
            types, [value](const auto* entry) { return entry->id.value == value; });
        return found == types.end() ? nullptr : *found;
    };
    const auto* type = find(type_id);
    if (type == nullptr) {
        return std::unexpected(error(domain::DebugErrorCode::not_found, "type not found"));
    }

    SantaMonicaTypeResult result;
    result.type = *type;
    result.generation = catalog.identity().generation;

    // The catalog already refused inheritance cycles and unknown bases, so this
    // walk is bounded by the same depth the domain admitted.
    std::vector<std::uint64_t> lineage{type->id.value};
    if (include_inherited) {
        const auto* node = type;
        while (node->base) {
            const auto* parent = find(node->base->value);
            if (parent == nullptr) break;
            lineage.push_back(parent->id.value);
            result.inheritance.push_back(parent->id);
            node = parent;
        }
    }

    const auto fields = collect<reflection::FieldRecord>(catalog);
    for (const auto owner : lineage) {
        for (const auto* field : fields) {
            if (field->owner.value != owner) continue;
            if (result.fields.size() >= max_fields) {
                result.fields_truncated = true;
                return result;
            }
            result.fields.push_back(*field);
        }
    }
    return result;
}

domain::Result<SantaMonicaEnumPage> MemoryDebugService::santamonica_runtime_enums(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id,
    const std::string_view name_contains, const std::size_t limit, const std::size_t max_values,
    const std::string_view page_token) const {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    if (limit == 0U || limit > policy_.max_scan_results) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "limit exceeds the configured result limit"));
    }
    if (max_values == 0U || max_values > policy_.max_santamonica_values_per_enum) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "max_values exceeds the configured limit"));
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& catalog = *(*context)->catalog;

    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(catalog.identity().bridge_epoch, binding);
    binding = domain::resume_token::digest(name_contains, binding);
    binding = domain::resume_token::digest("enums", binding);
    std::size_t offset = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                         "page_token does not belong to this query",
                                         "stale_snapshot"));
        }
        offset = static_cast<std::size_t>(*decoded);
    }

    const auto values = collect<reflection::EnumValueRecord>(catalog);
    SantaMonicaEnumPage page;
    page.offset = offset;
    page.generation = catalog.identity().generation;
    for (const auto* declaration : collect<reflection::EnumRecord>(catalog)) {
        if (!matches(declaration->name, name_contains)) continue;
        ++page.total_matched;
        if (page.total_matched <= offset) continue;
        if (page.enums.size() >= limit) {
            if (!page.next_page_token) {
                page.next_page_token = domain::resume_token::encode(
                    resume_key_, binding, static_cast<domain::Address>(offset + page.enums.size()));
            }
            continue;
        }
        SantaMonicaEnumEntry entry;
        entry.declaration = *declaration;
        for (const auto* value : values) {
            if (value->owner != declaration->id) continue;
            if (entry.values.size() >= max_values) {
                entry.values_truncated = true;
                break;
            }
            entry.values.push_back(*value);
        }
        page.enums.push_back(std::move(entry));
    }
    return page;
}

domain::Result<SantaMonicaFunctionPage> MemoryDebugService::santamonica_runtime_sli_functions(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id,
    const std::string_view name_contains, const std::size_t limit,
    const std::string_view page_token) const {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    if (limit == 0U || limit > policy_.max_scan_results) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "limit exceeds the configured result limit"));
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& catalog = *(*context)->catalog;

    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(catalog.identity().bridge_epoch, binding);
    binding = domain::resume_token::digest(name_contains, binding);
    binding = domain::resume_token::digest("sli", binding);
    std::size_t offset = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                         "page_token does not belong to this query",
                                         "stale_snapshot"));
        }
        offset = static_cast<std::size_t>(*decoded);
    }

    SantaMonicaFunctionPage page;
    page.offset = offset;
    page.generation = catalog.identity().generation;
    for (const auto* function : collect<reflection::SliFunctionRecord>(catalog)) {
        if (!matches(function->name, name_contains)) continue;
        ++page.total_matched;
        if (page.total_matched <= offset) continue;
        if (page.functions.size() < limit) {
            page.functions.push_back(*function);
        } else if (!page.next_page_token) {
            page.next_page_token = domain::resume_token::encode(
                resume_key_, binding, static_cast<domain::Address>(offset + page.functions.size()));
        }
    }
    return page;
}

domain::Result<void> MemoryDebugService::santamonica_runtime_release(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id) {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    return santamonica_contexts_.release(id, runtime_id);
}

domain::Result<SantaMonicaInventoryPage> MemoryDebugService::santamonica_runtime_resources(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id,
    const std::string_view name_contains, const std::size_t limit, const std::string_view page_token,
    const bool acquired_only, const bool refresh, const std::stop_token cancellation) {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    if (limit == 0U || limit > policy_.max_scan_results) {
        return std::unexpected(error(domain::DebugErrorCode::limit_exceeded,
                                     "limit exceeds the configured result limit"));
    }
    if (name_contains.size() > reflection::max_resource_name_bytes) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                     "name_contains is longer than any resource name"));
    }
    if (refresh && !page_token.empty()) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                     "refresh reads a new snapshot and cannot continue a page_token",
                                     "refresh_restarts_pagination"));
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& published = **context;
    if (!published.resources) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "this snapshot's build profile does not publish resources",
                                     "resources_not_published"));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    auto current = resource_snapshot(*session, published, policy_, refresh, cancellation);
    if (!current) {
        return std::unexpected(current.error());
    }
    const auto& resources = **current;

    // Bound to context, session, filter and generation: a token from before a
    // refresh or from another query is refused, never reinterpreted.
    auto binding = domain::resume_token::digest(runtime_id.value(), resume_key_);
    binding = domain::resume_token::digest(id.value(), binding);
    binding = domain::resume_token::digest(name_contains, binding);
    binding = domain::resume_token::digest(acquired_only ? "acquired" : "all", binding);
    binding = domain::resume_token::digest("resources", binding);
    binding = domain::resume_token::combine(binding, resources.generation);
    std::size_t offset = 0;
    if (!page_token.empty()) {
        const auto decoded = domain::resume_token::decode(page_token, resume_key_, binding);
        if (!decoded) {
            return std::unexpected(error(domain::DebugErrorCode::invalid_argument,
                                         "page_token does not belong to this query",
                                         "stale_snapshot"));
        }
        offset = static_cast<std::size_t>(*decoded);
    }

    SantaMonicaInventoryPage page;
    page.generation = resources.generation;
    page.offset = offset;
    page.resource_count = resources.entries.size();
    for (const auto& entry : resources.entries) {
        if (acquired_only && !entry.acquired) continue;
        if (!contains_ascii_case_insensitive(entry.name, name_contains)) continue;
        ++page.total_matched;
        if (page.total_matched <= offset) continue;
        if (page.entries.size() < limit) {
            page.entries.push_back(entry);
        } else if (!page.next_page_token) {
            page.next_page_token = domain::resume_token::encode(
                resume_key_, binding, static_cast<domain::Address>(offset + page.entries.size()));
        }
    }
    return page;
}

domain::Result<SantaMonicaResourceWrite> MemoryDebugService::santamonica_runtime_set_resource(
    const domain::SessionId& id, const domain::RuntimeId& runtime_id, const std::string_view name,
    const std::int64_t quantity, const std::string_view confirmation, const std::stop_token cancellation) {
    if (!policy_.enable_santamonica_runtime) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "santa monica runtime is disabled"));
    }
    // The same gate as any memory write: write access and the per-call phrase.
    auto authorization = policy_.authorize_write(sizeof(std::int32_t), confirmation);
    if (!authorization) {
        return std::unexpected(authorization.error());
    }
    auto context = santamonica_contexts_.get(id, runtime_id);
    if (!context) {
        return std::unexpected(context.error());
    }
    const auto& published = **context;
    if (!published.resources) {
        return std::unexpected(error(domain::DebugErrorCode::unsupported,
                                     "this snapshot's build profile does not publish resources",
                                     "resources_not_published"));
    }
    auto session = sessions_.get(id);
    if (!session) {
        return std::unexpected(session.error());
    }
    if ((*session)->access_mode() != domain::AccessMode::read_write) {
        return std::unexpected(error(domain::DebugErrorCode::access_denied,
                                     "resource writes require a read_write session", "session_read_only"));
    }
    if ((*session)->pid() != published.peer_pid) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state,
                                     "the session no longer matches the snapshot's process",
                                     "runtime_process_mismatch"));
    }

    SessionRuntimeMemoryView view{*session};
    if (auto space = view.refresh(); !space) {
        return std::unexpected(space.error());
    }
    auto location = infra::locate_resource_balance(
        view, resource_request(*published.resources, policy_), name, cancellation);
    if (!location) {
        return std::unexpected(location.error());
    }
    auto admitted = reflection::admit_resource_quantity(location->entry, quantity);
    if (!admitted) {
        return std::unexpected(admitted.error());
    }

    // Re-check the exact slots right before writing: the record must still link
    // to the same definition and the resource must still be held.
    std::array<std::byte, 8> definition_bytes{};
    std::array<std::byte, 4> state_bytes{};
    std::array<std::byte, 4> quantity_bytes{};
    if (auto ok = read_exact(view, location->definition_slot, definition_bytes, cancellation); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = read_exact(view, location->state, state_bytes, cancellation); !ok) {
        return std::unexpected(ok.error());
    }
    if (little_endian(definition_bytes) != location->definition ||
        little_endian(state_bytes) != location->acquired_state) {
        return std::unexpected(error(domain::DebugErrorCode::invalid_state,
                                     "the resource changed before it could be written",
                                     "resource_snapshot_changed"));
    }
    if (auto ok = read_exact(view, location->quantity, quantity_bytes, cancellation); !ok) {
        return std::unexpected(ok.error());
    }
    const auto previous = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(little_endian(quantity_bytes)));

    std::array<std::byte, 4> payload{};
    const auto raw = static_cast<std::uint32_t>(*admitted);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>((raw >> (8U * index)) & 0xFFU);
    }
    if (cancellation.stop_requested()) {
        return std::unexpected(error(domain::DebugErrorCode::cancelled, "operation cancelled",
                                     "operation_cancelled"));
    }
    auto written = (*session)->write(location->quantity, payload);
    // Whatever happened, the cached quantities no longer describe the target.
    {
        std::scoped_lock lock(published.inventory->mutex);
        published.inventory->snapshot.reset();
    }
    if (!written) {
        return std::unexpected(written.error());
    }
    if (*written != payload.size()) {
        return std::unexpected(error(domain::DebugErrorCode::io_error,
                                     "the resource write was short", "short_write"));
    }

    std::array<std::byte, 4> observed_bytes{};
    std::array<std::byte, 8> linked_bytes{};
    if (auto ok = read_exact(view, location->quantity, observed_bytes, {}); !ok) {
        return std::unexpected(ok.error());
    }
    if (auto ok = read_exact(view, location->definition_slot, linked_bytes, {}); !ok) {
        return std::unexpected(ok.error());
    }

    SantaMonicaResourceWrite result;
    result.resource = location->entry;
    result.previous = previous;
    result.requested = *admitted;
    result.observed = std::bit_cast<std::int32_t>(static_cast<std::uint32_t>(little_endian(observed_bytes)));
    result.verified = result.observed == result.requested &&
        little_endian(linked_bytes) == location->definition;
    return result;
}

}  // namespace argos::application
