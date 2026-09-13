#include "argos_mcp/domain/santa_monica_runtime.hpp"

#include <algorithm>
#include <charconv>
#include <new>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <utility>

namespace argos::domain::santamonica {
namespace {

[[nodiscard]] DebugError fail(const DebugErrorCode code, const char* reason) {
    return {code, "Santa Monica reflection validation failed", reason};
}

[[nodiscard]] bool printable(const std::string_view value, const std::size_t limit) {
    return !value.empty() && value.size() <= limit && std::ranges::all_of(value, [](const char c) {
        return c >= ' ' && c <= '~';
    });
}

[[nodiscard]] bool present(const Sha256Digest& digest) {
    return std::ranges::any_of(digest.bytes, [](const auto b) { return b != std::byte{}; });
}

[[nodiscard]] bool decimal_integer(const std::string_view value) {
    if (value.empty()) return false;
    const auto digits = value.front() == '-' ? value.substr(1) : value;
    if (digits.empty() || (digits.size() > 1 && digits.front() == '0') || value == "-0") return false;
    if (!std::ranges::all_of(digits, [](const char c) { return c >= '0' && c <= '9'; })) return false;
    if (value.front() == '-') {
        std::int64_t parsed{};
        const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
        return result.ec == std::errc{} && result.ptr == value.data() + value.size();
    }
    std::uint64_t parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}

// Accounts owned capacities, not just logical lengths; includes string SSO
// conservatively. No unchecked addition/multiplication uses external counts.
class Budget {
public:
    explicit Budget(const std::size_t limit) : limit_(limit) {}
    [[nodiscard]] bool add(const std::size_t count, const std::size_t size = 1) {
        if (size != 0 && count > (limit_ - used_) / size) return false;
        used_ += count * size;
        return true;
    }
    [[nodiscard]] bool string(const std::string& value) {
        return add(value.capacity()) && add(1);
    }
    [[nodiscard]] std::size_t used() const noexcept { return used_; }
private:
    std::size_t limit_;
    std::size_t used_{};
};

[[nodiscard]] bool charge_identity(Budget& budget, const SnapshotIdentity& identity) {
    if (!budget.add(sizeof(ReflectionCatalog)) || !budget.string(identity.process_instance) ||
        !budget.string(identity.bridge_epoch) || !budget.string(identity.profile.profile_id) ||
        !budget.add(identity.profile.modules.capacity(), sizeof(ModuleIdentity))) return false;
    for (const auto& module : identity.profile.modules) {
        if (!budget.string(module.name)) return false;
    }
    return true;
}

[[nodiscard]] Result<void> validate_record(
    const ReflectionRecord& record, const ReflectionLimits& limits, Budget& budget) {
    return std::visit([&](const auto& value) -> Result<void> {
        using T = std::decay_t<decltype(value)>;
        if (!printable(value.name, limits.max_string_bytes)) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_metadata_name"));
        }
        if (!budget.string(value.name)) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
        }
        if constexpr (std::is_same_v<T, TypeRecord> || std::is_same_v<T, EnumRecord> ||
                      std::is_same_v<T, SliFunctionRecord>) {
            if (value.id.value == 0) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_metadata_id"));
        } else {
            if (value.owner.value == 0) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_metadata_id"));
        }
        if constexpr (std::is_same_v<T, TypeRecord>) {
            if (value.size == 0) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_type_size"));
        } else if constexpr (std::is_same_v<T, FieldRecord>) {
            if (value.size == 0) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_field_size"));
            bool valid_kind = false;
            switch (value.kind) {
                case FieldKind::scalar:
                    valid_kind = !value.referenced_type && !value.referenced_enum;
                    break;
                case FieldKind::object:
                    valid_kind = value.referenced_type.has_value() && !value.referenced_enum;
                    break;
                case FieldKind::pointer:
                case FieldKind::array:
                case FieldKind::map:
                    valid_kind = !value.referenced_enum;
                    break;
                case FieldKind::enumeration:
                    valid_kind = !value.referenced_type && value.referenced_enum.has_value();
                    break;
            }
            if (!valid_kind) return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_field_kind"));
        } else if constexpr (std::is_same_v<T, EnumValueRecord>) {
            if (value.value.size() > limits.max_string_bytes || !decimal_integer(value.value)) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_enum_value"));
            }
            if (!budget.string(value.value)) return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
        } else if constexpr (std::is_same_v<T, SliFunctionRecord>) {
            if (!printable(value.signature, limits.max_string_bytes)) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_sli_signature"));
            }
            if (!budget.string(value.signature)) return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
        }
        return {};
    }, record);
}

template <typename T>
[[nodiscard]] bool sort_unique(std::vector<const T*>& entries) {
    std::ranges::sort(entries, {}, [](const T* item) { return item->id.value; });
    return std::adjacent_find(entries.begin(), entries.end(), [](const T* a, const T* b) {
        return a->id == b->id;
    }) == entries.end();
}

template <typename T, typename Key>
[[nodiscard]] const T* lookup(const std::vector<const T*>& entries, const Key key) {
    const auto found = std::ranges::lower_bound(entries, key.value, {}, [](const T* item) { return item->id.value; });
    return found != entries.end() && (*found)->id == key ? *found : nullptr;
}

template <typename T>
[[nodiscard]] bool unique_names(std::vector<const T*>& entries) {
    std::ranges::sort(entries, [](const T* a, const T* b) {
        if (a->owner.value != b->owner.value) return a->owner.value < b->owner.value;
        return a->name < b->name;
    });
    return std::adjacent_find(entries.begin(), entries.end(), [](const T* a, const T* b) {
        return a->owner == b->owner && a->name == b->name;
    }) == entries.end();
}

[[nodiscard]] Result<void> validate_links(
    const std::vector<ReflectionRecord>& records, const ReflectionLimits& limits,
    const std::stop_token cancellation) {
    // Deterministic O(n log n) indexes avoid adversarial hash collisions.
    // Indexes hold borrowed pointers only and die before catalog publication.
    std::vector<const TypeRecord*> types;
    std::vector<const EnumRecord*> enums;
    std::vector<const SliFunctionRecord*> functions;
    std::vector<const FieldRecord*> fields;
    std::vector<const EnumValueRecord*> values;
    for (const auto& record : records) {
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        std::visit([&](const auto& value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, TypeRecord>) types.push_back(&value);
            else if constexpr (std::is_same_v<T, EnumRecord>) enums.push_back(&value);
            else if constexpr (std::is_same_v<T, SliFunctionRecord>) functions.push_back(&value);
            else if constexpr (std::is_same_v<T, FieldRecord>) fields.push_back(&value);
            else values.push_back(&value);
        }, record);
    }
    if (!sort_unique(types) || !sort_unique(enums) || !sort_unique(functions) ||
        !unique_names(fields) || !unique_names(values)) {
        return std::unexpected(fail(DebugErrorCode::parse_error, "duplicate_metadata"));
    }
    for (const auto* type : types) {
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        const auto* node = type;
        std::size_t depth = 1;
        while (node->base) {
            const auto* parent = lookup(types, *node->base);
            if (!parent || parent->size > node->size) {
                return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_base_type"));
            }
            if (parent == type) return std::unexpected(fail(DebugErrorCode::parse_error, "inheritance_cycle"));
            if (++depth > limits.max_inheritance_depth) {
                return std::unexpected(fail(DebugErrorCode::limit_exceeded, "inheritance_depth_budget"));
            }
            node = parent;
        }
    }
    for (const auto* field : fields) {
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        const auto* owner = lookup(types, field->owner);
        if (!owner || field->offset > owner->size || field->size > owner->size - field->offset) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "field_out_of_bounds"));
        }
        if ((field->referenced_type && !lookup(types, *field->referenced_type)) ||
            (field->referenced_enum && !lookup(enums, *field->referenced_enum))) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "unknown_field_reference"));
        }
        if (field->kind == FieldKind::pointer && field->size != 8) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_pointer_size"));
        }
        if (field->kind == FieldKind::object &&
            field->size != lookup(types, *field->referenced_type)->size) {
            return std::unexpected(fail(DebugErrorCode::parse_error, "invalid_object_size"));
        }
    }
    for (const auto* value : values) {
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        if (!lookup(enums, value->owner)) return std::unexpected(fail(DebugErrorCode::parse_error, "unknown_enum_owner"));
    }
    return {};
}

[[nodiscard]] bool valid_boundary(const ReadBoundary& boundary) {
    return valid_identity_token(boundary.identity.process_instance) && valid_identity_token(boundary.identity.bridge_epoch) &&
        boundary.identity.generation != 0 &&
        (boundary.consistency == Consistency::stable ||
         boundary.consistency == Consistency::validated_best_effort);
}

// Reader diagnostics can contain native paths/addresses; keep them out of the
// public result even when a future infrastructure implementation errs.
[[nodiscard]] DebugError reader_error(const DebugError& error) {
    if (error.code == DebugErrorCode::cancelled) return fail(DebugErrorCode::cancelled, "operation_cancelled");
    if (error.code == DebugErrorCode::limit_exceeded) return fail(DebugErrorCode::limit_exceeded, "reader_budget");
    return fail(DebugErrorCode::io_error, "runtime_reader_failed");
}

}  // namespace

bool valid_identity_token(const std::string_view value) noexcept {
    return !value.empty() && value.size() <= 128 && std::ranges::all_of(value, [](const char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    });
}

Result<void> validate_profile_identity(const ProfileIdentity& profile) {
    if (profile.schema_version != 1 || profile.protocol_version != 1 ||
        profile.architecture != Architecture::x64) {
        return std::unexpected(fail(DebugErrorCode::unsupported, "unsupported_profile_version"));
    }
    // The two sources are mutually exclusive, in both directions: a bridge
    // profile must carry bridge identity, and a native one must carry none, so
    // neither can be dressed up as the other.
    switch (profile.source) {
        case SnapshotSource::bridge:
            if (profile.bridge_version == 0 || !present(profile.bridge_digest)) {
                return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_bridge_identity"));
            }
            break;
        case SnapshotSource::native_reader:
            if (profile.bridge_version != 0 || present(profile.bridge_digest)) {
                return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_bridge_identity"));
            }
            break;
        default:
            return std::unexpected(fail(DebugErrorCode::unsupported, "unsupported_profile_version"));
    }
    if (!valid_identity_token(profile.profile_id) || !present(profile.profile_digest) ||
        profile.modules.empty() || profile.modules.size() > 64) {
        return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_profile_identity"));
    }
    std::string_view previous;
    for (const auto& module : profile.modules) {
        if (!valid_identity_token(module.name) || module.name == "." || module.name == ".." ||
            module.image_size == 0 || !present(module.file_digest) ||
            (!previous.empty() && module.name <= previous)) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_profile_module"));
        }
        previous = module.name;
    }
    return {};
}

Result<std::unique_ptr<const ReflectionCatalog>> ReflectionCatalog::read(
    SantaMonicaRuntimeReader& reader, const ProfileIdentity& expected_profile,
    const ReflectionLimits& limits, const std::stop_token cancellation) {
    try {
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        const auto profile_check = validate_profile_identity(expected_profile);
        if (!profile_check) return std::unexpected(profile_check.error());
        // Hard ceilings apply even if an internal caller misconfigures policy.
        if (limits.max_records == 0 || limits.max_records > 100000 || limits.max_string_bytes == 0 ||
            limits.max_string_bytes > 4096 || limits.max_retained_bytes == 0 ||
            limits.max_retained_bytes > 32U * 1024U * 1024U || limits.max_inheritance_depth == 0 ||
            limits.max_inheritance_depth > 32) {
            return std::unexpected(fail(DebugErrorCode::invalid_argument, "invalid_reflection_limits"));
        }
        auto start = reader.begin(limits, cancellation);
        if (!start) return std::unexpected(reader_error(start.error()));
        if (!(start->identity.profile == expected_profile)) {
            return std::unexpected(fail(DebugErrorCode::unsupported, "profile_mismatch"));
        }
        if (!valid_boundary(*start)) return std::unexpected(fail(DebugErrorCode::invalid_state, "unstable_snapshot"));
        ReflectionCatalog catalog;
        catalog.identity_ = std::move(start->identity);
        Budget budget(limits.max_retained_bytes);
        if (!charge_identity(budget, catalog.identity_)) {
            return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
        }
        while (true) {
            if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
            auto next = reader.next(cancellation);
            if (!next) return std::unexpected(reader_error(next.error()));
            if (!*next) break;
            if (catalog.records_.size() >= limits.max_records) {
                return std::unexpected(fail(DebugErrorCode::limit_exceeded, "record_budget"));
            }
            auto checked = validate_record(**next, limits, budget);
            if (!checked) return std::unexpected(checked.error());
            if (catalog.records_.size() == catalog.records_.capacity()) {
                const auto old_capacity = catalog.records_.capacity();
                const auto desired = std::min(limits.max_records, old_capacity == 0 ? std::size_t{1} : old_capacity * 2);
                if (!budget.add(desired - old_capacity, sizeof(ReflectionRecord))) {
                    return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
                }
                catalog.records_.reserve(desired);
                if (!budget.add(catalog.records_.capacity() - desired, sizeof(ReflectionRecord))) {
                    return std::unexpected(fail(DebugErrorCode::limit_exceeded, "retained_bytes_budget"));
                }
            }
            catalog.records_.push_back(std::move(**next));
        }
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        auto end = reader.finish(cancellation);
        if (!end) return std::unexpected(reader_error(end.error()));
        if (!valid_boundary(*end) || !(catalog.identity_ == end->identity)) {
            return std::unexpected(fail(DebugErrorCode::invalid_state, "stale_snapshot"));
        }
        auto links = validate_links(catalog.records_, limits, cancellation);
        if (!links) return std::unexpected(links.error());
        if (cancellation.stop_requested()) return std::unexpected(fail(DebugErrorCode::cancelled, "operation_cancelled"));
        catalog.consistency_ = start->consistency == Consistency::stable && end->consistency == Consistency::stable
            ? Consistency::stable : Consistency::validated_best_effort;
        catalog.coverage_complete_ = start->coverage_complete && end->coverage_complete;
        catalog.retained_bytes_ = budget.used();
        return std::make_unique<const ReflectionCatalog>(std::move(catalog));
    } catch (const std::bad_alloc&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    } catch (const std::length_error&) {
        return std::unexpected(fail(DebugErrorCode::limit_exceeded, "allocation_budget"));
    }
}

}  // namespace argos::domain::santamonica
