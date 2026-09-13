#include "argos_mcp/domain/santa_monica_runtime.hpp"

#include <functional>
#include <iostream>
#include <limits>
#include <stop_token>
#include <string>
#include <utility>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}

Sha256Digest digest(const unsigned char value) {
    Sha256Digest result;
    result.bytes.fill(static_cast<std::byte>(value));
    return result;
}

ProfileIdentity profile() {
    return {1, "synthetic-x64", digest(1), digest(2), 1, 1,
            {{"synthetic.exe", 4096, digest(3)}}};
}

ReadBoundary boundary() {
    return {{profile(), "synthetic-process-1", "synthetic-epoch-1", 1},
            Consistency::validated_best_effort, true};
}

// Entirely synthetic, normalized metadata. No game layout, signature, script
// or proprietary bytes are included in the fixtures or production library.
class Reader final : public SantaMonicaRuntimeReader {
public:
    ReadBoundary first{boundary()};
    ReadBoundary last{boundary()};
    std::vector<ReflectionRecord> records{
        TypeRecord{{1}, "Base", 8, std::nullopt},
        TypeRecord{{2}, "Player", 16, TypeKey{1}},
        FieldRecord{{2}, "Health", 8, 8, FieldKind::scalar, std::nullopt, std::nullopt},
        EnumRecord{{3}, "Flags"},
        EnumValueRecord{{3}, "Maximum", "18446744073709551615"},
        SliFunctionRecord{{4}, "Describe", "string()"},
    };
    std::size_t calls{};
    std::size_t index{};
    bool finished{};
    bool fail_begin{};
    bool fail_next{};
    bool fail_finish{};
    std::function<void()> on_next;
    std::function<void()> on_finish;

    Result<ReadBoundary> begin(const ReflectionLimits&, std::stop_token) override {
        ++calls;
        if (fail_begin) return native_failure();
        return first;
    }
    Result<std::optional<ReflectionRecord>> next(std::stop_token) override {
        ++calls;
        if (on_next) on_next();
        if (fail_next) return native_failure();
        if (index == records.size()) return std::optional<ReflectionRecord>{};
        return std::optional<ReflectionRecord>{std::move(records[index++])};
    }
    Result<ReadBoundary> finish(std::stop_token) override {
        ++calls;
        finished = true;
        if (on_finish) on_finish();
        if (fail_finish) return native_failure();
        return last;
    }
private:
    static std::unexpected<DebugError> native_failure() {
        return std::unexpected(DebugError{DebugErrorCode::io_error,
            "private-path native bytes 0x1234", "private-native-reason"});
    }
};

void expect_failure(Reader& reader, const char* reason, const ReflectionLimits& limits = {}) {
    auto result = ReflectionCatalog::read(reader, profile(), limits);
    check(!result, reason);
    if (!result) check(result.error().reason == reason, "failure has expected safe reason");
}

void test_profiles() {
    check(validate_profile_identity(profile()).has_value(), "valid identity accepted");
    for (int change = 0; change < 10; ++change) {
        auto changed = profile();
        switch (change) {
            case 0: changed.schema_version = 2; break;
            case 1: changed.protocol_version = 2; break;
            case 2: changed.bridge_version = 0; break;
            case 3: changed.profile_digest = {}; break;
            case 4: changed.bridge_digest = {}; break;
            case 5: changed.modules.clear(); break;
            case 6: changed.modules[0].name = "../private.exe"; break;
            case 7: changed.modules[0].file_digest = {}; break;
            case 8: changed.modules.push_back(changed.modules.front()); break;
            case 9: changed.architecture = static_cast<Architecture>(99); break;
        }
        Reader reader;
        check(!ReflectionCatalog::read(reader, changed), "invalid expected profile refused");
        check(reader.calls == 0, "invalid profile rejected before reader access");
    }
    auto sorted = profile();
    sorted.modules.push_back({"z.dll", 32, digest(4)});
    check(validate_profile_identity(sorted).has_value(), "sorted relevant modules accepted");
    std::swap(sorted.modules[0], sorted.modules[1]);
    check(!validate_profile_identity(sorted), "noncanonical module order refused");
}

void test_catalog() {
    Reader reader;
    auto result = ReflectionCatalog::read(reader, profile());
    check(result.has_value(), "well-formed catalog admitted");
    if (!result) return;
    check(reader.finished, "reader boundary finalized before publication");
    const auto& catalog = **result;
    check(catalog.records().size() == 6, "every record retained");
    check(catalog.identity() == boundary().identity, "catalog has exact source identity");
    check(catalog.consistency() == Consistency::validated_best_effort,
          "identical sampled identities never promote best effort to stable");
    check(catalog.coverage_complete() && catalog.results_complete(), "explicit source coverage preserved");
    check(std::get<EnumValueRecord>(catalog.records()[4]).value == "18446744073709551615",
          "unsigned 64-bit enum value preserved exactly");
    reader.last.identity.generation = 2;
    check(catalog.identity().generation == 1, "catalog owns a copy independent of reader");

    Reader exact;
    ReflectionLimits limits;
    limits.max_retained_bytes = catalog.retained_bytes();
    auto exact_result = ReflectionCatalog::read(exact, profile(), limits);
    check(exact_result && (*exact_result)->retained_bytes() == limits.max_retained_bytes,
          "exact retained byte boundary accepted");
    Reader below;
    --limits.max_retained_bytes;
    expect_failure(below, "retained_bytes_budget", limits);
    Reader exact_count;
    limits = {};
    limits.max_records = 6;
    check(ReflectionCatalog::read(exact_count, profile(), limits).has_value(), "exact record boundary accepted");

    auto independent = [] {
        Reader scoped;
        return ReflectionCatalog::read(scoped, profile());
    }();
    check(independent && (*independent)->records().size() == 6, "catalog survives reader destruction");

    Reader stable;
    stable.first.consistency = stable.last.consistency = Consistency::stable;
    auto protected_copy = ReflectionCatalog::read(stable, profile());
    check(protected_copy && (*protected_copy)->consistency() == Consistency::stable,
          "protected immutable source retains stable evidence");
    Reader mixed;
    mixed.first.consistency = Consistency::stable;
    mixed.last.coverage_complete = false;
    auto partial = ReflectionCatalog::read(mixed, profile());
    check(partial && (*partial)->consistency() == Consistency::validated_best_effort &&
          !(*partial)->coverage_complete(), "weakest consistency and partial coverage preserved");
    Reader empty;
    empty.records.clear();
    auto empty_result = ReflectionCatalog::read(empty, profile());
    check(empty_result && (*empty_result)->records().empty(), "empty scoped catalog accepted");
}

void test_identity_changes() {
    for (int change = 0; change < 7; ++change) {
        Reader reader;
        switch (change) {
            case 0: reader.last.identity.process_instance = "reused-pid-new-process"; break;
            case 1: reader.last.identity.bridge_epoch = "reconnected-bridge"; break;
            case 2: reader.last.identity.generation = 2; break;
            case 3: reader.last.identity.profile.modules[0].file_digest = digest(4); break;
            case 4: reader.last.identity.profile.bridge_digest = digest(4); break;
            case 5: reader.last.consistency = Consistency::unstable; break;
            case 6: reader.last.identity.generation = 0; break;
        }
        expect_failure(reader, "stale_snapshot");
    }
    Reader mismatch;
    mismatch.first.identity.profile.profile_digest = digest(6);
    expect_failure(mismatch, "profile_mismatch");
    check(mismatch.index == 0, "mismatching profile fails before reading records");
    Reader unstable;
    unstable.first.consistency = Consistency::unstable;
    expect_failure(unstable, "unstable_snapshot");
}

void test_invalid_graphs() {
    Reader missing_base;
    std::get<TypeRecord>(missing_base.records[1]).base = TypeKey{99};
    expect_failure(missing_base, "invalid_base_type");
    Reader cycle;
    std::get<TypeRecord>(cycle.records[0]).size = 16;
    std::get<TypeRecord>(cycle.records[0]).base = TypeKey{2};
    expect_failure(cycle, "inheritance_cycle");
    Reader self;
    std::get<TypeRecord>(self.records[0]).base = TypeKey{1};
    expect_failure(self, "inheritance_cycle");
    Reader depth;
    ReflectionLimits limits;
    limits.max_inheritance_depth = 1;
    expect_failure(depth, "inheritance_depth_budget", limits);
    Reader duplicate;
    duplicate.records.push_back(duplicate.records[0]);
    expect_failure(duplicate, "duplicate_metadata");
    Reader duplicate_field;
    duplicate_field.records.push_back(duplicate_field.records[2]);
    expect_failure(duplicate_field, "duplicate_metadata");
    for (const std::size_t record_index : {3U, 4U, 5U}) {
        Reader duplicate_other;
        duplicate_other.records.push_back(duplicate_other.records[record_index]);
        expect_failure(duplicate_other, "duplicate_metadata");
    }
    Reader overflow;
    std::get<FieldRecord>(overflow.records[2]).offset = std::numeric_limits<std::uint64_t>::max();
    expect_failure(overflow, "field_out_of_bounds");
    Reader oversized;
    std::get<FieldRecord>(oversized.records[2]).size = std::numeric_limits<std::uint64_t>::max();
    expect_failure(oversized, "field_out_of_bounds");
    Reader owner;
    std::get<FieldRecord>(owner.records[2]).owner = TypeKey{99};
    expect_failure(owner, "field_out_of_bounds");
    Reader reference;
    auto& field = std::get<FieldRecord>(reference.records[2]);
    field.kind = FieldKind::pointer;
    field.referenced_type = TypeKey{99};
    expect_failure(reference, "unknown_field_reference");
    Reader kind;
    std::get<FieldRecord>(kind.records[2]).kind = static_cast<FieldKind>(99);
    expect_failure(kind, "invalid_field_kind");
    Reader missing_enum;
    auto& enum_field = std::get<FieldRecord>(missing_enum.records[2]);
    enum_field.kind = FieldKind::enumeration;
    enum_field.referenced_enum = EnumKey{99};
    expect_failure(missing_enum, "unknown_field_reference");
    Reader enum_owner;
    std::get<EnumValueRecord>(enum_owner.records[4]).owner = EnumKey{99};
    expect_failure(enum_owner, "unknown_enum_owner");
    Reader pointers;
    auto& pointer = std::get<FieldRecord>(pointers.records[2]);
    pointer.kind = FieldKind::pointer;
    pointer.referenced_type = TypeKey{2};
    check(ReflectionCatalog::read(pointers, profile()).has_value(), "pointer self-reference is valid, not inheritance cycle");
    Reader short_pointer;
    auto& invalid_pointer = std::get<FieldRecord>(short_pointer.records[2]);
    invalid_pointer.kind = FieldKind::pointer;
    invalid_pointer.referenced_type = TypeKey{2};
    invalid_pointer.size = 4;
    expect_failure(short_pointer, "invalid_pointer_size");
    Reader object;
    auto& invalid_object = std::get<FieldRecord>(object.records[2]);
    invalid_object.kind = FieldKind::object;
    invalid_object.referenced_type = TypeKey{2};
    expect_failure(object, "invalid_object_size");
    Reader missing_object;
    std::get<FieldRecord>(missing_object.records[2]).kind = FieldKind::object;
    expect_failure(missing_object, "invalid_field_kind");
    for (const auto untyped_kind : {FieldKind::pointer, FieldKind::array, FieldKind::map}) {
        Reader untyped;
        std::get<FieldRecord>(untyped.records[2]).kind = untyped_kind;
        check(ReflectionCatalog::read(untyped, profile()).has_value(),
              "pointer and collection storage may have primitive or unreflected targets");
    }
}

void test_limits_and_names() {
    Reader max_records;
    ReflectionLimits limits;
    limits.max_records = 5;
    expect_failure(max_records, "record_budget", limits);
    Reader memory;
    limits = {};
    limits.max_retained_bytes = 1;
    expect_failure(memory, "retained_bytes_budget", limits);
    Reader capacity;
    std::get<TypeRecord>(capacity.records[0]).name.reserve(1024U * 1024U);
    limits.max_retained_bytes = 4096;
    expect_failure(capacity, "retained_bytes_budget", limits);
    Reader bad_policy;
    limits.max_records = std::numeric_limits<std::size_t>::max();
    expect_failure(bad_policy, "invalid_reflection_limits", limits);
    check(bad_policy.calls == 0, "unbounded policy rejected before reader access");
    Reader name;
    std::get<TypeRecord>(name.records[0]).name = "unsafe\nname";
    expect_failure(name, "invalid_metadata_name");
    Reader long_name;
    std::get<TypeRecord>(long_name.records[0]).name.assign(4097, 'a');
    expect_failure(long_name, "invalid_metadata_name");
    Reader signature;
    std::get<SliFunctionRecord>(signature.records[5]).signature = "unsafe\nsignature";
    expect_failure(signature, "invalid_sli_signature");
    for (const auto* value : {"18446744073709551616", "-9223372036854775809", "1.5", "01", "+1", "-0", ""}) {
        Reader invalid;
        std::get<EnumValueRecord>(invalid.records[4]).value = value;
        expect_failure(invalid, "invalid_enum_value");
    }
    Reader signed_enum;
    std::get<EnumValueRecord>(signed_enum.records[4]).value = "-9223372036854775808";
    check(ReflectionCatalog::read(signed_enum, profile()).has_value(), "signed 64-bit lower bound preserved");
}

void test_cancellation_and_errors() {
    std::stop_source immediate;
    immediate.request_stop();
    Reader unused;
    auto cancelled = ReflectionCatalog::read(unused, profile(), {}, immediate.get_token());
    check(!cancelled && cancelled.error().code == DebugErrorCode::cancelled && unused.calls == 0,
          "pre-cancelled discovery does not touch reader");
    for (const bool at_finish : {false, true}) {
        Reader reader;
        std::stop_source source;
        auto cancel = [&source] { source.request_stop(); };
        if (at_finish) reader.on_finish = cancel;
        else reader.on_next = cancel;
        auto result = ReflectionCatalog::read(reader, profile(), {}, source.get_token());
        check(!result && result.error().code == DebugErrorCode::cancelled, "mid-read cancellation publishes no catalog");
    }
    for (int phase = 0; phase < 3; ++phase) {
        Reader reader;
        reader.fail_begin = phase == 0;
        reader.fail_next = phase == 1;
        reader.fail_finish = phase == 2;
        auto result = ReflectionCatalog::read(reader, profile());
        check(!result && result.error().reason == "runtime_reader_failed", "native reader failure translated");
        if (!result) check(result.error().safe_message.find("private") == std::string::npos,
                           "native diagnostics cannot expose paths or memory");
    }
}

void test_full_record_budget() {
    Reader reader;
    reader.records.clear();
    reader.records.reserve(100000);
    for (std::uint64_t index = 1; index <= 100000; ++index) {
        reader.records.emplace_back(EnumRecord{{index}, "Synthetic"});
    }
    auto result = ReflectionCatalog::read(reader, profile());
    check(result && (*result)->records().size() == 100000, "maximum record budget admitted without truncation");
    check(result && (*result)->retained_bytes() <= ReflectionLimits{}.max_retained_bytes,
          "maximum catalog respects retained capacity budget");
}

}  // namespace

int main() {
    test_profiles();
    test_catalog();
    test_identity_changes();
    test_invalid_graphs();
    test_limits_and_names();
    test_cancellation_and_errors();
    test_full_record_budget();
    if (failures != 0) std::cerr << failures << " Santa Monica test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
