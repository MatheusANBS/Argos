#include "argos_mcp/infrastructure/santa_monica_native_reader.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace argos::domain;
using namespace argos::domain::santamonica;
namespace infra = argos::infrastructure::santamonica;

int failures{};
void check(const bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

constexpr Address module_base = 0x140000000ULL;
constexpr std::uint64_t module_size = 0x10000;
constexpr std::uint64_t names_begin = 0x1000;
constexpr std::uint64_t names_end = 0x2000;
constexpr std::uint64_t table_begin = 0x4000;
constexpr std::uint32_t stride = 80;

Sha256Digest digest(const unsigned char value) {
    Sha256Digest result;
    result.bytes.fill(static_cast<std::byte>(value));
    return result;
}

// A synthetic image shaped like the observed table: no proprietary bytes, only
// the record structure the reader is contracted to parse.
class ImageBuilder {
public:
    ImageBuilder() : bytes_(module_size, std::byte{}) {}

    [[nodiscard]] std::uint64_t put_name(const std::string_view text) {
        const auto rva = next_name_;
        for (const char c : text) bytes_[next_name_++] = static_cast<std::byte>(c);
        bytes_[next_name_++] = std::byte{};
        return rva;
    }

    // Writes a name with no terminator before the end of the names region.
    [[nodiscard]] std::uint64_t put_unterminated() {
        const auto rva = names_end - 8;
        for (std::uint64_t index = rva; index < names_end; ++index) {
            bytes_[index] = static_cast<std::byte>('A');
        }
        return rva;
    }

    void put_record(const std::uint64_t tag_rva, const std::uint64_t size, const std::uint64_t align,
                    const std::uint16_t base = 0xFFFF, const std::uint32_t first = 0,
                    const std::uint32_t count = 0) {
        const auto rva = table_begin + records_ * stride;
        ++records_;
        write64(rva, tag_rva == 0 ? 0 : module_base + tag_rva);
        write64(rva + 0x08, tag_rva == 0 ? 0 : module_base + tag_rva);
        write64(rva + 0x10, size);
        write64(rva + 0x18, align);
        write(rva + 0x20, first, 4);
        write(rva + 0x24, count, 4);
        write(rva + 0x28, base, 2);
        // Must never be followed, even when a type has fields.
        write64(rva + 0x40, std::numeric_limits<std::uint64_t>::max() - 7U);
    }

    void put_raw_record(const std::uint64_t tag_pointer, const std::uint64_t size,
                        const std::uint64_t align) {
        const auto rva = table_begin + records_ * stride;
        ++records_;
        write64(rva, tag_pointer);
        write64(rva + 0x08, tag_pointer);
        write64(rva + 0x10, size);
        write64(rva + 0x18, align);
        write(rva + 0x28, 0xFFFF, 2);
    }

    [[nodiscard]] std::uint64_t table_end() const { return table_begin + records_ * stride; }
    [[nodiscard]] std::vector<std::byte> take() const { return bytes_; }

    void write(const std::uint64_t rva, const std::uint64_t value, const std::uint64_t width) {
        for (std::uint64_t index = 0; index < width; ++index) {
            bytes_[rva + index] = static_cast<std::byte>((value >> (8U * index)) & 0xFFU);
        }
    }
    void write64(const std::uint64_t rva, const std::uint64_t value) {
        for (std::uint64_t index = 0; index < 8; ++index) {
            bytes_[rva + index] = static_cast<std::byte>((value >> (8U * index)) & 0xFFU);
        }
    }
private:
    std::vector<std::byte> bytes_;
    std::uint64_t next_name_{names_begin};
    std::uint64_t records_{};
};

class FakeMemory final : public RuntimeMemoryView {
public:
    FakeMemory(std::vector<std::byte> image, std::string module_name, std::uint64_t declared_size)
        : image_(std::move(image)) {
        auto snapshot = std::make_shared<RuntimeAddressSpaceSnapshot>();
        snapshot->pid = 4242;
        snapshot->process_name = "synthetic";
        if (!module_name.empty()) {
            const std::array<ModuleInfo, 1> modules{
                ModuleInfo{std::move(module_name), "C:/synthetic", module_base, declared_size}};
            snapshot->modules = ModuleIndex::create(modules);
        }
        snapshot->sequence = 1;
        snapshot_ = std::move(snapshot);
    }

    [[nodiscard]] Result<std::size_t> read(const Address address, const std::span<std::byte> destination,
                                           const std::stop_token cancellation) const override {
        ++reads;
        if (cancel_after_read != nullptr) cancel_after_read->request_stop();
        if (cancellation.stop_requested()) {
            return std::unexpected(DebugError{DebugErrorCode::cancelled, "cancelled"});
        }
        if (fail_reads) {
            return std::unexpected(DebugError{DebugErrorCode::io_error, "private native detail"});
        }
        if (address < module_base) {
            ++outside_reads;
            return std::unexpected(DebugError{DebugErrorCode::io_error, "out of range"});
        }
        const auto offset = address - module_base;
        if (offset >= image_.size()) {
            ++outside_reads;
            return std::unexpected(DebugError{DebugErrorCode::io_error, "out of range"});
        }
        const auto available = std::min({destination.size(), image_.size() - offset, fragment_size});
        std::copy_n(std::next(image_.begin(), static_cast<std::ptrdiff_t>(offset)), available,
                    destination.begin());
        return available;
    }

    [[nodiscard]] Result<std::shared_ptr<const RuntimeAddressSpaceSnapshot>> snapshot() const override {
        if (!snapshot_) {
            return std::unexpected(DebugError{DebugErrorCode::invalid_state, "no snapshot"});
        }
        return snapshot_;
    }

    mutable std::size_t reads{};
    mutable std::size_t outside_reads{};
    std::size_t fragment_size{module_size};
    std::stop_source* cancel_after_read{};
    bool fail_reads{false};

private:
    std::vector<std::byte> image_;
    std::shared_ptr<const RuntimeAddressSpaceSnapshot> snapshot_;
};

infra::NativeTypeTableRequest request(const std::uint64_t table_end_rva) {
    infra::NativeTypeTableRequest value;
    value.profile_id = "gow2018-reflection-x64-v2";
    value.module_name = "Synthetic.exe";
    value.module_size = module_size;
    value.module_digest = digest(7);
    value.profile_digest = digest(9);
    value.table_begin_rva = table_begin;
    value.table_end_rva = table_end_rva;
    value.names_begin_rva = names_begin;
    value.names_end_rva = names_end;
    value.process_instance = "synthetic-process-1";
    value.bridge_epoch = "synthetic-epoch-1";
    value.generation = 1;
    return value;
}

void test_profile_identity() {
    auto identity = infra::native_profile_identity(request(table_begin + stride));
    check(identity.has_value(), "native profile identity is accepted by the domain");
    if (identity) {
        check(identity->source == SnapshotSource::native_reader, "the profile declares its source");
        check(identity->bridge_version == 0, "a native profile carries no bridge version");
        check(std::ranges::all_of(identity->bridge_digest.bytes,
                                  [](const std::byte b) { return b == std::byte{}; }),
              "a native profile carries no bridge digest");
    }

    // A native profile must not be able to wear bridge identity, nor a bridge
    // profile to drop it.
    auto masquerade = *identity;
    masquerade.bridge_digest = digest(3);
    masquerade.bridge_version = 1;
    auto rejected = validate_profile_identity(masquerade);
    check(!rejected && rejected.error().reason == "invalid_bridge_identity",
          "a native profile carrying bridge identity is refused");

    auto bridgeless = *identity;
    bridgeless.source = SnapshotSource::bridge;
    auto refused = validate_profile_identity(bridgeless);
    check(!refused && refused.error().reason == "invalid_bridge_identity",
          "a bridge profile without bridge identity is refused");
}

void test_reads_types() {
    ImageBuilder image;
    const auto first = image.put_name("tRecipeItem");
    const auto second = image.put_name("tRecipe");
    const auto third = image.put_name("tCamera::TweenOverride");
    image.put_record(first, 32, 8);
    image.put_record(second, 64, 8);
    image.put_record(third, 24, 16);
    const auto end = image.table_end();

    FakeMemory memory{image.take(), "Synthetic.exe", module_size};
    infra::NativeTypeTableReader reader{memory, request(end)};
    auto profile = infra::native_profile_identity(request(end));
    check(profile.has_value(), "profile builds");
    if (!profile) return;

    auto catalog = ReflectionCatalog::read(reader, *profile);
    check(catalog.has_value(), "a well-formed table is admitted by the domain catalog");
    if (!catalog) return;
    check((*catalog)->records().size() == 3, "every valid record becomes a type");
    check(!(*catalog)->coverage_complete(),
          "coverage is never reported complete: fields, enums and SLI are not covered");
    check((*catalog)->consistency() == Consistency::validated_best_effort,
          "a native snapshot is never reported as stable");
    check(reader.skipped_slots() == 0, "no slot is skipped in a clean table");

    std::vector<std::string> names;
    std::vector<std::uint64_t> sizes;
    for (const auto& record : (*catalog)->records()) {
        const auto& type = std::get<TypeRecord>(record);
        names.push_back(type.name);
        sizes.push_back(type.size);
        check(!type.base.has_value(), "no inheritance is invented for this table");
        check(type.id.value != 0, "every type gets a non-zero id");
    }
    check(std::ranges::find(names, "tRecipeItem") != names.end(), "type names survive");
    check(std::ranges::find(names, "tCamera::TweenOverride") != names.end(),
          "qualified names survive");
    check(std::ranges::find(sizes, std::uint64_t{64}) != sizes.end(), "type sizes survive");

    // Ids are a digest of the name, so the same build yields the same id twice.
    FakeMemory again{ImageBuilder{}.take(), "Synthetic.exe", module_size};
    static_cast<void>(again);
    ImageBuilder repeat;
    const auto repeat_name = repeat.put_name("tRecipeItem");
    repeat.put_record(repeat_name, 32, 8);
    FakeMemory second_memory{repeat.take(), "Synthetic.exe", module_size};
    infra::NativeTypeTableReader second_reader{second_memory, request(repeat.table_end())};
    auto second_catalog = ReflectionCatalog::read(second_reader, *profile);
    check(second_catalog.has_value(), "second read succeeds");
    if (second_catalog && !(*second_catalog)->records().empty()) {
        const auto& repeated = std::get<TypeRecord>((*second_catalog)->records().front());
        const auto& original = std::get<TypeRecord>((*catalog)->records().front());
        const bool same_name = repeated.name == original.name;
        check(!same_name || repeated.id == original.id, "the id of a name is stable across reads");
    }
}

void test_skips_invalid_slots() {
    ImageBuilder image;
    const auto good = image.put_name("tGood");
    const auto unterminated = image.put_unterminated();
    image.put_record(good, 32, 8);
    image.put_record(good, 0, 8);                       // size zero
    image.put_record(good, 32, 3);                      // alignment not a power of two
    image.put_record(good, 32, 0);                      // zero alignment
    image.put_raw_record(module_base + names_end + 16, 32, 8);  // name outside the names region
    image.put_raw_record(0, 32, 8);                     // null name pointer
    image.put_record(unterminated, 32, 8);              // name with no terminator
    const auto end = image.table_end();

    FakeMemory memory{image.take(), "Synthetic.exe", module_size};
    infra::NativeTypeTableReader reader{memory, request(end)};
    auto profile = infra::native_profile_identity(request(end));
    check(profile.has_value(), "profile builds");
    if (!profile) return;
    auto catalog = ReflectionCatalog::read(reader, *profile);
    check(catalog.has_value(), "invalid slots do not abort the read");
    if (!catalog) return;
    check((*catalog)->records().size() == 1, "only the valid record is admitted");
    check(reader.skipped_slots() == 6, "every invalid slot is counted, not silently ignored");
    check(reader.emitted_types() == 1, "emitted count matches the admitted records");
}

void test_module_and_profile_checks() {
    ImageBuilder image;
    const auto name = image.put_name("tGood");
    image.put_record(name, 32, 8);
    const auto end = image.table_end();
    const auto bytes = image.take();

    {
        FakeMemory memory{bytes, "", module_size};
        infra::NativeTypeTableReader reader{memory, request(end)};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "module_not_loaded",
              "a missing module stops the read");
    }
    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size + 4096};
        infra::NativeTypeTableReader reader{memory, request(end)};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "profile_mismatch",
              "a loaded image of another size is refused before any RVA is trusted");
    }
    {
        auto unknown = request(end);
        unknown.profile_id = "not-a-known-family";
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, unknown};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "unsupported_profile",
              "an unknown layout family is unsupported, never guessed");
    }
    {
        auto ragged = request(end + 7);
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, ragged};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "invalid_build_profile",
              "a span that is not a whole number of records is refused");
    }
    {
        auto beyond = request(module_size + stride);
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, beyond};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "invalid_build_profile",
              "a table outside the module is refused");
    }
    {
        auto undigested = request(end);
        undigested.module_digest = {};
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, undigested};
        auto begun = reader.begin({}, {});
        check(!begun && begun.error().reason == "invalid_build_profile",
              "a profile without a module digest is refused");
    }
}

void test_limits_state_and_failures() {
    ImageBuilder image;
    const auto name = image.put_name("tGood");
    image.put_record(name, 32, 8);
    image.put_record(name, 48, 8);
    const auto end = image.table_end();
    const auto bytes = image.take();

    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, request(end)};
        ReflectionLimits limits;
        limits.max_records = 1;
        auto begun = reader.begin(limits, {});
        check(!begun && begun.error().reason == "index_budget" && memory.reads == 0,
              "the record budget bounds preload before reading or allocating slots");
    }
    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, request(end)};
        auto early = reader.next({});
        check(!early && early.error().reason == "reader_state", "next before begin is refused");
        auto after = reader.begin({}, {});
        check(!after && after.error().reason == "reader_state", "a failed reader stays failed");
    }
    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, request(end)};
        check(reader.begin({}, {}).has_value(), "begin succeeds");
        auto early = reader.finish({});
        check(!early && early.error().reason == "reader_state", "finish before the end is refused");
    }
    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, request(end)};
        std::stop_source source;
        check(reader.begin({}, {}).has_value(), "begin succeeds");
        source.request_stop();
        auto cancelled = reader.next(source.get_token());
        check(!cancelled && cancelled.error().code == DebugErrorCode::cancelled,
              "cancellation stops the read");
    }
    {
        FakeMemory memory{bytes, "Synthetic.exe", module_size};
        memory.fail_reads = true;
        infra::NativeTypeTableReader reader{memory, request(end)};
        auto failed = reader.begin({}, {});
        check(!failed && failed.error().reason == "native_read_failed",
              "a failing read is reported without native detail");
        if (!failed) {
            check(failed.error().safe_message.find("private") == std::string::npos,
                  "native diagnostics never reach the caller");
        }
    }
}

struct ReflectionFixture {
    ImageBuilder image;
    infra::NativeTypeTableRequest profile;

    ReflectionFixture() {
        image.put_record(image.put_name("tBase"), 8, 8, 0xFFFF, 0, 1);
        image.put_record(image.put_name("tDerived"), 96, 8, 0, 1, 8);
        image.put_record(image.put_name("tInner"), 16, 8, 0xFFFF, 9, 1);
        profile = request(image.table_end());
        profile.attribute_begin_rva = 0x5000;
        profile.attribute_end_rva = 0x5140;  // 10 records, 32 bytes each.
        profile.enum_begin_rva = 0x6000;
        profile.enum_end_rva = 0x6020;
        profile.sli_begin_rva = 0x7000;
        profile.sli_end_rva = 0x7040;
        field(0, "Id", 0, 0, 4, 0);
        field(1, "Id", 0, 0, 4, 0);  // inherited copy outside Base's range
        field(2, "Mode", 1, 8, 4, 1, 0xFFFF, 0);
        field(3, "Text", 1, 16, 8, 6);
        field(4, "Items", 1, 24, 12, 9);
        field(5, "Embedded", 1, 40, 0, 11, 2);
        field(6, "NestedView", 2, 0, 4, 0, 0xFFFF, 0xFFFF, 5);
        field(7, "Parent", 1, 56, 8, 7, 0);
        field(8, "UnknownMap", 1, 64, 0, 10);
        field(9, "InnerValue", 2, 0, 4, 0);
        image.write64(0x6000, module_base + image.put_name("ModeEnum"));
        image.write(0x600C, 2, 4);
        image.write64(0x6010, module_base + 0x6100);
        image.write64(0x6018, module_base + 0x6200);
        image.write64(0x6100, module_base + image.put_name("None"));
        image.write64(0x6108, module_base + image.put_name("Maximum"));
        image.write64(0x6200, 0);
        image.write64(0x6208, std::numeric_limits<std::uint64_t>::max());
        for (std::uint64_t index = 0; index < 2; ++index) {
            image.write64(0x7000 + index * 32, module_base + image.put_name(index == 0 ? "Read" : "Describe"));
            image.write64(0x7008 + index * 32, module_base + 0x8000);
            image.write64(0x7010 + index * 32, module_base + image.put_name("v"));
        }
    }

    void field(const std::uint64_t index, const std::string_view name, const std::uint16_t owner,
               const std::uint16_t offset, const std::uint16_t size, const std::uint8_t kind,
               const std::uint16_t custom = 0xFFFF, const std::uint16_t enumeration = 0xFFFF,
               const std::uint16_t enclosing = 0xFFFF) {
        const auto rva = 0x5000 + index * 32;
        image.write64(rva, module_base + image.put_name(name));
        image.write(rva + 0x10, offset, 2);
        image.write(rva + 0x12, size, 2);
        image.write(rva + 0x14, static_cast<std::uint64_t>(kind) << 2U, 1);
        image.write(rva + 0x16, owner, 2);
        image.write(rva + 0x18, enclosing, 2);
        image.write(rva + 0x1A, custom, 2);
        image.write(rva + 0x1C, enumeration, 2);
    }
};

void test_full_reflection() {
    ReflectionFixture fixture;
    FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
    memory.fragment_size = 3;
    infra::NativeTypeTableReader reader{memory, fixture.profile};
    auto expected = infra::native_profile_identity(fixture.profile);
    auto catalog = ReflectionCatalog::read(reader, *expected);
    check(catalog.has_value(), "all native record variants integrate with the catalog through fragmented reads");
    if (!catalog) {
        std::cerr << catalog.error().reason << '\n';
        return;
    }
    check(reader.emitted_types() == 3 && reader.emitted_fields() == 7 &&
          reader.emitted_enums() == 1 && reader.emitted_functions() == 2,
          "own declarations are emitted once, inherited copies and nested views are excluded");
    check(reader.skipped_slots() == 1, "a map of unknown size is counted, never guessed");
    check(!(*catalog)->coverage_complete(), "auxiliary tables remain outside the coverage claim");
    check(memory.outside_reads == 0, "no heap member pointer or callback is followed");
    bool base = false, embedded = false, untyped = false, maximum = false;
    for (const auto& record : (*catalog)->records()) {
        if (const auto* type = std::get_if<TypeRecord>(&record); type && type->name == "tDerived") {
            base = type->base.has_value();
        }
        if (const auto* field = std::get_if<FieldRecord>(&record)) {
            if (field->name == "Embedded") embedded = field->size == 16 && field->referenced_type.has_value();
            if (field->name == "Text") untyped = field->kind == FieldKind::pointer && !field->referenced_type;
        }
        if (const auto* value = std::get_if<EnumValueRecord>(&record); value && value->name == "Maximum") {
            maximum = value->value == "18446744073709551615";
        }
    }
    check(base && embedded && untyped && maximum, "inheritance, embedded size, primitive pointer and full u64 survive");
}

void test_reflection_faults() {
    {
        ReflectionFixture fixture;
        fixture.profile.enum_end_rva += 32;
        fixture.image.write64(0x6020, module_base + fixture.image.put_name("ModeEnum"));
        fixture.image.write(0x602C, 0, 4);
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto catalog = ReflectionCatalog::read(reader, *infra::native_profile_identity(fixture.profile));
        check(catalog.has_value() && reader.emitted_enums() == 2,
              "same-named enums retain distinct build-scoped identities");
    }
    for (const auto pointer : {std::uint64_t{0}, module_base - 8,
                              module_base + module_size - 8, std::numeric_limits<std::uint64_t>::max() - 7U}) {
        for (const auto rva : {0x6010U, 0x6018U}) {
            ReflectionFixture fixture;
            fixture.image.write64(rva, pointer);
            FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
            infra::NativeTypeTableReader reader{memory, fixture.profile};
            auto catalog = ReflectionCatalog::read(reader, *infra::native_profile_identity(fixture.profile));
            check(catalog.has_value() && reader.emitted_enums() == 0,
                  "an enum with an invalid array range and its referring field are omitted");
            check(memory.outside_reads == 0, "invalid enum arrays are rejected before any read");
        }
    }
    {
        ReflectionFixture fixture;
        fixture.image.write(0x600C, 4097, 4);
        fixture.image.write64(0x7010, 0);  // unavailable signature
        fixture.image.write(0x5020 + 0x16, 0xFFFF, 2); // invalid owner
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto catalog = ReflectionCatalog::read(reader, *infra::native_profile_identity(fixture.profile));
        check(catalog.has_value() && reader.emitted_enums() == 0 && reader.emitted_functions() == 1,
              "oversized enums, unknown owners and null signatures never become invented metadata");
    }
    {
        ReflectionFixture fixture;
        fixture.image.write(table_begin + stride + 0x24, 0xFFFFFFFF, 4);
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto result = reader.begin({}, {});
        check(!result && result.error().reason == "invalid_attribute_range",
              "a type's canonical attribute window must fit the published table");
    }
    {
        ReflectionFixture fixture;
        fixture.image.write64(0x7008, 0);
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto catalog = ReflectionCatalog::read(reader, *infra::native_profile_identity(fixture.profile));
        check(catalog.has_value() && reader.emitted_functions() == 1,
              "an invalid callback does not hide later valid SLI declarations");
    }
    {
        ReflectionFixture fixture;
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        check(reader.begin({}, {}).has_value(), "I/O failure fixture preloads");
        memory.fail_reads = true;
        for (int index = 0; index < 3; ++index) check(reader.next({}).has_value(), "cached type arrives");
        auto failed = reader.next({});
        check(!failed && failed.error().reason == "native_read_failed", "field I/O failure is terminal");
        check(!reader.next({}) && !reader.finish({}), "I/O failure cannot resume or publish");
    }
    {
        ReflectionFixture fixture;
        fixture.image.write(table_begin + stride + 0x28, 5000, 2);
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        check(reader.begin({}, {}).has_value(), "invalid base fixture preloads");
        check(reader.next({}).has_value(), "base record arrives");
        auto invalid = reader.next({});
        check(!invalid && invalid.error().reason == "invalid_base_index", "invalid inheritance cannot disappear silently");
    }
    {
        ReflectionFixture fixture;
        fixture.image.write(0x5000 + 7 * 32 + 0x1A, 5000, 2);
        fixture.image.write(0x5000 + 3 * 32 + 0x12, 4, 2);
        fixture.image.write(0x5000 + 4 * 32 + 0x12, 1000, 2);
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto catalog = ReflectionCatalog::read(reader, *infra::native_profile_identity(fixture.profile));
        check(catalog.has_value() && reader.emitted_fields() == 4,
              "invalid reference, pointer width and overflowing field size are omitted");
    }
    for (const int fault : {0, 1, 2, 3, 4}) {
        ReflectionFixture fixture;
        if (fault == 0) fixture.profile.attribute_end_rva++;
        if (fault == 1) fixture.profile.enum_end_rva = module_size + 32;
        if (fault == 2) fixture.profile.sli_begin_rva = 0;
        if (fault == 3) fixture.profile.profile_id = "gow2018-typetable-x64";
        if (fault == 4) fixture.profile.max_duration = std::chrono::milliseconds{0};
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        check(!reader.begin({}, {}) && memory.reads == 0,
              "invalid ranges, legacy origin and invalid duration are refused before I/O");
    }
    {
        ReflectionFixture fixture;
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        std::stop_source stop;
        memory.cancel_after_read = &stop;
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        auto cancelled = reader.begin({}, stop.get_token());
        check(!cancelled && cancelled.error().code == DebugErrorCode::cancelled && memory.reads == 1,
              "cancellation during a read is preserved and stops preloading");
    }
    {
        ReflectionFixture fixture;
        fixture.profile.max_duration = std::chrono::milliseconds{10};
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        check(reader.begin({}, {}).has_value(), "deadline fixture preloads");
        std::this_thread::sleep_for(std::chrono::milliseconds{20});
        auto expired = reader.next({});
        check(!expired && expired.error().reason == "native_deadline", "deadline also stops cached emission");
    }
    {
        ReflectionFixture fixture;
        FakeMemory memory{fixture.image.take(), "Synthetic.exe", module_size};
        infra::NativeTypeTableReader reader{memory, fixture.profile};
        ReflectionLimits limits;
        limits.max_retained_bytes = 1;
        check(!reader.begin(limits, {}) && memory.reads == 0, "temporary index storage is bounded before preload");
    }
}

}  // namespace

int main() {
    test_profile_identity();
    test_reads_types();
    test_skips_invalid_slots();
    test_module_and_profile_checks();
    test_limits_state_and_failures();
    test_full_reflection();
    test_reflection_faults();
    if (failures != 0) std::cerr << failures << " Santa Monica native reader test(s) failed\n";
    return failures == 0 ? 0 : 1;
}
