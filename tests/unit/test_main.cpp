#include "argos_mcp/application/analysis_job_manager.hpp"
#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/application/scan_session_manager.hpp"
#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/infrastructure/output_ring_buffer.hpp"
#include "argos_mcp/infrastructure/pdb_type_metadata.hpp"
#include "argos_mcp/protocol/json/value.hpp"
#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

class FakeSession final : public argos::domain::ProcessSession {
public:
    FakeSession() {
        memory_ = {
            std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF},
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}
        };
        modules_ = {argos::domain::ModuleInfo{"fake.dll", "C:\\fake.dll", 0x140000000U, 0x1000U}};
    }

    explicit FakeSession(std::vector<std::byte> memory)
        : memory_(std::move(memory)),
          modules_{argos::domain::ModuleInfo{"fake.dll", "C:\\fake.dll", 0x140000000U, 0x1000U}} {}

    FakeSession(std::vector<std::byte> memory, std::vector<argos::domain::ModuleInfo> modules)
        : memory_(std::move(memory)), modules_(std::move(modules)) {}

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 42U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "fake-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override {
        return argos::domain::AccessMode::read_only;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> read(
        argos::domain::Address address,
        std::span<std::byte> output
    ) const override {
        constexpr argos::domain::Address base = 0x1000U;
        if (address < base) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "address below fake region"
            });
        }
        const auto offset = static_cast<std::size_t>(address - base);
        if (offset > memory_.size() || output.size() > memory_.size() - offset) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "read outside fake region"
            });
        }
        std::copy_n(memory_.begin() + static_cast<std::ptrdiff_t>(offset), output.size(), output.begin());
        return output.size();
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::access_denied, "fake session is read-only"
        });
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{argos::domain::MemoryRegion{
            0x1000U, 0x1000U + memory_.size(), true, false, false, true, "fake"
        }};
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return modules_;
    }

private:
    std::vector<std::byte> memory_{};
    std::vector<argos::domain::ModuleInfo> modules_{};
};

class FakeProvider final : public argos::domain::ProcessMemoryProvider {
public:
    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<argos::domain::ProcessInfo>{argos::domain::ProcessInfo{
            42U, "fake-target", std::nullopt, true
        }};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::ProcessSession>> attach(
        argos::domain::ProcessId pid,
        argos::domain::AccessMode access
    ) const override {
        if (pid != 42U || access != argos::domain::AccessMode::read_only) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::not_found, "fake process not found"
            });
        }
        return std::unique_ptr<argos::domain::ProcessSession>{std::make_unique<FakeSession>()};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::LaunchedProcessSession>> launch(
        const argos::domain::LaunchSpec&,
        argos::domain::AccessMode
    ) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::unsupported, "fake provider does not support launch"
        });
    }
};

struct MutableReadProbe {
    std::atomic<std::size_t> calls{0U};
    std::atomic<bool> short_batch_reads{false};
    std::atomic<bool> oversized_reads{false};
    std::atomic<std::size_t> cancel_after_calls{0U};
    std::stop_source cancellation;
};

class MutableFakeSession final : public argos::domain::ProcessSession {
public:
    explicit MutableFakeSession(
        std::shared_ptr<std::vector<std::byte>> memory,
        std::shared_ptr<MutableReadProbe> probe = nullptr
    ) : memory_(std::move(memory)), probe_(std::move(probe)) {}

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 42U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "fake-mutable-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override {
        return argos::domain::AccessMode::read_only;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> read(
        argos::domain::Address address,
        std::span<std::byte> output
    ) const override {
        if (probe_) {
            const auto call_count = probe_->calls.fetch_add(1U, std::memory_order_relaxed) + 1U;
            const auto cancel_after = probe_->cancel_after_calls.load(std::memory_order_relaxed);
            if (cancel_after != 0U && call_count >= cancel_after) {
                probe_->cancellation.request_stop();
            }
        }
        constexpr argos::domain::Address base = 0x1000U;
        if (address < base) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "address below fake region"
            });
        }
        const auto offset = static_cast<std::size_t>(address - base);
        const std::size_t read_size = probe_ && probe_->short_batch_reads.load(std::memory_order_relaxed) &&
                output.size() > sizeof(std::int32_t)
            ? sizeof(std::int32_t)
            : output.size();
        if (probe_ && probe_->oversized_reads.load(std::memory_order_relaxed)) {
            return output.size() + 1U;
        }
        if (offset > memory_->size() || read_size > memory_->size() - offset) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "read outside fake region"
            });
        }
        std::copy_n(memory_->begin() + static_cast<std::ptrdiff_t>(offset), read_size, output.begin());
        return read_size;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::access_denied, "fake session is read-only"
        });
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{argos::domain::MemoryRegion{
            0x1000U, 0x1000U + memory_->size(), true, false, false, true, "fake-mutable"
        }};
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{};
    }

private:
    std::shared_ptr<std::vector<std::byte>> memory_;
    std::shared_ptr<MutableReadProbe> probe_;
};

template <typename Signed>
[[nodiscard]] std::vector<std::byte> encode_signed(Signed value) {
    static_assert(std::is_integral_v<Signed> && std::is_signed_v<Signed>);
    using Unsigned = std::make_unsigned_t<Signed>;
    std::vector<std::byte> bytes(sizeof(Signed));
    const auto unsigned_value = static_cast<Unsigned>(value);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((unsigned_value >> (index * 8U)) & 0xFFU);
    }
    return bytes;
}

[[nodiscard]] std::vector<std::byte> encode_i32(const std::int32_t value) {
    return encode_signed(value);
}

class SingleSessionFakeProvider final : public argos::domain::ProcessMemoryProvider {
public:
    explicit SingleSessionFakeProvider(
        std::function<std::unique_ptr<argos::domain::ProcessSession>()> factory
    ) : factory_(std::move(factory)) {}

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<argos::domain::ProcessInfo>{argos::domain::ProcessInfo{
            42U, "fake-target", std::nullopt, true
        }};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::ProcessSession>> attach(
        argos::domain::ProcessId pid,
        argos::domain::AccessMode
    ) const override {
        if (pid != 42U) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::not_found, "fake process not found"
            });
        }
        return factory_();
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::LaunchedProcessSession>> launch(
        const argos::domain::LaunchSpec&,
        argos::domain::AccessMode
    ) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::unsupported, "fake provider does not support launch"
        });
    }

private:
    std::function<std::unique_ptr<argos::domain::ProcessSession>()> factory_;
};

class FakeLaunchedSession final : public argos::domain::LaunchedProcessSession {
public:
    explicit FakeLaunchedSession(std::shared_ptr<bool> terminated) : terminated_(std::move(terminated)) {}

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 99U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "fake-launched-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override {
        return argos::domain::AccessMode::read_only;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> read(argos::domain::Address, std::span<std::byte>) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::io_error, "fake launched session has no memory"
        });
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::access_denied, "fake launched session is read-only"
        });
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{};
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{};
    }

    [[nodiscard]] argos::domain::Result<argos::domain::OutputChunk> read_output(std::uint64_t, std::size_t) override {
        argos::domain::OutputChunk chunk;
        chunk.stdout_text = "banner\n";
        chunk.process_alive = !*terminated_;
        return chunk;
    }

    [[nodiscard]] argos::domain::Result<void> terminate() override {
        *terminated_ = true;
        return {};
    }

    [[nodiscard]] bool owned() const noexcept override { return true; }

private:
    std::shared_ptr<bool> terminated_;
};

class FakeLaunchProvider final : public argos::domain::ProcessMemoryProvider {
public:
    explicit FakeLaunchProvider(std::shared_ptr<bool> terminated) : terminated_(std::move(terminated)) {}

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ProcessInfo>> list_processes(
        std::string_view,
        std::size_t
    ) const override {
        return std::vector<argos::domain::ProcessInfo>{};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::ProcessSession>> attach(
        argos::domain::ProcessId pid,
        argos::domain::AccessMode access
    ) const override {
        if (pid != 42U || access != argos::domain::AccessMode::read_only) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::not_found, "fake process not found"
            });
        }
        return std::unique_ptr<argos::domain::ProcessSession>{std::make_unique<FakeSession>()};
    }

    [[nodiscard]] argos::domain::Result<std::unique_ptr<argos::domain::LaunchedProcessSession>> launch(
        const argos::domain::LaunchSpec&,
        argos::domain::AccessMode
    ) const override {
        return std::unique_ptr<argos::domain::LaunchedProcessSession>{
            std::make_unique<FakeLaunchedSession>(terminated_)
        };
    }

private:
    std::shared_ptr<bool> terminated_;
};

class FakeTypeMetadataProvider final : public argos::domain::TypeMetadataProvider {
public:
    [[nodiscard]] argos::domain::Result<argos::domain::TypeMetadata> inspect_pdb(
        std::string_view module_path,
        std::string_view type_name,
        std::size_t max_fields
    ) const override {
        if (module_path != "C:\\fake.dll" || type_name != "FakeType") {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::not_found, "fake type not found"
            });
        }
        return argos::domain::TypeMetadata{
            "FakeType", 8U,
            {argos::domain::TypeField{"value", "u64", 0, 8U}},
            "pdb:test", "high", max_fields < 1U
        };
    }

    [[nodiscard]] argos::domain::Result<argos::domain::TypeMetadata> inspect_unity(
        std::string_view,
        std::string_view,
        std::size_t
    ) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::unsupported, "fake Unity provider unavailable"
        });
    }

    [[nodiscard]] argos::domain::Result<argos::domain::TypeMetadata> inspect_unreal_type(
        std::string_view,
        std::string_view,
        std::size_t
    ) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::unsupported, "fake Unreal provider unavailable"
        });
    }

    [[nodiscard]] argos::domain::Result<argos::domain::ReflectionMetadata> inspect_unreal_reflection(
        std::string_view,
        std::size_t
    ) const override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::unsupported, "fake Unreal reflection provider unavailable"
        });
    }

    [[nodiscard]] argos::domain::Result<argos::domain::TypeCatalog> list_pdb_types(
        std::string_view module_path,
        std::string_view name_filter,
        std::string_view kind_filter,
        std::size_t max_symbols
    ) const override {
        if (module_path != "C:\\fake.dll") {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::not_found, "fake module not found"
            });
        }
        std::vector<argos::domain::TypeSummary> all{
            argos::domain::TypeSummary{"FakeType", "struct", 8U},
            argos::domain::TypeSummary{"OtherType", "class", 16U},
            argos::domain::TypeSummary{"FakeFlags", "enum", 4U}
        };
        std::vector<argos::domain::TypeSummary> filtered;
        for (const auto& summary : all) {
            if (!kind_filter.empty() && summary.kind != kind_filter) continue;
            if (!name_filter.empty() && summary.name.find(name_filter) == std::string::npos) continue;
            filtered.push_back(summary);
        }
        const bool truncated = filtered.size() > max_symbols;
        if (truncated) filtered.resize(max_symbols);
        return argos::domain::TypeCatalog{std::move(filtered), "pdb:dbghelp", "high", truncated};
    }
};

void test_json() {
    namespace json = argos::protocol::json;

    auto parsed = argos::protocol::json::parse(
        R"({"jsonrpc":"2.0","id":1,"params":{"ok":true,"values":[1,2,3]}})"
    );
    check(parsed.has_value(), "JSON parser accepts a valid request");
    if (!parsed) return;
    check(parsed->at("jsonrpc").as_string() == "2.0", "JSON string field is available");
    const std::string dumped = parsed->dump();
    auto round_trip = argos::protocol::json::parse(dumped);
    check(round_trip.has_value(), "JSON round trip succeeds");
    check(!argos::protocol::json::parse("{bad").has_value(), "JSON parser rejects malformed input");

    std::string maximum_input(json::max_parse_input_bytes, ' ');
    maximum_input.back() = '0';
    check(json::parse(maximum_input).has_value(), "JSON parser accepts input at the size limit");
    maximum_input.push_back(' ');
    const auto oversized = json::parse(maximum_input);
    check(!oversized.has_value(), "JSON parser rejects input above the 8 MiB limit");
    if (!oversized) {
        check(oversized.error().offset <= maximum_input.size() && !oversized.error().message.empty(),
              "oversized JSON returns a bounded, non-empty ParseError");
    }

    const auto nested_json = [](const std::size_t depth) {
        std::string text(depth, '[');
        text.push_back('0');
        text.append(depth, ']');
        return text;
    };
    check(json::parse(nested_json(json::max_parse_nesting_depth)).has_value(),
          "JSON parser accepts nesting at the depth limit");
    const auto too_deep = json::parse(nested_json(json::max_parse_nesting_depth + 1U));
    check(!too_deep.has_value(), "JSON parser rejects nesting above 128 levels");
    if (!too_deep) {
        check(too_deep.error().message == "maximum nesting depth exceeded",
              "excessive JSON nesting returns a safe ParseError");
    }

    std::string maximum_nodes{"["};
    maximum_nodes.reserve(json::max_parse_nodes * 5U);
    for (std::size_t index = 1U; index < json::max_parse_nodes; ++index) {
        if (index > 1U) maximum_nodes.push_back(',');
        maximum_nodes.append("null");
    }
    maximum_nodes.push_back(']');
    check(json::parse(maximum_nodes).has_value(), "JSON parser accepts the bounded maximum node count");
    maximum_nodes.insert(maximum_nodes.size() - 1U, ",null");
    const auto too_many_nodes = json::parse(maximum_nodes);
    check(!too_many_nodes.has_value() &&
              too_many_nodes.error().message == "maximum JSON node count exceeded",
          "JSON parser rejects flat containers that amplify beyond the DOM node budget");

    const json::Value nonfinite = json::Value::array({
        std::numeric_limits<double>::quiet_NaN(),
        std::numeric_limits<double>::infinity(),
        -std::numeric_limits<double>::infinity()
    });
    const std::string nonfinite_dump = nonfinite.dump();
    check(nonfinite_dump == "[null,null,null]",
          "JSON dump serializes NaN and infinities as null");
    check(json::parse(nonfinite_dump).has_value(),
          "JSON dump containing non-finite source values remains valid JSON");
}

void test_policy() {
    argos::security::SecurityPolicy policy;
    check(!policy.authorize_attach(false, argos::domain::AccessMode::read_only).has_value(),
          "attach requires explicit authorization");
    check(!policy.authorize_attach(true, argos::domain::AccessMode::read_write).has_value(),
          "write session is disabled by default");
    check(policy.authorize_read(32U).has_value(), "small read is allowed");
    check(!policy.authorize_read(policy.max_read_bytes + 1U).has_value(), "oversized read is denied");
}

void test_memory_service() {
    argos::security::SecurityPolicy policy;
    auto provider = std::make_unique<FakeProvider>();
    argos::application::MemoryDebugService service{std::move(provider), policy};
    auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
    check(attached.has_value(), "authorized fake process attaches");
    if (!attached) return;

    auto bytes = service.read_memory(attached->id, 0x1000U, 8U);
    check(bytes.has_value(), "authorized memory read succeeds");
    if (bytes) {
        check(bytes->size() == 8U, "memory read returns expected size");
        check(std::to_integer<unsigned int>((*bytes)[0]) == 0xDEU, "memory content matches");
    }

    const std::array<std::byte, 2> pattern{std::byte{0xBE}, std::byte{0xEF}};
    auto scan = service.scan_exact(attached->id, pattern, 1U, 8U, 8U, false);
    check(scan.has_value(), "exact scan succeeds");
    if (scan) {
        check(scan->matches.size() == 1U && scan->matches[0].address == 0x1002U,
              "exact scan finds the expected address");
    }

    std::stop_source cancelled;
    cancelled.request_stop();
    auto cancelled_scan = service.scan_exact(
        attached->id, pattern, 1U, 8U, 8U, false, std::nullopt, std::nullopt,
        cancelled.get_token()
    );
    check(!cancelled_scan.has_value() &&
          cancelled_scan.error().code == argos::domain::DebugErrorCode::cancelled,
          "scan observes cooperative cancellation");
    check(service.detach(attached->id).has_value(), "session detaches cleanly");
}

void test_pdb_metadata_service() {
    argos::security::SecurityPolicy policy;
    auto provider = std::make_unique<FakeProvider>();
    auto metadata = std::make_unique<FakeTypeMetadataProvider>();
    argos::application::MemoryDebugService service{std::move(provider), policy, std::move(metadata)};
    auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
    check(attached.has_value(), "metadata test attaches fake process");
    if (!attached) return;

    auto type = service.pdb_type(attached->id, "fake.dll", "FakeType", 16U);
    check(type.has_value(), "PDB metadata provider returns a type");
    if (type) {
        check(type->size == 8U && type->fields.size() == 1U, "PDB metadata preserves layout");
        check(type->confidence == "high", "PDB metadata preserves confidence");
    }
    auto rejected = service.pdb_type(attached->id, "outside.dll", "FakeType", 16U);
    check(!rejected.has_value() && rejected.error().code == argos::domain::DebugErrorCode::not_found,
          "metadata cannot inspect a module outside the attached session");

    auto unity = service.unity_type(attached->id, "fake.dll", "FakeType", 16U);
    check(!unity.has_value() && unity.error().code == argos::domain::DebugErrorCode::unsupported,
          "Unity metadata stays behind the provider boundary");
    auto unreal = service.unreal_type(attached->id, "fake.dll", "FGameState", 16U);
    check(!unreal.has_value() && unreal.error().code == argos::domain::DebugErrorCode::unsupported,
          "Unreal type metadata stays behind the provider boundary");
    auto reflection = service.unreal_reflection(attached->id, "fake.dll", 16U);
    check(!reflection.has_value() && reflection.error().code == argos::domain::DebugErrorCode::unsupported,
          "Unreal reflection stays behind the provider boundary");

    auto catalog = service.pdb_list_types(attached->id, "fake.dll", "", "", 16U);
    check(catalog.has_value() && catalog->types.size() == 3U, "pdb_list_types returns the full fake catalog");

    auto struct_only = service.pdb_list_types(attached->id, "fake.dll", "", "struct", 16U);
    check(struct_only.has_value() && struct_only->types.size() == 1U &&
              struct_only->types[0].name == "FakeType",
          "kind_filter narrows the catalog");

    auto name_filtered = service.pdb_list_types(attached->id, "fake.dll", "Fake", "", 16U);
    check(name_filtered.has_value() && name_filtered->types.size() == 2U,
          "name_filter narrows the catalog by substring");

    auto truncated_catalog = service.pdb_list_types(attached->id, "fake.dll", "", "", 1U);
    check(truncated_catalog.has_value() && truncated_catalog->types.size() == 1U && truncated_catalog->truncated,
          "max_symbols truncates the catalog and marks truncated");

    auto catalog_outside_session = service.pdb_list_types(attached->id, "outside.dll", "", "", 16U);
    check(!catalog_outside_session.has_value() &&
              catalog_outside_session.error().code == argos::domain::DebugErrorCode::not_found,
          "pdb_list_types cannot inspect a module outside the attached session");
}

void test_scan_pointers_to() {
    argos::security::SecurityPolicy policy;
    constexpr std::uint64_t target8 = 0xAABBCCDD11223344ULL;
    constexpr std::uint32_t target4 = 0xCAFEBABEU;
    std::vector<std::byte> memory;
    for (std::size_t index = 0; index < 8U; ++index) {
        memory.push_back(static_cast<std::byte>((target8 >> (index * 8U)) & 0xFFU));
    }
    memory.push_back(std::byte{0x00});
    memory.push_back(std::byte{0x00});
    memory.push_back(std::byte{0x00});
    memory.push_back(std::byte{0x00});
    for (std::size_t index = 0; index < 4U; ++index) {
        memory.push_back(static_cast<std::byte>((target4 >> (index * 8U)) & 0xFFU));
    }
    for (std::size_t index = 0; index < 8U; ++index) {
        memory.push_back(static_cast<std::byte>((target8 >> (index * 8U)) & 0xFFU));
    }

    const auto make_provider = [memory]() {
        return std::make_unique<SingleSessionFakeProvider>(
            [memory]() -> std::unique_ptr<argos::domain::ProcessSession> {
                return std::make_unique<FakeSession>(memory);
            }
        );
    };

    {
        argos::application::MemoryDebugService service{make_provider(), policy};
        auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointers_to test attaches fake process (8-byte)");
        if (!attached) return;

        std::array<std::byte, 8> manual_pattern{};
        for (std::size_t index = 0; index < 8U; ++index) {
            manual_pattern[index] = static_cast<std::byte>((target8 >> (index * 8U)) & 0xFFU);
        }
        auto manual = service.scan_exact(attached->id, manual_pattern, 8U, 4096U, 256U, false);
        auto via_helper = service.scan_pointers_to(attached->id, target8, 8U, 4096U, 256U, false);
        check(manual.has_value() && via_helper.has_value(), "both 8-byte scans succeed");
        if (manual && via_helper) {
            check(manual->matches.size() == 2U, "8-byte target appears twice in fixture");
            check(manual->matches.size() == via_helper->matches.size() &&
                      std::equal(
                          manual->matches.begin(), manual->matches.end(), via_helper->matches.begin(),
                          [](const auto& lhs, const auto& rhs) { return lhs.address == rhs.address; }
                      ),
                  "scan_pointers_to matches scan_exact with the manually encoded pattern");
            check(manual->bytes_scanned == via_helper->bytes_scanned, "byte accounting matches between both calls");
        }

        auto bad_pointer_size = service.scan_pointers_to(attached->id, target8, 6U, 4096U, 256U, false);
        check(!bad_pointer_size.has_value() &&
                  bad_pointer_size.error().code == argos::domain::DebugErrorCode::invalid_argument,
              "invalid pointer_size is rejected");
        auto zero_target = service.scan_pointers_to(attached->id, 0U, 8U, 4096U, 256U, false);
        check(!zero_target.has_value() &&
                  zero_target.error().code == argos::domain::DebugErrorCode::invalid_argument,
              "zero target_address is rejected");
    }
    {
        argos::application::MemoryDebugService service{make_provider(), policy};
        auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointers_to test attaches fake process (4-byte)");
        if (!attached) return;

        std::array<std::byte, 4> manual_pattern{};
        for (std::size_t index = 0; index < 4U; ++index) {
            manual_pattern[index] = static_cast<std::byte>((target4 >> (index * 8U)) & 0xFFU);
        }
        auto manual = service.scan_exact(attached->id, manual_pattern, 4U, 4096U, 256U, false);
        auto via_helper = service.scan_pointers_to(attached->id, target4, 4U, 4096U, 256U, false);
        check(manual.has_value() && via_helper.has_value() &&
                  manual->matches.size() == via_helper->matches.size() &&
                  !manual->matches.empty() && manual->matches[0].address == via_helper->matches[0].address,
              "4-byte scan_pointers_to matches scan_exact with the manually encoded pattern");
    }
}

void test_scan_pointer_chains() {
    namespace domain = argos::domain;
    namespace application = argos::application;

    argos::security::SecurityPolicy policy;

    const auto put_ptr64 = [](std::vector<std::byte>& m, std::uint64_t v) {
        for (std::size_t i = 0; i < 8; ++i) {
            m.push_back(static_cast<std::byte>((v >> (i * 8U)) & 0xFFU));
        }
    };
    const auto put_ptr32 = [](std::vector<std::byte>& m, std::uint32_t v) {
        for (std::size_t i = 0; i < 4; ++i) {
            m.push_back(static_cast<std::byte>((v >> (i * 8U)) & 0xFFU));
        }
    };

    constexpr std::uint64_t target8 = 0xAABBCCDDEEFF0011ULL;

    const auto make_service = [](
        std::vector<std::byte> memory,
        std::vector<domain::ModuleInfo> modules,
        argos::security::SecurityPolicy pol
    ) {
        auto provider = std::make_unique<SingleSessionFakeProvider>(
            [memory, modules]() -> std::unique_ptr<domain::ProcessSession> {
                return std::make_unique<FakeSession>(memory, modules);
            }
        );
        return application::MemoryDebugService{std::move(provider), pol};
    };

    // Case A: two-hop chain (8-byte).
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 8U; ++i) memory.push_back(std::byte{0x00});  // filler at 0x1000
        put_ptr64(memory, 0x1010U);   // X_2 slot at 0x1008 -> 0x1010
        put_ptr64(memory, target8);   // X_1 slot at 0x1010 -> target

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case A attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case A: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.size() == 1U, "case A: exactly one candidate found");
                if (result->candidates.size() == 1U) {
                    const auto& candidate = result->candidates[0];
                    check(candidate.hop_offsets == std::vector<std::int64_t>{8, 0},
                          "case A: hop_offsets == {8, 0}");
                    check(candidate.module_base == 0x1000U, "case A: module_base == 0x1000");
                    check(candidate.module_name == "game.exe", "case A: module_name == game.exe");
                    check(candidate.resolved_address == 0x1010U, "case A: resolved_address == 0x1010");
                }
                check(!result->truncated, "case A: not truncated");
            }

            std::array<std::int64_t, 2> offsets{8, 0};
            auto resolved = service.resolve_pointer_chain(attached->id, 0x1000U, offsets, 8U);
            check(resolved.has_value() && *resolved == 0x1010U,
                  "case A: resolve_pointer_chain reproduces level-1 finding");
        }
    }

    // Case B: one-hop degenerate (8-byte).
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 8U; ++i) memory.push_back(std::byte{0x00});  // filler at 0x1000
        put_ptr64(memory, target8);  // X_1 slot at 0x1008 -> target

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case B attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case B: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.size() == 1U, "case B: exactly one candidate found");
                if (result->candidates.size() == 1U) {
                    const auto& candidate = result->candidates[0];
                    check(candidate.hop_offsets == std::vector<std::int64_t>{8},
                          "case B: hop_offsets == {8}");
                    check(candidate.resolved_address == 0x1008U, "case B: resolved_address == 0x1008");
                }
                check(!result->truncated, "case B: not truncated");
            }
        }
    }

    // Case C: target already inside a module (short-circuit).
    {
        std::vector<std::byte> memory(16U, std::byte{0x00});
        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case C attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, 0x1008U, 8U, 8U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case C: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.empty(), "case C: no candidates when target already in module");
                check(result->bytes_scanned == 0U, "case C: bytes_scanned == 0");
                check(!result->truncated, "case C: not truncated");
            }
        }
    }

    // Case D: invalid pointer_size.
    {
        std::vector<std::byte> memory(16U, std::byte{0x00});
        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };
        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case D attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 6U, 8U, 16U, 4096U, 32U, false
            );
            check(!result.has_value() && result.error().code == domain::DebugErrorCode::invalid_argument,
                  "case D: invalid pointer_size rejected");
        }
    }

    // Case E: zero target.
    {
        std::vector<std::byte> memory(16U, std::byte{0x00});
        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };
        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case E attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, 0U, 8U, 8U, 16U, 4096U, 32U, false
            );
            check(!result.has_value() && result.error().code == domain::DebugErrorCode::invalid_argument,
                  "case E: zero target rejected");
        }
    }

    // Case F: limit rejections (depth cap 8, fanout cap 16) using the case A fixture.
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 8U; ++i) memory.push_back(std::byte{0x00});
        put_ptr64(memory, 0x1010U);
        put_ptr64(memory, target8);

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case F attaches fake process");
        if (attached) {
            auto zero_depth = service.scan_pointer_chains(
                attached->id, target8, 8U, 0U, 16U, 4096U, 32U, false
            );
            check(!zero_depth.has_value() && zero_depth.error().code == domain::DebugErrorCode::limit_exceeded,
                  "case F: max_depth == 0 rejected");

            auto too_deep = service.scan_pointer_chains(
                attached->id, target8, 8U, 9U, 16U, 4096U, 32U, false
            );
            check(!too_deep.has_value() && too_deep.error().code == domain::DebugErrorCode::limit_exceeded,
                  "case F: max_depth above cap rejected");

            auto zero_fanout = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 0U, 4096U, 32U, false
            );
            check(!zero_fanout.has_value() && zero_fanout.error().code == domain::DebugErrorCode::limit_exceeded,
                  "case F: max_fanout == 0 rejected");

            auto too_wide = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 17U, 4096U, 32U, false
            );
            check(!too_wide.has_value() && too_wide.error().code == domain::DebugErrorCode::limit_exceeded,
                  "case F: max_fanout above cap rejected");
        }
    }

    // Case G: max_depth too shallow -> empty candidates, truncated == true.
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 8U; ++i) memory.push_back(std::byte{0x00});
        put_ptr64(memory, 0x1010U);
        put_ptr64(memory, target8);

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case G attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 8U, 1U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case G: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.empty(), "case G: no candidates when depth exhausted too shallow");
                check(result->truncated, "case G: truncated == true when depth exhausted");
            }
        }
    }

    // Case H: tiny byte_budget -> truncated mid-BFS.
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 8U; ++i) memory.push_back(std::byte{0x00});
        put_ptr64(memory, 0x1010U);
        put_ptr64(memory, target8);

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case H attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 16U, 1U, 32U, false
            );
            check(result.has_value(), "case H: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.empty(), "case H: no candidates with tiny byte_budget");
                check(result->truncated, "case H: truncated == true with tiny byte_budget");
                check(result->bytes_scanned <= 1U, "case H: bytes_scanned bounded by byte_budget");
            }
        }
    }

    // Case I: four-byte pointer variant.
    {
        std::vector<std::byte> memory;
        for (std::size_t i = 0; i < 4U; ++i) memory.push_back(std::byte{0x00});  // filler at 0x1000
        put_ptr32(memory, 0x1008U);         // X_2 slot at 0x1004 -> 0x1008
        put_ptr32(memory, 0xCAFEBABEU);     // X_1 slot at 0x1008 -> target

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x8U}
        };

        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case I attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, 0xCAFEBABEULL, 4U, 8U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case I: scan_pointer_chains succeeds");
            if (result) {
                check(result->candidates.size() == 1U, "case I: exactly one candidate found");
                if (result->candidates.size() == 1U) {
                    const auto& candidate = result->candidates[0];
                    check(candidate.hop_offsets == std::vector<std::int64_t>{4, 0},
                          "case I: hop_offsets == {4, 0}");
                    check(candidate.resolved_address == 0x1008U, "case I: resolved_address == 0x1008");
                    check(candidate.module_base == 0x1000U, "case I: module_base == 0x1000");
                }
            }
            auto too_wide_target = service.scan_pointer_chains(
                attached->id, 0x1'0000'0000ULL, 4U, 8U, 16U, 4096U, 32U, false
            );
            check(!too_wide_target.has_value() &&
                      too_wide_target.error().code == domain::DebugErrorCode::invalid_argument,
                  "case I: a target wider than a 32-bit pointer is rejected");
        }
    }

    // Case J: a branching frontier is scanned once per depth, not once per
    // frontier item. Two heap slots point to the target; two module slots point
    // to those heap slots. A 48-byte region therefore costs exactly two sweeps.
    {
        std::vector<std::byte> memory;
        put_ptr64(memory, 0x1020U);  // module + 0x0 -> heap slot A
        put_ptr64(memory, 0x1028U);  // module + 0x8 -> heap slot B
        put_ptr64(memory, 0U);
        put_ptr64(memory, 0U);
        put_ptr64(memory, target8);  // heap slot A -> target
        put_ptr64(memory, target8);  // heap slot B -> target

        std::vector<domain::ModuleInfo> modules{
            domain::ModuleInfo{"game.exe", "C:\\game.exe", 0x1000U, 0x10U}
        };
        auto service = make_service(memory, modules, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan_pointer_chains case J attaches fake process");
        if (attached) {
            auto result = service.scan_pointer_chains(
                attached->id, target8, 8U, 8U, 16U, 4096U, 32U, false
            );
            check(result.has_value(), "case J: branching pointer-chain scan succeeds");
            if (result) {
                check(result->candidates.size() == 2U,
                      "case J: both stable module anchors are returned");
                check(result->bytes_scanned == 96U,
                      "case J: the 48-byte address space is read once for each of two depths");
                check(!result->truncated, "case J: a fully covered branching scan is not truncated");
            }
        }
    }
}

void test_scan_sessions() {
    namespace domain = argos::domain;
    namespace application = argos::application;

    const auto make_memory = [] {
        auto memory = std::make_shared<std::vector<std::byte>>();
        const auto append = [&memory](std::int32_t value) {
            auto bytes = encode_i32(value);
            memory->insert(memory->end(), bytes.begin(), bytes.end());
        };
        append(100);
        append(200);
        append(50);
        append(300);
        return memory;
    };
    const auto make_service = [](std::shared_ptr<std::vector<std::byte>> memory, argos::security::SecurityPolicy policy) {
        auto provider = std::make_unique<SingleSessionFakeProvider>(
            [memory]() -> std::unique_ptr<domain::ProcessSession> {
                return std::make_unique<MutableFakeSession>(memory);
            }
        );
        return argos::application::MemoryDebugService{std::move(provider), policy};
    };

    {
        auto memory = make_memory();
        argos::security::SecurityPolicy policy;
        auto service = make_service(memory, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan session test attaches fake process");
        if (!attached) return;

        auto first = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
            std::nullopt, std::nullopt, 4096U, 256U, false
        );
        check(first.has_value() && first->info.candidate_count == 4U, "scan_first(unknown) captures all aligned candidates");
        if (!first) return;

        (*memory)[0] = encode_i32(90)[0]; (*memory)[1] = encode_i32(90)[1];
        (*memory)[2] = encode_i32(90)[2]; (*memory)[3] = encode_i32(90)[3];
        auto slot2_new = encode_i32(80);
        std::copy(slot2_new.begin(), slot2_new.end(), memory->begin() + 8);
        auto slot3_new = encode_i32(250);
        std::copy(slot3_new.begin(), slot3_new.end(), memory->begin() + 12);

        auto decreased = service.scan_next(first->info.id, domain::ScanComparison::decreased, std::nullopt, std::nullopt);
        check(decreased.has_value() && decreased->candidate_count == 2U,
              "scan_next(decreased) keeps only candidates whose value went down");

        auto results = service.scan_results(first->info.id, 0U, 50U);
        check(results.has_value() && results->size() == 2U, "scan_results returns the surviving candidates");

        auto reset = service.scan_reset(first->info.id);
        check(reset.has_value(), "scan_reset succeeds");
        auto after_reset = service.scan_results(first->info.id, 0U, 50U);
        check(after_reset.has_value() && after_reset->empty(), "scan_reset clears candidates");

        auto detach_result = service.detach(attached->id);
        check(detach_result.has_value(), "debug session detaches");
        auto after_detach = service.scan_results(first->info.id, 0U, 50U);
        check(!after_detach.has_value() && after_detach.error().code == domain::DebugErrorCode::not_found,
              "scan sessions do not survive detach of the owning session");
    }
    {
        auto memory = make_memory();
        argos::security::SecurityPolicy policy;
        auto service = make_service(memory, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "exact scan test attaches fake process");
        if (!attached) return;

        auto exact = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::exact,
            encode_i32(200), std::nullopt, 4096U, 256U, false
        );
        check(exact.has_value() && exact->info.candidate_count == 1U, "scan_first(exact) finds the single matching candidate");

        auto in_range = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::in_range,
            std::nullopt, std::pair{encode_i32(60), encode_i32(250)}, 4096U, 256U, false
        );
        check(in_range.has_value() && in_range->info.candidate_count == 2U,
              "scan_first(in_range) keeps only candidates within [low, high]");
        if (in_range) {
            auto unsupported_in_range_next = service.scan_next(
                in_range->info.id, domain::ScanComparison::in_range, std::nullopt, std::nullopt
            );
            check(!unsupported_in_range_next.has_value() &&
                      unsupported_in_range_next.error().code == domain::DebugErrorCode::invalid_argument,
                  "scan_next does not support in_range (no range parameter is available on that call)");
        }

        auto missing_value = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::exact,
            std::nullopt, std::nullopt, 4096U, 256U, false
        );
        check(!missing_value.has_value() &&
                  missing_value.error().code == domain::DebugErrorCode::invalid_argument,
              "scan_first(exact) requires a value");
    }
    {
        // Start one byte into the region so a naturally aligned i32 straddles
        // the reusable 64 KiB chunk boundary. This guards the optimized
        // aligned-step loop and its cross-chunk carry handling.
        constexpr std::size_t chunk_size = 64U * 1024U;
        auto memory = std::make_shared<std::vector<std::byte>>(chunk_size + 16U, std::byte{0});
        const auto needle = encode_i32(0x12345678);
        std::copy(needle.begin(), needle.end(), memory->begin() + static_cast<std::ptrdiff_t>(chunk_size));

        argos::security::SecurityPolicy policy;
        auto service = make_service(memory, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "cross-chunk scan fixture attaches fake process");
        if (!attached) return;

        auto exact = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::exact,
            needle, std::nullopt, memory->size() - 1U, 256U, false,
            domain::Address{0x1001U}
        );
        check(exact.has_value() && exact->info.candidate_count == 1U,
              "scan_first preserves a naturally aligned match spanning two reused chunks");
        if (exact) {
            check(exact->coverage.complete(), "cross-chunk scan reports complete coverage");
        }
    }
    {
        auto memory = make_memory();
        argos::security::SecurityPolicy policy;
        auto service = make_service(memory, policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "increased_by scan test attaches fake process");
        if (!attached) return;

        auto first = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
            std::nullopt, std::nullopt, 4096U, 256U, false
        );
        check(first.has_value(), "unknown scan succeeds for increased_by fixture");
        if (!first) return;

        auto slot2_new = encode_i32(80);
        std::copy(slot2_new.begin(), slot2_new.end(), memory->begin() + 8);

        auto increased_by = service.scan_next(
            first->info.id, domain::ScanComparison::increased_by, std::nullopt, encode_i32(30)
        );
        check(increased_by.has_value() && increased_by->candidate_count == 1U,
              "scan_next(increased_by) matches only the candidate that increased by exactly delta");
    }
    {
        const auto exercise_signed_wrap = [&make_service](
            const domain::ScanValueType value_type,
            const std::vector<std::byte>& maximum,
            const std::vector<std::byte>& minimum,
            const std::vector<std::byte>& one
        ) -> std::pair<bool, bool> {
            auto memory = std::make_shared<std::vector<std::byte>>(maximum);
            argos::security::SecurityPolicy policy;
            auto service = make_service(memory, policy);
            auto attached = service.attach(42U, domain::AccessMode::read_only, true);
            if (!attached) return {false, false};

            auto first = service.scan_first(
                attached->id, value_type, domain::ScanComparison::unknown,
                std::nullopt, std::nullopt, 4096U, 256U, false
            );
            if (!first || first->info.candidate_count != 1U) return {false, false};

            *memory = minimum;
            auto increased = service.scan_next(
                first->info.id, domain::ScanComparison::increased_by, std::nullopt, one
            );
            if (!increased || increased->candidate_count != 1U) return {false, false};

            *memory = maximum;
            auto decreased = service.scan_next(
                first->info.id, domain::ScanComparison::decreased_by, std::nullopt, one
            );
            return {true, decreased.has_value() && decreased->candidate_count == 1U};
        };

        const auto i8_wrap = exercise_signed_wrap(
            domain::ScanValueType::i8,
            encode_signed(std::numeric_limits<std::int8_t>::max()),
            encode_signed(std::numeric_limits<std::int8_t>::min()),
            encode_signed<std::int8_t>(1)
        );
        check(i8_wrap.first && i8_wrap.second,
              "signed i8 delta comparisons wrap at extrema without undefined behavior");

        const auto i16_wrap = exercise_signed_wrap(
            domain::ScanValueType::i16,
            encode_signed(std::numeric_limits<std::int16_t>::max()),
            encode_signed(std::numeric_limits<std::int16_t>::min()),
            encode_signed<std::int16_t>(1)
        );
        check(i16_wrap.first && i16_wrap.second,
              "signed i16 delta comparisons wrap at extrema without undefined behavior");

        const auto i32_wrap = exercise_signed_wrap(
            domain::ScanValueType::i32,
            encode_signed(std::numeric_limits<std::int32_t>::max()),
            encode_signed(std::numeric_limits<std::int32_t>::min()),
            encode_signed<std::int32_t>(1)
        );
        check(i32_wrap.first && i32_wrap.second,
              "signed i32 delta comparisons wrap at extrema without undefined behavior");

        const auto i64_wrap = exercise_signed_wrap(
            domain::ScanValueType::i64,
            encode_signed(std::numeric_limits<std::int64_t>::max()),
            encode_signed(std::numeric_limits<std::int64_t>::min()),
            encode_signed<std::int64_t>(1)
        );
        check(i64_wrap.first && i64_wrap.second,
              "signed i64 delta comparisons wrap at extrema without undefined behavior");
    }
    {
        auto memory = make_memory();
        argos::security::SecurityPolicy tight_policy;
        tight_policy.max_scan_session_candidates = 2U;
        auto service = make_service(memory, tight_policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "candidate limit test attaches fake process");
        if (!attached) return;

        auto first = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
            std::nullopt, std::nullopt, 4096U, 2U, false
        );
        check(first.has_value() && first->info.candidate_count == 2U,
              "scan_first stops accumulating candidates at the configured limit");
    }
    {
        auto memory = make_memory();
        argos::security::SecurityPolicy tight_policy;
        tight_policy.max_scan_sessions_per_session = 1U;
        auto service = make_service(memory, tight_policy);
        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "scan session limit test attaches fake process");
        if (!attached) return;

        auto first = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
            std::nullopt, std::nullopt, 4096U, 256U, false
        );
        check(first.has_value(), "first scan session is created");
        auto second = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
            std::nullopt, std::nullopt, 4096U, 256U, false
        );
        check(!second.has_value() && second.error().code == domain::DebugErrorCode::limit_exceeded,
              "a second scan session beyond the per-session limit is rejected");
    }
}

void test_scan_session_snapshot_cow() {
    namespace application = argos::application;
    namespace domain = argos::domain;

    auto owner = domain::SessionId::create("cow-owner");
    check(owner.has_value(), "COW scan-session test creates an owner id");
    if (!owner) return;

    application::ScanSessionManager manager;
    std::vector<application::ScanCandidate> candidates;
    const auto first_value = encode_i32(10);
    const auto second_value = encode_i32(20);
    candidates.emplace_back(0x1000U, std::span<const std::byte>{first_value});
    candidates.emplace_back(0x1004U, std::span<const std::byte>{second_value});
    const auto* const original_data = candidates.data();

    auto created = manager.create(*owner, domain::ScanValueType::i32, std::move(candidates), 4U);
    check(created.has_value(), "COW scan-session test creates a session");
    if (!created) return;

    auto first_snapshot = manager.snapshot(created->id);
    auto second_snapshot = manager.snapshot(created->id);
    check(first_snapshot.has_value() && second_snapshot.has_value(),
          "scan-session snapshots are available");
    if (!first_snapshot || !second_snapshot) return;

    check(first_snapshot->candidates().data() == original_data,
          "scan-session create moves the candidate vector without a deep copy");
    check(second_snapshot->candidates().data() == first_snapshot->candidates().data(),
          "multiple snapshots share the same immutable candidate generation");

    std::atomic<bool> reader_started{false};
    std::atomic<bool> release_reader{false};
    std::atomic<bool> snapshot_stable{true};
    std::jthread reader([&] {
        reader_started.store(true, std::memory_order_release);
        while (!release_reader.load(std::memory_order_acquire)) {
            const auto observed = first_snapshot->candidates();
            if (observed.size() != 2U || observed[0].address != 0x1000U) {
                snapshot_stable.store(false, std::memory_order_relaxed);
            }
            std::this_thread::yield();
        }
    });

    std::vector<application::ScanCandidate> replacement;
    const auto replacement_value = encode_i32(30);
    replacement.emplace_back(0x2000U, std::span<const std::byte>{replacement_value});
    const auto* const replacement_data = replacement.data();
    while (!reader_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    auto replaced = manager.replace(created->id, *first_snapshot, std::move(replacement));
    release_reader.store(true, std::memory_order_release);
    reader.join();

    check(replaced.has_value() && replaced->generation == 1U,
          "replacing a current scan snapshot publishes the next generation");
    check(snapshot_stable.load(std::memory_order_relaxed),
          "a reader keeps a stable old generation while replacement runs concurrently");
    check(first_snapshot->candidates().size() == 2U && first_snapshot->candidates()[0].address == 0x1000U,
          "an old snapshot remains readable after copy-on-write replacement");

    auto current_snapshot = manager.snapshot(created->id);
    check(current_snapshot.has_value() && current_snapshot->candidates().data() == replacement_data,
          "replacement moves and publishes its candidate vector without a deep copy");
    check(current_snapshot.has_value() && current_snapshot->candidates().size() == 1U &&
              current_snapshot->candidates()[0].address == 0x2000U,
          "new snapshots observe the replacement generation");

    std::vector<application::ScanCandidate> stale_replacement;
    stale_replacement.emplace_back(0x3000U, std::span<const std::byte>{replacement_value});
    auto stale = manager.replace(created->id, *first_snapshot, std::move(stale_replacement));
    check(!stale.has_value() && stale.error().code == domain::DebugErrorCode::invalid_state,
          "a stale snapshot cannot overwrite a newer candidate generation");

    manager.remove_owned_by(*owner);
    auto removed = manager.snapshot(created->id);
    check(!removed.has_value() && removed.error().code == domain::DebugErrorCode::not_found,
          "removing an owner removes its scan-session registry entry");
    check(first_snapshot->candidates().size() == 2U,
          "a snapshot safely retains candidate lifetime after owner removal");
}

void test_scan_next_batches_contiguous_candidates() {
    namespace domain = argos::domain;

    auto memory = std::make_shared<std::vector<std::byte>>();
    for (const std::int32_t value : {10, 20, 30, 40}) {
        const auto bytes = encode_i32(value);
        memory->insert(memory->end(), bytes.begin(), bytes.end());
    }
    auto probe = std::make_shared<MutableReadProbe>();
    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, probe]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<MutableFakeSession>(memory, probe);
        }
    );
    argos::security::SecurityPolicy policy;
    policy.max_read_bytes = 8U;
    argos::application::MemoryDebugService service{std::move(provider), policy};

    auto attached = service.attach(42U, domain::AccessMode::read_only, true);
    check(attached.has_value(), "batched scan_next test attaches fake process");
    if (!attached) return;

    auto first = service.scan_first(
        attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
        std::nullopt, std::nullopt, memory->size(), 16U, false
    );
    check(first.has_value() && first->info.candidate_count == 4U,
          "batched scan_next fixture captures four contiguous candidates");
    if (!first) return;

    probe->calls.store(0U, std::memory_order_relaxed);
    auto unchanged = service.scan_next(
        first->info.id, domain::ScanComparison::unchanged, std::nullopt, std::nullopt
    );
    check(unchanged.has_value() && unchanged->candidate_count == 4U,
          "batched scan_next preserves all unchanged candidates");
    check(probe->calls.load(std::memory_order_relaxed) == 2U,
          "scan_next reads contiguous candidates in max_read_bytes-bounded runs");

    probe->calls.store(0U, std::memory_order_relaxed);
    probe->short_batch_reads.store(true, std::memory_order_relaxed);
    auto after_short_reads = service.scan_next(
        first->info.id, domain::ScanComparison::unchanged, std::nullopt, std::nullopt
    );
    check(after_short_reads.has_value() && after_short_reads->candidate_count == 4U,
          "scan_next falls back after short batched reads without losing candidates");
    check(probe->calls.load(std::memory_order_relaxed) == 4U,
          "each short two-candidate run falls back only for its unread suffix");

    probe->short_batch_reads.store(false, std::memory_order_relaxed);
    probe->calls.store(0U, std::memory_order_relaxed);
    probe->cancel_after_calls.store(1U, std::memory_order_relaxed);
    auto cancelled = service.scan_next(
        first->info.id, domain::ScanComparison::unchanged, std::nullopt, std::nullopt,
        probe->cancellation.get_token()
    );
    check(!cancelled.has_value() && cancelled.error().code == domain::DebugErrorCode::cancelled,
          "scan_next observes cancellation raised while processing a batched run");
    check(probe->calls.load(std::memory_order_relaxed) == 1U,
          "cancellation prevents scan_next from issuing the next contiguous run");
}

void test_read_batch_coalesces_ranges() {
    namespace application = argos::application;
    namespace domain = argos::domain;

    auto memory = std::make_shared<std::vector<std::byte>>();
    for (const std::int32_t value : {10, 20, 30, 40}) {
        const auto bytes = encode_i32(value);
        memory->insert(memory->end(), bytes.begin(), bytes.end());
    }
    auto probe = std::make_shared<MutableReadProbe>();
    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, probe]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<MutableFakeSession>(memory, probe);
        }
    );
    argos::security::SecurityPolicy policy;
    application::MemoryDebugService service{std::move(provider), policy};
    auto attached = service.attach(42U, domain::AccessMode::read_only, true);
    check(attached.has_value(), "coalesced read_batch test attaches fake process");
    if (!attached) return;

    const std::array<application::BatchReadItem, 4> items{{
        {0x1008U, 4U}, {0x1000U, 4U}, {0x100CU, 4U}, {0x1004U, 4U}
    }};
    auto result = service.read_batch(attached->id, items);
    check(result.has_value() && result->size() == items.size(),
          "read_batch preserves all results for out-of-order adjacent ranges");
    check(probe->calls.load(std::memory_order_relaxed) == 1U,
          "read_batch coalesces four adjacent ranges into one native read");
    if (result && result->size() == items.size()) {
        for (std::size_t index = 0; index < items.size(); ++index) {
            const auto expected_offset = static_cast<std::size_t>(items[index].address - 0x1000U);
            check((*result)[index].address == items[index].address && (*result)[index].success &&
                      (*result)[index].bytes == std::vector<std::byte>(
                          memory->begin() + static_cast<std::ptrdiff_t>(expected_offset),
                          memory->begin() + static_cast<std::ptrdiff_t>(expected_offset + items[index].size)
                      ),
                  "read_batch keeps input order and exact byte slices after coalescing");
        }
    }

    probe->calls.store(0U, std::memory_order_relaxed);
    probe->short_batch_reads.store(true, std::memory_order_relaxed);
    result = service.read_batch(attached->id, items);
    check(result.has_value() && std::ranges::all_of(*result, [](const auto& item) { return item.success; }),
          "read_batch falls back to individual reads after a short coalesced read");
    check(probe->calls.load(std::memory_order_relaxed) == 5U,
          "short coalesced read performs one attempted run plus four safe fallbacks");

    probe->short_batch_reads.store(false, std::memory_order_relaxed);
    probe->oversized_reads.store(true, std::memory_order_relaxed);
    auto oversized_read = service.read_memory(attached->id, 0x1000U, 4U);
    check(!oversized_read.has_value() && oversized_read.error().code == domain::DebugErrorCode::io_error,
          "read_memory rejects a backend count larger than the supplied span");
    auto oversized_scan = service.scan_first(
        attached->id, domain::ScanValueType::i32, domain::ScanComparison::unknown,
        std::nullopt, std::nullopt, memory->size(), 16U, false
    );
    check(!oversized_scan.has_value() && oversized_scan.error().code == domain::DebugErrorCode::io_error,
          "scan_first rejects a backend count larger than its reusable chunk span");
}

void test_output_ring_buffer() {
    argos::infrastructure::OutputRingBuffer buffer{8U};
    auto read1 = buffer.read(0U, 100U);
    check(read1.text.empty(), "empty ring buffer returns no text");

    buffer.append("hello");
    read1 = buffer.read(0U, 100U);
    check(read1.text == "hello" && read1.next_position == 5U, "ring buffer returns appended text with a cursor");

    buffer.append("world!");
    check(buffer.produced() == 11U, "produced count accumulates across appends");
    check(buffer.retained() == 8U, "retained size is capped at capacity");

    auto read2 = buffer.read(read1.next_position, 100U);
    check(read2.text == "world!", "reading from a still-retained position returns the correct slice");

    auto read3 = buffer.read(0U, 100U);
    check(read3.text == "loworld!", "reading from an evicted position clamps forward to the oldest retained data");

    auto read4 = buffer.read(read3.next_position, 100U);
    check(read4.text.empty(), "reading from the current end returns no text");

    auto read5 = buffer.read(read3.next_position - 3U, 3U);
    check(read5.text.size() == 3U, "max_bytes caps how much text a single read returns");

    buffer.append("0123456789ABCDEF");
    auto read6 = buffer.read(0U, 100U);
    check(read6.text == "89ABCDEF" && buffer.retained() == 8U,
          "an append larger than capacity retains exactly its newest tail");

    argos::infrastructure::OutputRingBuffer wrapped{5U};
    wrapped.append("ab");
    wrapped.append("cd");
    wrapped.append("ef");
    wrapped.append("gh");
    check(wrapped.read(0U, 100U).text == "defgh",
          "multiple wrapped appends preserve FIFO order without shifting storage");
}

void test_domain_query_helpers() {
    namespace domain = argos::domain;

    const auto encoded_i32 = domain::encode_scan_value(domain::ScanValueType::i32, " 91293908 ");
    check(encoded_i32.has_value() && *encoded_i32 == std::vector<std::byte>{
              std::byte{0xD4}, std::byte{0x08}, std::byte{0x71}, std::byte{0x05}
          },
          "decimal scan values are encoded as exact little-endian bytes");
    check(!domain::encode_scan_value(domain::ScanValueType::u8, "256").has_value(),
          "decimal encoding rejects integral overflow");
    check(!domain::encode_scan_value(domain::ScanValueType::u32, "-1").has_value(),
          "decimal encoding rejects a negative value for an unsigned type");
    check(!domain::encode_scan_value(domain::ScanValueType::f32, "1e39").has_value(),
          "decimal encoding rejects values that overflow only after narrowing to f32");
    check(!domain::encode_scan_value(domain::ScanValueType::f32, "1e-50").has_value(),
          "decimal encoding rejects values that silently underflow to zero in f32");

    const std::vector<domain::MemoryRegion> regions{
        {0x1000U, 0x2000U, true, true, false, true, "heap-main"},
        {0x2000U, 0x2800U, true, false, true, false, "game.exe"},
        {0x3000U, 0x3400U, false, true, false, true, "heap-guard"}
    };
    domain::RegionFilter writable_heap{};
    writable_heap.writable = true;
    writable_heap.name_contains = "HEAP";
    const auto page = domain::filter_regions(regions, writable_heap, 0U, 1U);
    check(page.total_matched == 2U && page.regions.size() == 1U && page.truncated,
          "region filtering is case-insensitive, paginated and reports the full match count");
    const auto out_of_range_page = domain::filter_regions(
        regions, writable_heap, std::numeric_limits<std::size_t>::max(), 1U
    );
    check(out_of_range_page.regions.empty() && !out_of_range_page.truncated,
          "region pagination handles a maximal offset without arithmetic overflow");

    const auto summary = domain::summarize_address_space(regions);
    check(summary.region_count == 3U && summary.total_bytes == 0x1C00U,
          "address-space summary reports total regions and bytes");
    check(summary.scannable_bytes == 0x1800U && summary.scannable_writable_bytes == 0x1000U,
          "address-space summary distinguishes readable and writable scan coverage");
    check(summary.lowest_address == 0x1000U && summary.highest_address == 0x3400U,
          "address-space summary reports the full address range");
}

void test_authorize_launch_policy() {
    argos::security::SecurityPolicy policy;
    check(!policy.authorize_launch(true, "C:\\Allowed\\app.exe").has_value() &&
              policy.authorize_launch(true, "C:\\Allowed\\app.exe").error().code ==
                  argos::domain::DebugErrorCode::access_denied,
          "launch is denied by default when the gate is off");

    policy.allow_launch = true;
    check(!policy.authorize_launch(false, "C:\\Allowed\\app.exe").has_value() &&
              policy.authorize_launch(false, "C:\\Allowed\\app.exe").error().code ==
                  argos::domain::DebugErrorCode::unauthorized,
          "launch requires explicit authorization even with the gate on");

    check(!policy.authorize_launch(true, "relative\\app.exe").has_value() &&
              policy.authorize_launch(true, "relative\\app.exe").error().code ==
                  argos::domain::DebugErrorCode::invalid_argument,
          "relative executable paths are rejected");

    check(policy.authorize_launch(true, "C:\\Allowed\\app.exe").has_value(),
          "absolute path is authorized when no allowlist is configured");

    policy.launch_allowed_dirs = {"C:\\Allowed"};
    check(policy.authorize_launch(true, "C:\\Allowed\\sub\\app.exe").has_value(),
          "path under the allowlist is authorized");
    check(!policy.authorize_launch(true, "C:\\Other\\app.exe").has_value() &&
              policy.authorize_launch(true, "C:\\Other\\app.exe").error().code ==
                  argos::domain::DebugErrorCode::access_denied,
          "path outside the allowlist is denied");
    check(!policy.authorize_launch(true, "C:\\Allowed\\..\\Other\\app.exe").has_value(),
          "path traversal cannot escape the allowlist");
}

void test_launch_and_managed_process() {
    namespace domain = argos::domain;
    auto terminated = std::make_shared<bool>(false);

    {
        argos::security::SecurityPolicy policy;
        auto service = argos::application::MemoryDebugService{
            std::make_unique<FakeLaunchProvider>(terminated), policy
        };
        auto denied = service.launch(
            domain::LaunchSpec{"C:\\Allowed\\app.exe", {}, std::nullopt, true},
            domain::AccessMode::read_only, true
        );
        check(!denied.has_value() && denied.error().code == domain::DebugErrorCode::access_denied,
              "launch is denied when ARGOS_MCP_ALLOW_LAUNCH is off");
    }
    {
        argos::security::SecurityPolicy policy;
        policy.allow_launch = true;
        auto service = argos::application::MemoryDebugService{
            std::make_unique<FakeLaunchProvider>(terminated), policy
        };
        auto launched = service.launch(
            domain::LaunchSpec{"C:\\Allowed\\app.exe", {}, std::nullopt, true},
            domain::AccessMode::read_only, true
        );
        check(launched.has_value(), "launch succeeds once the gate is on and authorized is true");
        if (!launched) return;

        auto output = service.read_output(launched->id, 0U, 4096U);
        check(output.has_value() && output->stdout_text == "banner\n" && output->process_alive,
              "read_output returns captured banner text for a launched session");

        auto denied_terminate = service.detach(launched->id, false);
        check(denied_terminate.has_value(), "plain detach (no terminate) succeeds on a launched session");
    }
    {
        argos::security::SecurityPolicy policy;
        policy.allow_launch = true;
        auto service = argos::application::MemoryDebugService{
            std::make_unique<FakeLaunchProvider>(terminated), policy
        };
        auto launched = service.launch(
            domain::LaunchSpec{"C:\\Allowed\\app.exe", {}, std::nullopt, true},
            domain::AccessMode::read_only, true
        );
        check(launched.has_value(), "second launch succeeds for the terminate test");
        if (!launched) return;

        *terminated = false;
        auto terminate_result = service.detach(launched->id, true);
        check(terminate_result.has_value() && *terminated,
              "detach(terminate=true) on an owned session terminates the process");

        auto attached = service.attach(42U, domain::AccessMode::read_only, true);
        check(attached.has_value(), "attach still works alongside launch on the same service");
        if (!attached) return;
        auto rejected = service.detach(attached->id, true);
        check(!rejected.has_value() && rejected.error().code == domain::DebugErrorCode::access_denied,
              "detach(terminate=true) on an attach()-created session is rejected");
    }
    {
        argos::security::SecurityPolicy policy;
        policy.allow_launch = true;
        policy.max_launched_processes = 1U;
        auto service = argos::application::MemoryDebugService{
            std::make_unique<FakeLaunchProvider>(terminated), policy
        };
        auto first = service.launch(
            domain::LaunchSpec{"C:\\Allowed\\app.exe", {}, std::nullopt, true},
            domain::AccessMode::read_only, true
        );
        check(first.has_value(), "first launch is accepted under the process limit");
        auto second = service.launch(
            domain::LaunchSpec{"C:\\Allowed\\app.exe", {}, std::nullopt, true},
            domain::AccessMode::read_only, true
        );
        check(!second.has_value() && second.error().code == domain::DebugErrorCode::limit_exceeded,
              "a second launch beyond max_launched_processes is rejected");
    }
}

void test_extract_strings() {
    argos::security::SecurityPolicy policy;
    {
        std::vector<std::byte> memory{
            std::byte{0x00},
            std::byte{'H'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'},
            std::byte{0x00},
            std::byte{'H'}, std::byte{'i'},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}
        };
        auto provider = std::make_unique<SingleSessionFakeProvider>(
            [memory]() -> std::unique_ptr<argos::domain::ProcessSession> {
                return std::make_unique<FakeSession>(memory);
            }
        );
        argos::application::MemoryDebugService service{std::move(provider), policy};
        auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "strings test attaches fake process");
        if (!attached) return;

        auto min3 = service.extract_strings(attached->id, 3U, "ascii", 4096U, 256U, false);
        check(min3.has_value(), "ascii string extraction succeeds");
        if (min3) {
            check(min3->matches.size() == 1U, "min_length filters out short runs");
            if (!min3->matches.empty()) {
                check(min3->matches[0].text == "Hello", "extracted text matches expected run");
                check(min3->matches[0].address == 0x1001U, "extracted address points at run start");
                check(min3->matches[0].encoding == "ascii", "encoding label is ascii");
            }
        }

        auto min1 = service.extract_strings(attached->id, 1U, "ascii", 4096U, 256U, false);
        check(min1.has_value() && min1->matches.size() == 2U, "lower min_length keeps both runs");

        auto bad_encoding = service.extract_strings(attached->id, 1U, "latin1", 4096U, 256U, false);
        check(!bad_encoding.has_value() &&
                  bad_encoding.error().code == argos::domain::DebugErrorCode::invalid_argument,
              "unknown encoding is rejected");

        auto bad_min_length = service.extract_strings(attached->id, 0U, "ascii", 4096U, 256U, false);
        check(!bad_min_length.has_value() &&
                  bad_min_length.error().code == argos::domain::DebugErrorCode::invalid_argument,
              "min_length of zero is rejected");
    }
    {
        argos::security::SecurityPolicy truncating_policy;
        truncating_policy.max_string_result_length = 3U;
        std::vector<std::byte> memory{
            std::byte{0x00},
            std::byte{'H'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'},
            std::byte{0x00}
        };
        auto provider = std::make_unique<SingleSessionFakeProvider>(
            [memory]() -> std::unique_ptr<argos::domain::ProcessSession> {
                return std::make_unique<FakeSession>(memory);
            }
        );
        argos::application::MemoryDebugService service{std::move(provider), truncating_policy};
        auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "truncation test attaches fake process");
        if (!attached) return;
        auto result = service.extract_strings(attached->id, 3U, "ascii", 4096U, 256U, false);
        check(result.has_value() && result->matches.size() == 1U, "truncated run is still a single match");
        if (result.has_value() && !result->matches.empty()) {
            check(result->matches[0].text == "Hel", "match text is truncated to max_string_result_length");
        }
    }
    {
        std::vector<std::byte> memory{
            std::byte{'O'}, std::byte{0x00}, std::byte{'k'}, std::byte{0x00},
            std::byte{0x00}, std::byte{0xFF}, std::byte{0x00}, std::byte{0x00}
        };
        auto provider = std::make_unique<SingleSessionFakeProvider>(
            [memory]() -> std::unique_ptr<argos::domain::ProcessSession> {
                return std::make_unique<FakeSession>(memory);
            }
        );
        argos::application::MemoryDebugService service{std::move(provider), policy};
        auto attached = service.attach(42U, argos::domain::AccessMode::read_only, true);
        check(attached.has_value(), "utf16le test attaches fake process");
        if (!attached) return;
        auto result = service.extract_strings(attached->id, 1U, "utf16le", 4096U, 256U, false);
        check(result.has_value() && result->matches.size() == 1U, "utf16le extraction finds one run");
        if (result.has_value() && !result->matches.empty()) {
            check(result->matches[0].text == "Ok", "utf16le run decodes to expected text");
            check(result->matches[0].encoding == "utf16le", "encoding label is utf16le");
        }
    }
}

void write_u32(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint32_t value) {
    for (std::size_t index = 0U; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
    }
}

void write_u16(std::vector<std::byte>& bytes, const std::size_t offset, const std::uint16_t value) {
    for (std::size_t index = 0U; index < sizeof(value); ++index) {
        bytes[offset + index] = static_cast<std::byte>((value >> (index * 8U)) & 0xFFU);
    }
}

class ScopedTestDirectory final {
public:
    explicit ScopedTestDirectory(std::filesystem::path path) : path_(std::move(path)) {}
    ~ScopedTestDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    ScopedTestDirectory(const ScopedTestDirectory&) = delete;
    ScopedTestDirectory& operator=(const ScopedTestDirectory&) = delete;

private:
    std::filesystem::path path_;
};

void test_unity_il2cpp_metadata() {
    std::filesystem::path root;
    std::error_code directory_error;
    std::random_device entropy;
    for (std::size_t attempt = 0U; attempt < 32U && root.empty(); ++attempt) {
        const auto token = (static_cast<std::uint64_t>(entropy()) << 32U) |
                           static_cast<std::uint64_t>(entropy());
        auto candidate = std::filesystem::temp_directory_path() /
                         ("argos-unity-metadata-fixture-" + std::to_string(token));
        directory_error.clear();
        if (std::filesystem::create_directory(candidate, directory_error)) {
            root = std::move(candidate);
        } else if (directory_error && directory_error != std::errc::file_exists) {
            break;
        }
    }
    check(!root.empty(), "Unity fixture directory is created");
    if (root.empty()) return;
    const ScopedTestDirectory cleanup{root};

    const auto module = root / "GameAssembly.dll";
    const auto metadata_path = root / "global-metadata.dat";
    {
        std::ofstream module_file(module, std::ios::binary);
        module_file << "MZ";
    }

    const std::string strings{"\0Test\0Game\0value\0", 17U};
    constexpr std::size_t header_size = 272U;
    const std::size_t fields_offset = header_size + strings.size();
    const std::size_t types_offset = fields_offset + 12U;
    std::vector<std::byte> bytes(types_offset + 88U, std::byte{0});
    write_u32(bytes, 0U, 0xFAB11BAFU);
    write_u32(bytes, 4U, 29U);
    write_u32(bytes, 24U, static_cast<std::uint32_t>(header_size));
    write_u32(bytes, 28U, static_cast<std::uint32_t>(strings.size()));
    write_u32(bytes, 96U, static_cast<std::uint32_t>(fields_offset));
    write_u32(bytes, 100U, 12U);
    write_u32(bytes, 160U, static_cast<std::uint32_t>(types_offset));
    write_u32(bytes, 164U, 88U);
    std::memcpy(bytes.data() + header_size, strings.data(), strings.size());
    write_u32(bytes, fields_offset, 11U);
    write_u32(bytes, fields_offset + 4U, 42U);
    write_u32(bytes, fields_offset + 8U, 0U);
    write_u32(bytes, types_offset, 1U);
    write_u32(bytes, types_offset + 4U, 6U);
    write_u32(bytes, types_offset + 32U, 0U);
    write_u16(bytes, types_offset + 68U, 1U);
    {
        std::ofstream metadata_file(metadata_path, std::ios::binary);
        metadata_file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }

    argos::infrastructure::PdbTypeMetadataProvider provider;
    auto result = provider.inspect_unity(module.string(), "Game.Test", 16U);
    check(result.has_value(), "Unity IL2CPP metadata parser reads a valid fixture");
    if (result) {
        check(result->type_name == "Game.Test", "Unity parser preserves namespace-qualified type name");
        check(result->fields.size() == 1U, "Unity parser reads field count");
        if (!result->fields.empty()) {
            check(result->fields[0].name == "value", "Unity parser reads field name");
            check(result->fields[0].offset == -1, "Unity parser marks unavailable native offset explicitly");
            check(result->fields[0].type_name == "il2cpp_type_index:42", "Unity parser preserves field type index");
        }
    }
    auto invalid_unreal = provider.inspect_unreal_type(module.string(), "NotAReflectedType", 16U);
    check(!invalid_unreal.has_value() &&
              invalid_unreal.error().code == argos::domain::DebugErrorCode::invalid_argument,
          "Unreal parser rejects non-reflected type names before touching symbols");
}

}  // namespace

void test_encode_scan_value() {
    using argos::domain::ScanValueType;
    using argos::domain::encode_scan_value;

    const auto bytes_of = [](std::initializer_list<int> values) {
        std::vector<std::byte> out;
        for (const int value : values) out.push_back(static_cast<std::byte>(value));
        return out;
    };

    // The literal that motivated this: 91293908 == 0x057108D4, little-endian.
    auto credits = encode_scan_value(ScanValueType::i32, "91293908");
    check(credits.has_value() && *credits == bytes_of({0xD4, 0x08, 0x71, 0x05}),
          "encode_scan_value encodes i32 decimal as little-endian bytes");

    auto negative = encode_scan_value(ScanValueType::i32, "-2");
    check(negative.has_value() && *negative == bytes_of({0xFE, 0xFF, 0xFF, 0xFF}),
          "encode_scan_value encodes negative i32 in two's complement");

    auto byte_max = encode_scan_value(ScanValueType::u8, "255");
    check(byte_max.has_value() && byte_max->size() == 1U,
          "encode_scan_value honours the width of the value_type");

    auto overflow = encode_scan_value(ScanValueType::u8, "256");
    check(!overflow.has_value(), "encode_scan_value rejects values wider than value_type");

    auto signed_overflow = encode_scan_value(ScanValueType::i8, "128");
    check(!signed_overflow.has_value(), "encode_scan_value rejects signed overflow");

    auto negative_unsigned = encode_scan_value(ScanValueType::u32, "-1");
    check(!negative_unsigned.has_value(), "encode_scan_value rejects a negative value for an unsigned type");

    auto fractional_integer = encode_scan_value(ScanValueType::i32, "1.5");
    check(!fractional_integer.has_value(), "encode_scan_value rejects a fractional literal for an integer type");

    auto garbage = encode_scan_value(ScanValueType::i32, "12abc");
    check(!garbage.has_value(), "encode_scan_value rejects trailing garbage");

    auto empty = encode_scan_value(ScanValueType::i32, "   ");
    check(!empty.has_value(), "encode_scan_value rejects an empty literal");

    auto single = encode_scan_value(ScanValueType::f32, "1.0");
    check(single.has_value() && *single == bytes_of({0x00, 0x00, 0x80, 0x3F}),
          "encode_scan_value encodes f32 1.0 as IEEE-754 little-endian");

    auto padded = encode_scan_value(ScanValueType::i32, "  7 ");
    check(padded.has_value(), "encode_scan_value tolerates surrounding whitespace");
}

void test_region_queries() {
    using argos::domain::MemoryRegion;
    const std::vector<MemoryRegion> regions{
        MemoryRegion{0x1000U, 0x2000U, true,  false, false, true,  "heap-ro"},
        MemoryRegion{0x2000U, 0x6000U, true,  true,  false, true,  "heap-rw"},
        MemoryRegion{0x6000U, 0x6800U, true,  true,  true,  false, "image-rwx"},
        MemoryRegion{0x8000U, 0x8100U, false, true,  false, true,  "reserved"}
    };

    const auto summary = argos::domain::summarize_address_space(regions);
    check(summary.region_count == 4U, "summarize_address_space counts every region");
    check(summary.total_bytes == 0x1000U + 0x4000U + 0x800U + 0x100U,
          "summarize_address_space totals every region size");
    // Only readable regions can be swept; the unreadable one must not count.
    check(summary.scannable_bytes == 0x1000U + 0x4000U + 0x800U,
          "summarize_address_space counts only readable bytes as scannable");
    check(summary.scannable_writable_bytes == 0x4000U + 0x800U,
          "summarize_address_space separates readable+writable bytes");
    check(summary.largest_region_bytes == 0x4000U, "summarize_address_space reports the largest region");
    check(summary.lowest_address == 0x1000U && summary.highest_address == 0x8100U,
          "summarize_address_space reports the address span");
    check(summary.executable_count == 1U && summary.private_count == 3U,
          "summarize_address_space counts by attribute");

    argos::domain::RegionFilter writable{};
    writable.writable = true;
    auto page = argos::domain::filter_regions(regions, writable, 0U, 10U);
    check(page.total_matched == 3U && page.regions.size() == 3U && !page.truncated,
          "filter_regions selects by attribute");

    argos::domain::RegionFilter readable_writable{};
    readable_writable.writable = true;
    readable_writable.readable = true;
    page = argos::domain::filter_regions(regions, readable_writable, 0U, 10U);
    check(page.total_matched == 2U, "filter_regions combines attribute predicates");

    argos::domain::RegionFilter by_size{};
    by_size.min_size = 0x1000U;
    page = argos::domain::filter_regions(regions, by_size, 0U, 10U);
    check(page.total_matched == 2U, "filter_regions applies min_size");

    argos::domain::RegionFilter by_name{};
    by_name.name_contains = "HEAP";
    page = argos::domain::filter_regions(regions, by_name, 0U, 10U);
    check(page.total_matched == 2U, "filter_regions matches name case-insensitively");

    argos::domain::RegionFilter overlap{};
    overlap.start_address = 0x6000U;
    page = argos::domain::filter_regions(regions, overlap, 0U, 10U);
    check(page.total_matched == 2U, "filter_regions keeps regions overlapping start_address");

    // Paging must report the full match count, not just the page size, so the
    // caller knows whether to ask for more.
    argos::domain::RegionFilter none{};
    page = argos::domain::filter_regions(regions, none, 0U, 2U);
    check(page.total_matched == 4U && page.regions.size() == 2U && page.truncated,
          "filter_regions reports total_matched beyond the page and flags truncation");
    page = argos::domain::filter_regions(regions, none, 2U, 2U);
    check(page.total_matched == 4U && page.regions.size() == 2U && !page.truncated &&
              page.regions.front().start == 0x6000U,
          "filter_regions honours offset and clears truncation on the last page");
    page = argos::domain::filter_regions(regions, none, 99U, 2U);
    check(page.total_matched == 4U && page.regions.empty(),
          "filter_regions returns an empty page past the end without losing the total");

    const auto [all_bytes, all_regions] =
        argos::domain::eligible_scan_bytes(regions, false, std::nullopt, std::nullopt);
    check(all_bytes == 0x1000U + 0x4000U + 0x800U && all_regions == 3U,
          "eligible_scan_bytes skips unreadable regions");
    const auto [rw_bytes, rw_regions] =
        argos::domain::eligible_scan_bytes(regions, true, std::nullopt, std::nullopt);
    check(rw_bytes == 0x4000U + 0x800U && rw_regions == 2U,
          "eligible_scan_bytes honours writable_only");
    const auto [clamped_bytes, clamped_regions] =
        argos::domain::eligible_scan_bytes(regions, false, 0x1800U, 0x2400U);
    check(clamped_bytes == 0x800U + 0x400U && clamped_regions == 2U,
          "eligible_scan_bytes clamps to the requested address window");
}

void test_scan_coverage() {
    argos::domain::ScanCoverage full{};
    full.bytes_scanned = 1024U;
    full.bytes_eligible = 1024U;
    check(full.coverage_ratio() == 1.0 && full.complete(), "full sweep reports ratio 1.0 and complete");

    argos::domain::ScanCoverage partial{};
    partial.bytes_scanned = 256U;
    partial.bytes_eligible = 1024U;
    partial.truncated_by_budget = true;
    check(partial.coverage_ratio() == 0.25 && !partial.complete(),
          "budget-truncated sweep reports a fractional ratio and is not complete");

    argos::domain::ScanCoverage empty{};
    check(empty.coverage_ratio() == 1.0, "an empty address space counts as fully covered");

    // A sweep may read slightly past the pre-computed eligible total when a
    // chunk straddles the window edge; the ratio must stay clamped at 1.0.
    argos::domain::ScanCoverage over{};
    over.bytes_scanned = 2048U;
    over.bytes_eligible = 1024U;
    check(over.coverage_ratio() == 1.0, "coverage_ratio never exceeds 1.0");

    // This is the case that made an empty result ambiguous in the field: a
    // budget smaller than the target silently covered a fraction of it.
    argos::security::SecurityPolicy policy{};
    policy.max_scan_bytes = 1024U * 1024U;
    policy.max_scan_session_candidates = 4096U;
    policy.max_scan_sessions_per_session = 4U;
    argos::application::MemoryDebugService service{
        std::make_unique<FakeProvider>(), policy
    };
    auto session = service.attach(42U, argos::domain::AccessMode::read_only, true);
    check(session.has_value(), "coverage test attaches");
    if (!session) return;

    const std::array<std::byte, 4> needle{
        std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}
    };
    auto starved = service.scan_first(
        session->id, argos::domain::ScanValueType::i32, argos::domain::ScanComparison::exact,
        std::vector<std::byte>(needle.begin(), needle.end()), std::nullopt,
        4U, 64U, false
    );
    check(starved.has_value(), "scan_first with a starved budget still succeeds");
    if (starved) {
        check(starved->info.candidate_count == 0U, "starved sweep finds nothing");
        check(starved->coverage.truncated_by_budget, "starved sweep is flagged as budget-truncated");
        check(!starved->coverage.complete(), "starved sweep is not complete");
        check(starved->coverage.coverage_ratio() < 1.0, "starved sweep reports partial coverage");
        check(starved->coverage.bytes_eligible == 8U, "coverage reports the full eligible size");
    }

    auto complete = service.scan_first(
        session->id, argos::domain::ScanValueType::i32, argos::domain::ScanComparison::exact,
        std::vector<std::byte>(needle.begin(), needle.end()), std::nullopt,
        1024U, 64U, false
    );
    check(complete.has_value(), "scan_first with a sufficient budget succeeds");
    if (complete) {
        check(complete->info.candidate_count == 1U, "complete sweep finds the value");
        check(complete->coverage.complete(), "complete sweep is flagged complete");
        check(complete->coverage.coverage_ratio() == 1.0, "complete sweep reports full coverage");
        check(complete->coverage.regions_scanned == 1U, "complete sweep counts the region it swept");
    }
}

void test_region_page_service() {
    argos::security::SecurityPolicy policy{};
    argos::application::MemoryDebugService service{
        std::make_unique<FakeProvider>(), policy
    };
    auto session = service.attach(42U, argos::domain::AccessMode::read_only, true);
    check(session.has_value(), "region page test attaches");
    if (!session) return;

    auto summary = service.address_space_summary(session->id);
    check(summary.has_value() && summary->region_count == 1U && summary->scannable_bytes == 8U,
          "address_space_summary aggregates the session regions");

    argos::domain::RegionFilter none{};
    auto page = service.regions_page(session->id, none, 0U, 10U);
    check(page.has_value() && page->total_matched == 1U, "regions_page returns matching regions");

    argos::domain::RegionFilter writable{};
    writable.writable = true;
    page = service.regions_page(session->id, writable, 0U, 10U);
    check(page.has_value() && page->total_matched == 0U,
          "regions_page filters out non-writable regions");

    auto zero_limit = service.regions_page(session->id, none, 0U, 0U);
    check(!zero_limit.has_value(), "regions_page rejects a zero limit");

    argos::domain::RegionFilter inverted{};
    inverted.start_address = 0x2000U;
    inverted.end_address = 0x1000U;
    auto bad_window = service.regions_page(session->id, inverted, 0U, 10U);
    check(!bad_window.has_value(), "regions_page rejects an inverted address window");

    argos::domain::RegionFilter bad_size{};
    bad_size.min_size = 100U;
    bad_size.max_size = 10U;
    auto inverted_size = service.regions_page(session->id, bad_size, 0U, 10U);
    check(!inverted_size.has_value(), "regions_page rejects max_size below min_size");
}

// ---------------------------------------------------------------------------
// Spec 0008 -- AnalysisJobManager.
//
// ReadGate/GatedFakeSession let a test deterministically prove a worker
// thread is blocked inside native I/O (via wait_until_blocked_at_least) and
// then release it in controlled steps, without ever sleeping for a fixed
// duration. This is the fixture the spec's test plan calls for: proof that
// start returns before I/O completes and that status/cancel remain
// responsive while a reader is blocked.
// ---------------------------------------------------------------------------

struct ReadGate {
    std::mutex mutex;
    std::condition_variable cv;
    std::size_t permits{0U};
    std::size_t blocked{0U};
    bool open{false};

    void wait_turn() {
        std::unique_lock lock(mutex);
        if (open) return;
        ++blocked;
        cv.notify_all();
        cv.wait(lock, [&] { return open || permits > 0U; });
        --blocked;
        if (!open) --permits;
    }

    void wait_until_blocked_at_least(const std::size_t n) {
        std::unique_lock lock(mutex);
        cv.wait(lock, [&] { return blocked >= n; });
    }

    void grant(const std::size_t n) {
        std::scoped_lock lock(mutex);
        permits += n;
        cv.notify_all();
    }

    void open_gate() {
        std::scoped_lock lock(mutex);
        open = true;
        cv.notify_all();
    }
};

class GatedFakeSession final : public argos::domain::ProcessSession {
public:
    GatedFakeSession(std::shared_ptr<std::vector<std::byte>> memory, std::shared_ptr<ReadGate> gate)
        : memory_(std::move(memory)), gate_(std::move(gate)) {}

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 42U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "fake-gated-target"; }
    [[nodiscard]] argos::domain::AccessMode access_mode() const noexcept override {
        return argos::domain::AccessMode::read_only;
    }

    [[nodiscard]] argos::domain::Result<std::size_t> read(
        const argos::domain::Address address,
        const std::span<std::byte> output
    ) const override {
        gate_->wait_turn();
        constexpr argos::domain::Address base = 0x1000U;
        if (address < base) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "address below fake region"
            });
        }
        const auto offset = static_cast<std::size_t>(address - base);
        if (offset > memory_->size() || output.size() > memory_->size() - offset) {
            return std::unexpected(argos::domain::DebugError{
                argos::domain::DebugErrorCode::io_error, "read outside fake region"
            });
        }
        std::copy_n(memory_->begin() + static_cast<std::ptrdiff_t>(offset), output.size(), output.begin());
        return output.size();
    }

    [[nodiscard]] argos::domain::Result<std::size_t> write(
        argos::domain::Address,
        std::span<const std::byte>
    ) override {
        return std::unexpected(argos::domain::DebugError{
            argos::domain::DebugErrorCode::access_denied, "gated fake session is read-only"
        });
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::MemoryRegion>> regions() const override {
        return std::vector<argos::domain::MemoryRegion>{argos::domain::MemoryRegion{
            0x1000U, 0x1000U + memory_->size(), true, false, false, true, "gated"
        }};
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{};
    }

private:
    std::shared_ptr<std::vector<std::byte>> memory_;
    std::shared_ptr<ReadGate> gate_;
};

// Bounded, sleep-free spin: the condition below is guaranteed to become true
// quickly once a test opens/grants its gate, since nothing else throttles the
// worker at that point. This is polling a real condition to completion, not
// waiting out a fixed duration.
[[nodiscard]] argos::domain::AnalysisJobInfo poll_until_terminal(
    argos::application::AnalysisJobManager& manager,
    const argos::domain::SessionId& owner,
    const argos::domain::AnalysisJobId& job_id,
    bool* sequence_monotonic = nullptr
) {
    std::optional<argos::domain::AnalysisJobInfo> status;
    std::uint64_t last_sequence = 0U;
    bool first = true;
    for (int iterations = 0; iterations < 4'000'000; ++iterations) {
        auto polled = manager.status(owner, job_id);
        if (!polled) break;
        if (sequence_monotonic != nullptr) {
            if (!first && polled->progress.sequence < last_sequence) *sequence_monotonic = false;
            last_sequence = polled->progress.sequence;
            first = false;
        }
        status = *polled;
        if (status->state == argos::domain::AnalysisJobState::completed ||
            status->state == argos::domain::AnalysisJobState::failed ||
            status->state == argos::domain::AnalysisJobState::cancelled) {
            break;
        }
    }
    if (status) return *status;
    // Never reachable in practice (status() only fails for a missing job,
    // which none of these tests submit-then-immediately-lose); constructing
    // a placeholder needs an id/owner since neither type default-constructs.
    return argos::domain::AnalysisJobInfo{job_id, owner};
}

void test_analysis_job_manager_lifecycle_progress_and_pagination() {
    using namespace argos;
    security::SecurityPolicy policy{};

    // 200 KiB of zero bytes with a 4-byte pattern at the very end: the sweep
    // needs several 64 KiB chunks (several session->read() calls, several
    // progress publications) to reach it.
    auto memory = std::make_shared<std::vector<std::byte>>(200U * 1024U, std::byte{0x00});
    const std::array<std::byte, 4> pattern{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    std::copy(pattern.begin(), pattern.end(), memory->end() - 4);

    auto gate = std::make_shared<ReadGate>();
    gate->open_gate();  // No blocking needed for this test.

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "async lifecycle test attaches");
    if (!session) return;

    application::AnalysisJobManager manager{service, policy};

    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern.assign(pattern.begin(), pattern.end());
    request.alignment = 1U;
    request.result_limit = 16U;

    auto submitted = manager.submit(
        session->id, domain::AsyncScanOperation::scan_exact, request,
        application::AnalysisJobManager::ExecutionLimits{memory->size() + 4096U, 60'000U}
    );
    check(submitted.has_value(), "submit accepts a well-formed scan_exact job");
    if (!submitted) return;
    check(submitted->state == domain::AnalysisJobState::queued, "job starts queued");
    check(!submitted->cancel_requested, "cancel_requested starts false");
    check(submitted->operation == domain::AsyncScanOperation::scan_exact, "job records its operation");

    bool sequence_monotonic = true;
    const auto status = poll_until_terminal(manager, session->id, submitted->id, &sequence_monotonic);
    check(sequence_monotonic, "ScanProgress::sequence never decreases across polls");
    check(status.state == domain::AnalysisJobState::completed, "job reaches completed");
    check(status.results_available, "results_available once terminal");
    if (status.termination) {
        check(status.termination->reason == domain::AnalysisStopReason::range_exhausted,
              "a full untruncated sweep terminates as range_exhausted");
        check(status.termination->coverage_complete && status.termination->results_complete,
              "full sweep reports complete coverage and results");
        check(!status.termination->truncated, "full sweep is not truncated");
        check(!status.termination->resume_token.has_value(),
              "no resume_token is issued in this version (deferred extension point)");
    } else {
        check(false, "terminal job carries a termination block");
    }

    auto page = manager.results(session->id, submitted->id, 0U, 1U);
    check(page.has_value() && page->address_matches.size() == 1U, "results page respects the requested limit");
    if (page) {
        check(page->total == 1U, "exactly one match for the fixture pattern");
        check(!page->has_more, "single match with limit>=total reports no further pages");
    }

    auto other_owner = domain::SessionId::create("someone-else-session");
    check(other_owner.has_value(), "fixture session id is well-formed");
    if (other_owner) {
        auto wrong_owner = manager.results(*other_owner, submitted->id, 0U, 10U);
        check(!wrong_owner.has_value() && wrong_owner.error().code == domain::DebugErrorCode::not_found,
              "results() from a different owner is not_found, never leaking that the job exists");
    }

    auto release_ok = manager.release(session->id, submitted->id);
    check(release_ok.has_value(), "release succeeds on a terminal job");
    auto after_release = manager.status(session->id, submitted->id);
    check(!after_release.has_value() && after_release.error().code == domain::DebugErrorCode::not_found,
          "job is not_found after release");
}

void test_analysis_job_manager_cancel_running_job() {
    using namespace argos;
    security::SecurityPolicy policy{};
    auto memory = std::make_shared<std::vector<std::byte>>(200U * 1024U, std::byte{0x41});
    auto gate = std::make_shared<ReadGate>();  // starts closed: the first read blocks.

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "cancel-running test attaches");
    if (!session) return;

    application::AnalysisJobManager manager{service, policy};
    application::AnalysisJobManager::StringScanRequest request;
    request.min_length = 4U;
    request.encoding = "ascii";
    request.result_limit = 16U;

    auto submitted = manager.submit(
        session->id, domain::AsyncScanOperation::strings, request,
        application::AnalysisJobManager::ExecutionLimits{memory->size() + 4096U, 60'000U}
    );
    check(submitted.has_value(), "submit accepts a strings job");
    if (!submitted) return;

    // Deterministic sync point: proves the worker reached native I/O.
    gate->wait_until_blocked_at_least(1U);

    auto status_while_blocked = manager.status(session->id, submitted->id);
    check(status_while_blocked.has_value() && status_while_blocked->state == domain::AnalysisJobState::running,
          "status() is responsive and reports running while the worker is blocked in I/O");

    auto cancelled = manager.cancel(session->id, submitted->id);
    check(cancelled.has_value() && cancelled->cancel_requested,
          "job_cancel is responsive while the worker is blocked in I/O");
    check(cancelled.has_value() && cancelled->state == domain::AnalysisJobState::running,
          "cancel_requested precedes the terminal state, it does not jump to it");

    gate->open_gate();  // Let the worker observe the stop request cooperatively.
    const auto final_status = poll_until_terminal(manager, session->id, submitted->id);
    check(final_status.state == domain::AnalysisJobState::cancelled, "job reaches cancelled");
    if (final_status.termination) {
        check(final_status.termination->reason == domain::AnalysisStopReason::client_cancelled,
              "stop_reason is client_cancelled");
        check(!final_status.termination->coverage_complete && !final_status.termination->results_complete,
              "a cancelled job never reports complete coverage or results");
    }

    auto second_cancel = manager.cancel(session->id, submitted->id);
    check(second_cancel.has_value() && second_cancel->state == domain::AnalysisJobState::cancelled,
          "cancelling an already-terminal job is idempotent");

    auto release_ok = manager.release(session->id, submitted->id);
    check(release_ok.has_value(), "release succeeds once the cancelled job is terminal");
}

void test_analysis_job_manager_queued_cancel_and_backpressure() {
    using namespace argos;
    security::SecurityPolicy policy{};
    policy.max_async_jobs_per_session = 2U;
    policy.max_async_queue_depth = 5U;
    policy.max_async_workers = 1U;

    auto memory = std::make_shared<std::vector<std::byte>>(64U * 1024U, std::byte{0x00});
    auto gate = std::make_shared<ReadGate>();  // starts closed

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "backpressure test attaches");
    if (!session) return;

    application::AnalysisJobManager manager{service, policy};
    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern = {std::byte{0xAA}};
    request.result_limit = 16U;
    const application::AnalysisJobManager::ExecutionLimits limits{memory->size(), 60'000U};

    auto job1 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job1.has_value(), "first job for the session is accepted");
    if (!job1) return;
    gate->wait_until_blocked_at_least(1U);  // job1 is now provably running.

    auto job1_again_check = manager.status(session->id, job1->id);
    check(job1_again_check.has_value() && job1_again_check->state == domain::AnalysisJobState::running,
          "job1 is running while holding the session's one-running-job slot");

    // job2 targets the same session: it must queue behind job1, never run
    // concurrently with it (Spec 0008: at most one running job per session).
    auto job2 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job2.has_value() && job2->state == domain::AnalysisJobState::queued,
          "a second job for a session that already has one running stays queued");

    // The session is now at its per-session job cap (2): a third submission
    // must be rejected before any buffer is allocated or any I/O happens.
    auto job3 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(!job3.has_value() &&
              job3.error().code == domain::DebugErrorCode::limit_exceeded &&
              job3.error().reason == "job_queue_full",
          "a session at its job quota is rejected with limit_exceeded/job_queue_full");

    // Cancelling a queued job is immediate: it never touches the target.
    auto cancel_queued = manager.cancel(session->id, job2->id);
    check(cancel_queued.has_value() && cancel_queued->state == domain::AnalysisJobState::cancelled,
          "cancelling a queued job completes immediately");
    if (cancel_queued && cancel_queued->termination) {
        check(cancel_queued->termination->reason == domain::AnalysisStopReason::client_cancelled,
              "a queued cancel reports client_cancelled");
    }
    auto release_queued = manager.release(session->id, job2->id);
    check(release_queued.has_value(), "a queued-then-cancelled job can be released immediately");

    // A running/queued job cannot be released or read before it is terminal.
    auto early_results = manager.results(session->id, job1->id, 0U, 10U);
    check(!early_results.has_value() &&
              early_results.error().code == domain::DebugErrorCode::invalid_state &&
              early_results.error().reason == "job_not_terminal",
          "job_results on a running job is invalid_state/job_not_terminal");
    auto early_release = manager.release(session->id, job1->id);
    check(!early_release.has_value() && early_release.error().code == domain::DebugErrorCode::invalid_state,
          "release on a running job is rejected");

    gate->open_gate();
    const auto final_status = poll_until_terminal(manager, session->id, job1->id);
    check(final_status.state == domain::AnalysisJobState::completed, "job1 eventually completes");
    (void)manager.release(session->id, job1->id);
}

void test_analysis_job_manager_ttl_and_tombstone() {
    using namespace argos;
    security::SecurityPolicy policy{};
    policy.async_results_ttl_ms = 100U;
    policy.async_tombstone_ttl_ms = 50U;

    auto memory = std::make_shared<std::vector<std::byte>>(4U * 1024U, std::byte{0xAA});
    auto gate = std::make_shared<ReadGate>();
    gate->open_gate();

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "TTL test attaches");
    if (!session) return;

    // Fake, test-controlled clock: no test in this suite sleeps for a fixed
    // duration to cross a TTL boundary. Time only moves when the test moves
    // it explicitly.
    auto fake_now_ms = std::make_shared<std::atomic<std::int64_t>>(0);
    application::AnalysisJobManager::ClockFn clock = [fake_now_ms]() {
        return application::AnalysisJobManager::Clock::time_point{} +
            std::chrono::milliseconds(fake_now_ms->load());
    };
    application::AnalysisJobManager manager{service, policy, clock};

    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern = {std::byte{0xAA}};
    request.result_limit = 4U;
    auto submitted = manager.submit(
        session->id, domain::AsyncScanOperation::scan_exact, request,
        application::AnalysisJobManager::ExecutionLimits{memory->size() + 4096U, 60'000U}
    );
    check(submitted.has_value(), "TTL test job is accepted");
    if (!submitted) return;
    const auto status = poll_until_terminal(manager, session->id, submitted->id);
    check(status.state == domain::AnalysisJobState::completed, "TTL test job completes");

    auto fresh_results = manager.results(session->id, submitted->id, 0U, 10U);
    check(fresh_results.has_value(), "results are available immediately after completion");

    fake_now_ms->store(150);  // past async_results_ttl_ms (100)
    auto expired_status = manager.status(session->id, submitted->id);
    check(expired_status.has_value() && expired_status->results_expired && !expired_status->results_available,
          "status() reports results_expired once past the results TTL");
    auto expired_results = manager.results(session->id, submitted->id, 0U, 10U);
    check(!expired_results.has_value() &&
              expired_results.error().code == domain::DebugErrorCode::invalid_state &&
              expired_results.error().reason == "results_expired",
          "job_results answers invalid_state/results_expired once results have expired");

    // Past results_ttl_ms + tombstone_ttl_ms (150): reaping is an
    // opportunistic side effect of the *next* status() call, not of the
    // clock alone -- the first call at this instant still finds (and then
    // reaps) the tombstone, so it observes it one final time before it goes.
    fake_now_ms->store(300);
    auto last_look_at_tombstone = manager.status(session->id, submitted->id);
    check(last_look_at_tombstone.has_value(), "a tombstone is still observable exactly at its expiry instant");
    auto after_tombstone_reaped = manager.status(session->id, submitted->id);
    check(!after_tombstone_reaped.has_value() && after_tombstone_reaped.error().code == domain::DebugErrorCode::not_found,
          "the tombstone is reaped after its own TTL and later polls see not_found");
}

void test_analysis_job_manager_detach_session() {
    using namespace argos;
    security::SecurityPolicy policy{};
    auto memory = std::make_shared<std::vector<std::byte>>(64U * 1024U, std::byte{0x00});
    auto gate = std::make_shared<ReadGate>();  // starts closed

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "detach test attaches");
    if (!session) return;

    application::AnalysisJobManager manager{service, policy};
    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern = {std::byte{0xAA}};
    request.result_limit = 4U;
    const application::AnalysisJobManager::ExecutionLimits limits{memory->size(), 60'000U};

    auto job1 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job1.has_value(), "detach test job1 accepted");
    if (!job1) return;
    gate->wait_until_blocked_at_least(1U);  // job1 is running.

    auto job2 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job2.has_value() && job2->state == domain::AnalysisJobState::queued, "job2 stays queued behind job1");

    // Open the gate first: detach_session() blocks the calling thread until
    // the worker actually releases the session, so the worker must be free
    // to observe the stop request and unwind on its own thread.
    gate->open_gate();
    manager.detach_session(session->id);

    auto status1 = manager.status(session->id, job1->id);
    check(!status1.has_value() && status1.error().code == domain::DebugErrorCode::not_found,
          "job1 is gone after detach_session");
    auto status2 = manager.status(session->id, job2->id);
    check(!status2.has_value() && status2.error().code == domain::DebugErrorCode::not_found,
          "the queued job2 is also gone after detach_session");
    // detach_session() clears the owner's closing marker once fully drained
    // (it is a one-shot drain barrier, not a permanent tombstone of the
    // owner id): a *new* submit for the same id is accepted by the manager
    // in isolation. In production this is moot -- MemoryDebugService::detach
    // has already removed the session from SessionManager by this point, so
    // a real scan_start for it fails earlier with not_found regardless; see
    // test_memory_debug_service_rejects_sync_scan_while_job_running for the
    // wired end-to-end path.
}

void test_memory_debug_service_rejects_sync_scan_while_job_running() {
    using namespace argos;
    security::SecurityPolicy policy{};
    auto memory = std::make_shared<std::vector<std::byte>>(64U * 1024U, std::byte{0x00});
    auto gate = std::make_shared<ReadGate>();  // starts closed

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "mutual-exclusion test attaches");
    if (!session) return;

    // This is service.async_jobs(): the *same* manager instance
    // MemoryDebugService's own scan_* methods consult, unlike the
    // standalone managers the other tests construct.
    auto& jobs = service.async_jobs();
    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern = {std::byte{0xAA}};
    request.result_limit = 4U;
    auto submitted = jobs.submit(
        session->id, domain::AsyncScanOperation::scan_exact, request,
        application::AnalysisJobManager::ExecutionLimits{memory->size() + 4096U, 60'000U}
    );
    check(submitted.has_value(), "wired async job is accepted");
    if (!submitted) return;
    gate->wait_until_blocked_at_least(1U);

    std::array<std::byte, 1> sync_pattern{std::byte{0xAA}};
    auto sync_attempt = service.scan_exact(session->id, sync_pattern, 1U, 4096U, 16U, false);
    check(!sync_attempt.has_value() &&
              sync_attempt.error().code == domain::DebugErrorCode::invalid_state &&
              sync_attempt.error().reason == "analysis_job_active",
          "a synchronous scan_exact call is rejected while an async job owns the session's scan slot "
          "(and the async worker calling the very same engine is not rejected by its own guard)");

    gate->open_gate();
    (void)poll_until_terminal(jobs, session->id, submitted->id);
    (void)jobs.release(session->id, submitted->id);

    // Once the job is gone, the sync path is available again.
    auto sync_after = service.scan_exact(session->id, sync_pattern, 1U, 4096U, 16U, false);
    check(sync_after.has_value(), "the sync scan path recovers once no job is running for the session");
}

void test_analysis_job_manager_retained_bytes_budget() {
    using namespace argos;
    security::SecurityPolicy policy{};
    // Only enough room, globally, for 6 ScanMatch entries. One job's worth
    // (4 matches) fits; a second identical job cannot fit its own 4 on top,
    // proving the cap is a single aggregate summed across every retained
    // job, not a per-job allowance -- ARGOS_MCP_MAX_ASYNC_RESULTS_RETAINED_BYTES
    // was declared and clamped by SecurityPolicy but never enforced before
    // this test (it would pass trivially either way otherwise).
    policy.max_async_results_retained_bytes = 6U * sizeof(domain::ScanMatch);

    // 4 KiB of zero bytes with the same 4-byte pattern planted at 4
    // non-overlapping, 4-byte-aligned offsets: scan_exact (alignment 4)
    // finds exactly 4 matches -- an untruncated, range_exhausted sweep from
    // the scan engine's own point of view, so any truncation observed below
    // comes only from the new retained-bytes accounting.
    auto memory = std::make_shared<std::vector<std::byte>>(4U * 1024U, std::byte{0x00});
    const std::array<std::byte, 4> pattern{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    const std::array<std::size_t, 4> offsets{0U, 1024U, 2048U, 3072U};
    for (const auto offset : offsets) {
        std::copy(pattern.begin(), pattern.end(), memory->begin() + static_cast<std::ptrdiff_t>(offset));
    }

    auto gate = std::make_shared<ReadGate>();
    gate->open_gate();  // No blocking needed for this test.

    auto provider = std::make_unique<SingleSessionFakeProvider>(
        [memory, gate]() -> std::unique_ptr<domain::ProcessSession> {
            return std::make_unique<GatedFakeSession>(memory, gate);
        }
    );
    application::MemoryDebugService service{std::move(provider), policy};
    auto session = service.attach(42U, domain::AccessMode::read_only, true);
    check(session.has_value(), "retained-bytes test attaches");
    if (!session) return;

    application::AnalysisJobManager manager{service, policy};

    application::AnalysisJobManager::ExactScanRequest request;
    request.pattern.assign(pattern.begin(), pattern.end());
    request.alignment = 4U;
    request.result_limit = 16U;
    const application::AnalysisJobManager::ExecutionLimits limits{memory->size() + 4096U, 60'000U};

    // job1: budget has room for all 4 matches (4 * sizeof <= 6 * sizeof).
    auto job1 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job1.has_value(), "job1 is accepted");
    if (!job1) return;
    const auto status1 = poll_until_terminal(manager, session->id, job1->id);
    check(status1.state == domain::AnalysisJobState::completed, "job1 completes");
    if (status1.termination) {
        check(!status1.termination->truncated, "job1 fits the retained-bytes budget untruncated");
        check(status1.termination->coverage_complete && status1.termination->results_complete,
              "job1's scan and retention both report complete");
    }
    auto page1 = manager.results(session->id, job1->id, 0U, 10U);
    check(page1.has_value() && page1->total == 4U, "job1 retains all 4 matches it found");

    // job2: identical request, but only 2 * sizeof(ScanMatch) of budget
    // remains globally (6 already spent, 4 held by job1). This is only
    // possible to observe if the cap is a global aggregate, not per job --
    // with a per-job cap job2 would fit exactly like job1 did.
    auto job2 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job2.has_value(), "job2 is accepted");
    if (!job2) return;
    const auto status2 = poll_until_terminal(manager, session->id, job2->id);
    check(status2.state == domain::AnalysisJobState::completed,
          "job2's scan completes even though retention is short on room");
    if (status2.termination) {
        check(status2.termination->coverage_complete,
              "job2 still swept every eligible byte -- scan coverage is independent of result retention");
        check(!status2.termination->results_complete,
              "job2 could not retain every match it found, so results_complete is false");
        check(status2.termination->truncated, "job2's termination is marked truncated, never silently dropped");
        const auto& reasons = status2.termination->truncation_reasons;
        check(std::ranges::find(reasons, domain::AnalysisTruncationReason::retained_bytes_budget) != reasons.end(),
              "retained_bytes_budget names the global retained-bytes cap as the truncation cause");
    }
    auto page2 = manager.results(session->id, job2->id, 0U, 10U);
    check(page2.has_value() && page2->total == 2U,
          "job2 keeps only as many matches as the remaining global budget allows (2 of the 4 it found)");

    // Releasing job1 gives its 4 * sizeof(ScanMatch) share back to the
    // global budget. A third, identical job should now fit fully again --
    // proving release() (not just TTL expiry) frees the aggregate correctly.
    auto release1 = manager.release(session->id, job1->id);
    check(release1.has_value(), "job1 releases cleanly");

    auto job3 = manager.submit(session->id, domain::AsyncScanOperation::scan_exact, request, limits);
    check(job3.has_value(), "job3 is accepted");
    if (!job3) return;
    const auto status3 = poll_until_terminal(manager, session->id, job3->id);
    check(status3.state == domain::AnalysisJobState::completed, "job3 completes");
    if (status3.termination) {
        check(!status3.termination->truncated,
              "job3 fits fully once releasing job1 restored the global retained-bytes budget");
    }
    auto page3 = manager.results(session->id, job3->id, 0U, 10U);
    check(page3.has_value() && page3->total == 4U, "job3 retains all 4 matches after budget was freed by release");

    (void)manager.release(session->id, job2->id);
    (void)manager.release(session->id, job3->id);
}

int main() {
    test_json();
    test_policy();
    test_memory_service();
    test_pdb_metadata_service();
    test_scan_pointers_to();
    test_scan_pointer_chains();
    test_scan_sessions();
    test_scan_session_snapshot_cow();
    test_scan_next_batches_contiguous_candidates();
    test_read_batch_coalesces_ranges();
    test_domain_query_helpers();
    test_output_ring_buffer();
    test_authorize_launch_policy();
    test_launch_and_managed_process();
    test_extract_strings();
    test_unity_il2cpp_metadata();
    test_encode_scan_value();
    test_region_queries();
    test_scan_coverage();
    test_region_page_service();
    test_analysis_job_manager_lifecycle_progress_and_pagination();
    test_analysis_job_manager_cancel_running_job();
    test_analysis_job_manager_queued_cancel_and_backpressure();
    test_analysis_job_manager_ttl_and_tombstone();
    test_analysis_job_manager_detach_session();
    test_analysis_job_manager_retained_bytes_budget();
    test_memory_debug_service_rejects_sync_scan_while_job_running();
    if (failures == 0) {
        std::cout << "All unit tests passed\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed\n";
    return 1;
}
