#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/process_memory.hpp"
#include "argos_mcp/infrastructure/output_ring_buffer.hpp"
#include "argos_mcp/infrastructure/pdb_type_metadata.hpp"
#include "argos_mcp/protocol/json/value.hpp"
#include "argos_mcp/security/policy.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <stop_token>
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
    }

    explicit FakeSession(std::vector<std::byte> memory) : memory_(std::move(memory)) {}

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
        return std::vector<argos::domain::ModuleInfo>{argos::domain::ModuleInfo{
            "fake.dll", "C:\\fake.dll", 0x140000000U, 0x1000U
        }};
    }

private:
    std::vector<std::byte> memory_{};
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

class MutableFakeSession final : public argos::domain::ProcessSession {
public:
    explicit MutableFakeSession(std::shared_ptr<std::vector<std::byte>> memory) : memory_(std::move(memory)) {}

    [[nodiscard]] argos::domain::ProcessId pid() const noexcept override { return 42U; }
    [[nodiscard]] std::string_view process_name() const noexcept override { return "fake-mutable-target"; }
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
};

[[nodiscard]] std::vector<std::byte> encode_i32(std::int32_t value) {
    std::vector<std::byte> bytes(4U);
    const auto unsigned_value = static_cast<std::uint32_t>(value);
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes[index] = static_cast<std::byte>((unsigned_value >> (index * 8U)) & 0xFFU);
    }
    return bytes;
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
        check(first.has_value() && first->candidate_count == 4U, "scan_first(unknown) captures all aligned candidates");
        if (!first) return;

        (*memory)[0] = encode_i32(90)[0]; (*memory)[1] = encode_i32(90)[1];
        (*memory)[2] = encode_i32(90)[2]; (*memory)[3] = encode_i32(90)[3];
        auto slot2_new = encode_i32(80);
        std::copy(slot2_new.begin(), slot2_new.end(), memory->begin() + 8);
        auto slot3_new = encode_i32(250);
        std::copy(slot3_new.begin(), slot3_new.end(), memory->begin() + 12);

        auto decreased = service.scan_next(first->id, domain::ScanComparison::decreased, std::nullopt, std::nullopt);
        check(decreased.has_value() && decreased->candidate_count == 2U,
              "scan_next(decreased) keeps only candidates whose value went down");

        auto results = service.scan_results(first->id, 0U, 50U);
        check(results.has_value() && results->size() == 2U, "scan_results returns the surviving candidates");

        auto reset = service.scan_reset(first->id);
        check(reset.has_value(), "scan_reset succeeds");
        auto after_reset = service.scan_results(first->id, 0U, 50U);
        check(after_reset.has_value() && after_reset->empty(), "scan_reset clears candidates");

        auto detach_result = service.detach(attached->id);
        check(detach_result.has_value(), "debug session detaches");
        auto after_detach = service.scan_results(first->id, 0U, 50U);
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
        check(exact.has_value() && exact->candidate_count == 1U, "scan_first(exact) finds the single matching candidate");

        auto in_range = service.scan_first(
            attached->id, domain::ScanValueType::i32, domain::ScanComparison::in_range,
            std::nullopt, std::pair{encode_i32(60), encode_i32(250)}, 4096U, 256U, false
        );
        check(in_range.has_value() && in_range->candidate_count == 2U,
              "scan_first(in_range) keeps only candidates within [low, high]");
        if (in_range) {
            auto unsupported_in_range_next = service.scan_next(
                in_range->id, domain::ScanComparison::in_range, std::nullopt, std::nullopt
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
            first->id, domain::ScanComparison::increased_by, std::nullopt, encode_i32(30)
        );
        check(increased_by.has_value() && increased_by->candidate_count == 1U,
              "scan_next(increased_by) matches only the candidate that increased by exactly delta");
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
        check(first.has_value() && first->candidate_count == 2U,
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

void test_unity_il2cpp_metadata() {
    const auto root = std::filesystem::temp_directory_path() / "argos-unity-metadata-fixture";
    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    std::filesystem::create_directories(root, cleanup_error);
    check(!cleanup_error, "Unity fixture directory is created");
    if (cleanup_error) return;

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
    std::filesystem::remove_all(root, cleanup_error);
}

}  // namespace

int main() {
    test_json();
    test_policy();
    test_memory_service();
    test_pdb_metadata_service();
    test_scan_pointers_to();
    test_scan_sessions();
    test_output_ring_buffer();
    test_authorize_launch_policy();
    test_launch_and_managed_process();
    test_extract_strings();
    test_unity_il2cpp_metadata();
    if (failures == 0) {
        std::cout << "All unit tests passed\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed\n";
    return 1;
}
