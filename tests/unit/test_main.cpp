#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/domain/process_memory.hpp"
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
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <stop_token>
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
            0x1000U, 0x1008U, true, false, false, true, "fake"
        }};
    }

    [[nodiscard]] argos::domain::Result<std::vector<argos::domain::ModuleInfo>> modules() const override {
        return std::vector<argos::domain::ModuleInfo>{argos::domain::ModuleInfo{
            "fake.dll", "C:\\fake.dll", 0x140000000U, 0x1000U
        }};
    }

private:
    std::array<std::byte, 8> memory_{};
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
    test_unity_il2cpp_metadata();
    if (failures == 0) {
        std::cout << "All unit tests passed\n";
        return 0;
    }
    std::cerr << failures << " test(s) failed\n";
    return 1;
}
