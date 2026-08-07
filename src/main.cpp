#include "argos_mcp/application/memory_debug_service.hpp"
#include "argos_mcp/infrastructure/native_process_memory.hpp"
#include "argos_mcp/infrastructure/pdb_type_metadata.hpp"
#include "argos_mcp/observability/logger.hpp"
#include "argos_mcp/protocol/mcp/server.hpp"
#include "argos_mcp/protocol/mcp/tools.hpp"
#include "argos_mcp/security/policy.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>

int main() {
    try {
        const auto policy = argos::security::SecurityPolicy::from_environment();
        argos::observability::Logger logger{argos::observability::log_level_from_environment()};
        auto provider = std::make_unique<argos::infrastructure::NativeProcessMemoryProvider>(
            policy.allow_foreign_user
        );
        auto metadata_provider = std::make_unique<argos::infrastructure::PdbTypeMetadataProvider>();
        argos::application::MemoryDebugService service{
            std::move(provider), policy, std::move(metadata_provider)
        };
        argos::protocol::mcp::ToolCatalog tools{service, logger};
        argos::protocol::mcp::Server server{tools, logger};
        logger.log(
            argos::observability::LogLevel::info,
            "server_started",
            policy.allow_write ? "read-write capability enabled" : "read-only mode"
        );
        return server.run(std::cin, std::cout);
    } catch (const std::exception& exception) {
        std::cerr << "{\"level\":\"fatal\",\"message\":\"" << exception.what() << "\"}\n";
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "{\"level\":\"fatal\",\"message\":\"unknown fatal error\"}\n";
        return EXIT_FAILURE;
    }
}
