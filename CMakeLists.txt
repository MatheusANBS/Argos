cmake_minimum_required(VERSION 3.25)
project(argos_runtime_memory_mcp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_EXTENSIONS OFF)

option(ARGOS_BUILD_TESTS "Build tests" ON)
option(ARGOS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ARGOS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ARGOS_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ARGOS_ENABLE_CLANG_TIDY "Enable clang-tidy when available" OFF)
option(ARGOS_ENABLE_IPO "Enable interprocedural optimization in Release builds" OFF)

if(ARGOS_ENABLE_IPO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ARGOS_IPO_SUPPORTED OUTPUT ARGOS_IPO_ERROR LANGUAGES CXX)
    if(ARGOS_IPO_SUPPORTED)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    else()
        message(WARNING "Interprocedural optimization is unavailable: ${ARGOS_IPO_ERROR}")
    endif()
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Sanitizers)
include(StaticAnalysis)

add_library(argos_domain
    src/domain/types.cpp
)
target_include_directories(argos_domain PUBLIC include)
target_compile_features(argos_domain PUBLIC cxx_std_23)
argos_set_warnings(argos_domain)
argos_enable_sanitizers(argos_domain)
argos_enable_static_analysis(argos_domain)

add_library(argos_infrastructure
    src/infrastructure/native_process_memory.cpp
    src/infrastructure/pdb_type_metadata.cpp
    src/infrastructure/output_ring_buffer.cpp
)
target_include_directories(argos_infrastructure PUBLIC include)
target_link_libraries(argos_infrastructure PUBLIC argos_domain)
target_compile_features(argos_infrastructure PUBLIC cxx_std_23)
argos_set_warnings(argos_infrastructure)
argos_enable_sanitizers(argos_infrastructure)
argos_enable_static_analysis(argos_infrastructure)
if(WIN32)
    target_link_libraries(argos_infrastructure PRIVATE advapi32 dbghelp)
endif()

add_library(argos_application
    src/application/session_manager.cpp
    src/application/scan_session_manager.cpp
    src/application/memory_debug_service.cpp
    src/application/analysis_job_manager.cpp
    src/security/policy.cpp
)
target_include_directories(argos_application PUBLIC include)
target_link_libraries(argos_application PUBLIC argos_domain argos_infrastructure)
target_compile_features(argos_application PUBLIC cxx_std_23)
argos_set_warnings(argos_application)
argos_enable_sanitizers(argos_application)
argos_enable_static_analysis(argos_application)

add_library(argos_protocol
    src/protocol/json/value.cpp
    src/protocol/mcp/tools.cpp
    src/protocol/mcp/server.cpp
    src/observability/logger.cpp
)
target_include_directories(argos_protocol PUBLIC include)
target_link_libraries(argos_protocol PUBLIC argos_application)
target_compile_features(argos_protocol PUBLIC cxx_std_23)
argos_set_warnings(argos_protocol)
argos_enable_sanitizers(argos_protocol)
argos_enable_static_analysis(argos_protocol)

add_executable(argos_runtime_memory_mcp src/main.cpp)
target_link_libraries(argos_runtime_memory_mcp PRIVATE argos_protocol)
target_compile_features(argos_runtime_memory_mcp PRIVATE cxx_std_23)
argos_set_warnings(argos_runtime_memory_mcp)
argos_enable_sanitizers(argos_runtime_memory_mcp)
argos_enable_static_analysis(argos_runtime_memory_mcp)

add_executable(argos_memory_target tools/memory_target.cpp)
target_compile_features(argos_memory_target PRIVATE cxx_std_23)
argos_set_warnings(argos_memory_target)
argos_enable_sanitizers(argos_memory_target)

add_executable(argos_debug_target_game tools/debug_target_game.cpp)
target_compile_features(argos_debug_target_game PRIVATE cxx_std_23)
argos_set_warnings(argos_debug_target_game)
argos_enable_sanitizers(argos_debug_target_game)
if(WIN32)
    target_link_libraries(argos_debug_target_game PRIVATE user32)
endif()

install(TARGETS argos_runtime_memory_mcp RUNTIME DESTINATION bin)

if(ARGOS_BUILD_TESTS)
    enable_testing()
    add_executable(argos_unit_tests
        tests/unit/test_main.cpp
    )
    target_link_libraries(argos_unit_tests PRIVATE argos_protocol)
    target_compile_features(argos_unit_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_unit_tests)
    argos_enable_sanitizers(argos_unit_tests)
    add_test(NAME argos_unit_tests COMMAND argos_unit_tests)

    add_executable(argos_contract_tests
        tests/contract/test_mcp_contract.cpp
    )
    target_link_libraries(argos_contract_tests PRIVATE argos_protocol)
    target_compile_features(argos_contract_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_contract_tests)
    argos_enable_sanitizers(argos_contract_tests)
    add_test(NAME argos_contract_tests COMMAND argos_contract_tests)
endif()
