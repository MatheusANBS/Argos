cmake_minimum_required(VERSION 3.25)
project(argos_runtime_memory_mcp VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_EXTENSIONS OFF)

# Ninja tracks header dependencies on MSVC by parsing /showIncludes, whose
# prefix is localized. CMake probes it from cl.exe at configure time. If this
# build directory was configured without a working cl.exe on PATH, the probe
# falls back to the English default, ninja stops recognizing the lines, and
# header changes silently stop triggering rebuilds. That surfaces much later as
# a stale object linked against a changed ABI -- an access violation in a test
# that prints nothing -- instead of as a build error. Fail loudly here instead.
if(MSVC AND CMAKE_GENERATOR MATCHES "Ninja" AND NOT CMAKE_CL_SHOWINCLUDES_PREFIX)
    message(FATAL_ERROR
        "cl.exe /showIncludes prefix was not detected, so header dependency "
        "tracking would be silently broken. Configure this build directory "
        "from a Developer Command Prompt, or run tools/build.ps1, which sets "
        "the MSVC environment up first.")
endif()

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

# Vendored x86/x64 decoder for the read-only disassembler (ADR-0029). Build only
# the static library; the upstream examples, tools, tests and Doxygen are not
# part of this project. Zydis is third-party C: its own warning and analysis
# settings apply, not ours.
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/zydis EXCLUDE_FROM_ALL)

add_library(argos_domain
    src/domain/types.cpp
    src/domain/address_inspection.cpp
    src/domain/unreal_runtime.cpp
    src/domain/santa_monica_runtime.cpp
    src/domain/santa_monica_bridge.cpp
    src/domain/santa_monica_invoke.cpp
    src/domain/santa_monica_dispatcher.cpp
    src/domain/santa_monica_inventory.cpp
    src/domain/disassembly.cpp
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
    src/infrastructure/santa_monica_reflection_stream.cpp
    src/infrastructure/santa_monica_bridge_crypto.cpp
    src/infrastructure/santa_monica_handshake_stream.cpp
    src/infrastructure/santa_monica_bridge_channel.cpp
    src/infrastructure/santa_monica_invoke_stream.cpp
    src/infrastructure/santa_monica_bridge_service.cpp
    src/infrastructure/santa_monica_bridge_peer.cpp
    src/infrastructure/santa_monica_native_reader.cpp
    src/infrastructure/santa_monica_inventory_reader.cpp
    src/infrastructure/zydis_disassembler.cpp
)
target_include_directories(argos_infrastructure PUBLIC include)
target_link_libraries(argos_infrastructure PUBLIC argos_domain)
# Zydis is an implementation detail behind the Disassembler port, so it is a
# private link dependency: no Zydis type appears in argos_infrastructure's
# public headers (ADR-0029).
target_link_libraries(argos_infrastructure PRIVATE Zydis)
target_compile_features(argos_infrastructure PUBLIC cxx_std_23)
argos_set_warnings(argos_infrastructure)
argos_enable_sanitizers(argos_infrastructure)
argos_enable_static_analysis(argos_infrastructure)
if(WIN32)
    # bcrypt is the system CNG provider used for HMAC-SHA-256 and nonces
    # (ADR-0024); no cryptographic primitive is implemented in this repository.
    target_link_libraries(argos_infrastructure PRIVATE advapi32 dbghelp bcrypt)
endif()

add_library(argos_application
    src/application/session_manager.cpp
    src/application/scan_session_manager.cpp
    src/application/unreal_runtime_manager.cpp
    src/application/memory_debug_service.cpp
    src/application/memory_debug_service_santamonica.cpp
    src/application/santa_monica_runtime_manager.cpp
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

    # Controlled synthetic peer for the Santa Monica channel (ADR-0025). It
    # speaks the protocol with made-up metadata; it is not a game bridge.
    add_executable(argos_santa_monica_peer tools/santa_monica_peer.cpp)
    target_link_libraries(argos_santa_monica_peer PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_peer PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_peer)
    argos_enable_sanitizers(argos_santa_monica_peer)
    argos_enable_static_analysis(argos_santa_monica_peer)

    add_library(argos_debug_bridge SHARED tools/debug_bridge.cpp)
    target_link_libraries(argos_debug_bridge PRIVATE argos_infrastructure)
    target_compile_features(argos_debug_bridge PRIVATE cxx_std_23)
    argos_set_warnings(argos_debug_bridge)
    argos_enable_sanitizers(argos_debug_bridge)
    argos_enable_static_analysis(argos_debug_bridge)
    set_target_properties(argos_debug_bridge PROPERTIES OUTPUT_NAME "argos_debug_bridge")

    # Client driver for the bridge's named-pipe server: sends one AddResource
    # command and prints the result. Pairs with ARGOS_BRIDGE_PIPE on the target.
    add_executable(argos_bridge_invoke tools/bridge_invoke.cpp)
    target_link_libraries(argos_bridge_invoke PRIVATE argos_infrastructure)
    target_compile_features(argos_bridge_invoke PRIVATE cxx_std_23)
    argos_set_warnings(argos_bridge_invoke)
    argos_enable_sanitizers(argos_bridge_invoke)
    argos_enable_static_analysis(argos_bridge_invoke)
endif()

install(TARGETS argos_runtime_memory_mcp RUNTIME DESTINATION bin)
if(WIN32)
    install(TARGETS argos_debug_bridge argos_santa_monica_peer RUNTIME DESTINATION bin)
endif()

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

    add_executable(argos_address_inspection_tests
        tests/unit/test_address_inspection.cpp
    )
    target_include_directories(argos_address_inspection_tests PRIVATE tests/unit)
    target_link_libraries(argos_address_inspection_tests PRIVATE argos_protocol)
    target_compile_features(argos_address_inspection_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_address_inspection_tests)
    argos_enable_sanitizers(argos_address_inspection_tests)
    add_test(NAME argos_address_inspection_tests COMMAND argos_address_inspection_tests)

    add_executable(argos_unreal_runtime_tests
        tests/unit/test_unreal_runtime.cpp
    )
    target_include_directories(argos_unreal_runtime_tests PRIVATE tests/unit)
    target_link_libraries(argos_unreal_runtime_tests PRIVATE argos_protocol)
    target_compile_features(argos_unreal_runtime_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_unreal_runtime_tests)
    argos_enable_sanitizers(argos_unreal_runtime_tests)
    add_test(NAME argos_unreal_runtime_tests COMMAND argos_unreal_runtime_tests)

    add_executable(argos_contract_tests
        tests/contract/test_mcp_contract.cpp
    )
    target_link_libraries(argos_contract_tests PRIVATE argos_protocol)
    target_compile_features(argos_contract_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_contract_tests)
    argos_enable_sanitizers(argos_contract_tests)
    if(WIN32)
        # The contract test drives the whole chain against the controlled peer,
        # so it needs the exact binary CMake just built.
        target_compile_definitions(argos_contract_tests PRIVATE
            ARGOS_SANTAMONICA_PEER="$<TARGET_FILE:argos_santa_monica_peer>")
        add_dependencies(argos_contract_tests argos_santa_monica_peer)
    endif()
    add_test(NAME argos_contract_tests COMMAND argos_contract_tests)

    add_executable(argos_disassembly_tests tests/unit/test_disassembly.cpp)
    target_include_directories(argos_disassembly_tests PRIVATE tests/unit)
    target_link_libraries(argos_disassembly_tests PRIVATE argos_protocol)
    target_compile_features(argos_disassembly_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_disassembly_tests)
    argos_enable_sanitizers(argos_disassembly_tests)
    add_test(NAME argos_disassembly_tests COMMAND argos_disassembly_tests)

    add_executable(argos_santa_monica_runtime_tests tests/unit/test_santa_monica_runtime.cpp)
    target_link_libraries(argos_santa_monica_runtime_tests PRIVATE argos_domain)
    target_compile_features(argos_santa_monica_runtime_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_runtime_tests)
    argos_enable_sanitizers(argos_santa_monica_runtime_tests)
    argos_enable_static_analysis(argos_santa_monica_runtime_tests)
    add_test(NAME argos_santa_monica_runtime_tests COMMAND argos_santa_monica_runtime_tests)

    add_executable(argos_santa_monica_invoke_tests tests/unit/test_santa_monica_invoke.cpp)
    target_link_libraries(argos_santa_monica_invoke_tests PRIVATE argos_domain)
    target_compile_features(argos_santa_monica_invoke_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_invoke_tests)
    argos_enable_sanitizers(argos_santa_monica_invoke_tests)
    argos_enable_static_analysis(argos_santa_monica_invoke_tests)
    add_test(NAME argos_santa_monica_invoke_tests COMMAND argos_santa_monica_invoke_tests)

    add_executable(argos_santa_monica_dispatcher_tests tests/unit/test_santa_monica_dispatcher.cpp)
    target_link_libraries(argos_santa_monica_dispatcher_tests PRIVATE argos_domain)
    target_compile_features(argos_santa_monica_dispatcher_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_dispatcher_tests)
    argos_enable_sanitizers(argos_santa_monica_dispatcher_tests)
    argos_enable_static_analysis(argos_santa_monica_dispatcher_tests)
    add_test(NAME argos_santa_monica_dispatcher_tests COMMAND argos_santa_monica_dispatcher_tests)

    add_executable(argos_santa_monica_stream_tests tests/unit/test_santa_monica_reflection_stream.cpp)
    target_link_libraries(argos_santa_monica_stream_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_stream_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_stream_tests)
    argos_enable_sanitizers(argos_santa_monica_stream_tests)
    argos_enable_static_analysis(argos_santa_monica_stream_tests)
    add_test(NAME argos_santa_monica_stream_tests COMMAND argos_santa_monica_stream_tests)

    add_executable(argos_santa_monica_invoke_stream_tests tests/unit/test_santa_monica_invoke_stream.cpp)
    target_link_libraries(argos_santa_monica_invoke_stream_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_invoke_stream_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_invoke_stream_tests)
    argos_enable_sanitizers(argos_santa_monica_invoke_stream_tests)
    argos_enable_static_analysis(argos_santa_monica_invoke_stream_tests)
    add_test(NAME argos_santa_monica_invoke_stream_tests COMMAND argos_santa_monica_invoke_stream_tests)

    add_executable(argos_santa_monica_bridge_service_tests tests/unit/test_santa_monica_bridge_service.cpp)
    target_link_libraries(argos_santa_monica_bridge_service_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_bridge_service_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_bridge_service_tests)
    argos_enable_sanitizers(argos_santa_monica_bridge_service_tests)
    argos_enable_static_analysis(argos_santa_monica_bridge_service_tests)
    add_test(NAME argos_santa_monica_bridge_service_tests COMMAND argos_santa_monica_bridge_service_tests)

    if(WIN32)
        # Loads the built bridge DLL (LoadLibrary == the injection code path) and
        # drives its exported ABI end to end on the controlled target's own code.
        add_executable(argos_debug_bridge_load_tests tests/unit/test_debug_bridge_load.cpp)
        target_link_libraries(argos_debug_bridge_load_tests PRIVATE argos_infrastructure)
        target_compile_features(argos_debug_bridge_load_tests PRIVATE cxx_std_23)
        argos_set_warnings(argos_debug_bridge_load_tests)
        argos_enable_sanitizers(argos_debug_bridge_load_tests)
        argos_enable_static_analysis(argos_debug_bridge_load_tests)
        target_compile_definitions(argos_debug_bridge_load_tests PRIVATE
            ARGOS_DEBUG_BRIDGE_DLL="$<TARGET_FILE:argos_debug_bridge>")
        add_dependencies(argos_debug_bridge_load_tests argos_debug_bridge)
        add_test(NAME argos_debug_bridge_load_tests COMMAND argos_debug_bridge_load_tests)
    endif()

    add_executable(argos_santa_monica_bridge_tests tests/unit/test_santa_monica_bridge.cpp)
    target_link_libraries(argos_santa_monica_bridge_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_bridge_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_bridge_tests)
    argos_enable_sanitizers(argos_santa_monica_bridge_tests)
    argos_enable_static_analysis(argos_santa_monica_bridge_tests)
    if(WIN32)
        # The test cross-checks the provider HMAC against the RFC 2104
        # construction, so it calls CNG directly as well.
        target_link_libraries(argos_santa_monica_bridge_tests PRIVATE bcrypt)
    endif()
    add_test(NAME argos_santa_monica_bridge_tests COMMAND argos_santa_monica_bridge_tests)

    add_executable(argos_santa_monica_channel_tests tests/unit/test_santa_monica_channel.cpp)
    target_link_libraries(argos_santa_monica_channel_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_channel_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_channel_tests)
    argos_enable_sanitizers(argos_santa_monica_channel_tests)
    argos_enable_static_analysis(argos_santa_monica_channel_tests)
    add_test(NAME argos_santa_monica_channel_tests COMMAND argos_santa_monica_channel_tests)

    add_executable(argos_santa_monica_native_tests tests/unit/test_santa_monica_native_reader.cpp)
    target_link_libraries(argos_santa_monica_native_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_native_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_native_tests)
    argos_enable_sanitizers(argos_santa_monica_native_tests)
    argos_enable_static_analysis(argos_santa_monica_native_tests)
    add_test(NAME argos_santa_monica_native_tests COMMAND argos_santa_monica_native_tests)

    add_executable(argos_santa_monica_inventory_tests tests/unit/test_santa_monica_inventory.cpp)
    target_link_libraries(argos_santa_monica_inventory_tests PRIVATE argos_infrastructure)
    target_compile_features(argos_santa_monica_inventory_tests PRIVATE cxx_std_23)
    argos_set_warnings(argos_santa_monica_inventory_tests)
    argos_enable_sanitizers(argos_santa_monica_inventory_tests)
    argos_enable_static_analysis(argos_santa_monica_inventory_tests)
    add_test(NAME argos_santa_monica_inventory_tests COMMAND argos_santa_monica_inventory_tests)
endif()
