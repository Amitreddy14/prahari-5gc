cmake_minimum_required(VERSION 3.22)

project(prahari_probe
    VERSION 0.3.0
    DESCRIPTION "Passive 5G core signalling probe"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PRAHARI_WERROR "Treat compiler warnings as errors" ON)
option(PRAHARI_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(PRAHARI_BUILD_TESTS "Build unit tests (needs GoogleTest)" ON)
option(PRAHARI_FUZZ "Build libFuzzer targets (Clang only)" OFF)

include(cmake/Warnings.cmake)

configure_file(include/prahari/version.hpp.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/prahari/version.hpp @ONLY)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# Core library: every decoder lives here so tests and the CLI share one build.
add_library(prahari_core
    src/byte_reader.cpp
    src/pfcp.cpp
    src/pfcp_ie.cpp
    src/net.cpp
    src/session_table.cpp
    src/event.cpp
    src/pipeline.cpp
    src/pcap_source.cpp
    src/plmn.cpp
    src/ngap.cpp
    src/nas.cpp
    src/supi.cpp
    src/ue_table.cpp)
target_include_directories(prahari_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(prahari_core PUBLIC PkgConfig::PCAP OpenSSL::Crypto)
prahari_set_warnings(prahari_core)

add_executable(prahari-probe src/main.cpp)
target_link_libraries(prahari-probe PRIVATE prahari_core)
prahari_set_warnings(prahari-probe)

if(PRAHARI_SANITIZE)
    foreach(t prahari_core prahari-probe)
        target_compile_options(${t} PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
        target_link_options(${t} PUBLIC -fsanitize=address,undefined)
    endforeach()
endif()

if(PRAHARI_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    add_executable(prahari_tests
        tests/test_byte_reader.cpp
        tests/test_pfcp.cpp
        tests/test_net.cpp
        tests/test_pfcp_ie.cpp
        tests/test_session_table.cpp
        tests/test_event.cpp
        tests/test_pipeline_capture.cpp
        tests/test_ngap.cpp
        tests/test_nas.cpp)
    target_compile_definitions(prahari_tests PRIVATE
        PRAHARI_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
    target_link_libraries(prahari_tests PRIVATE prahari_core GTest::gtest GTest::gtest_main)
    prahari_set_warnings(prahari_tests)
    include(GoogleTest)
    gtest_discover_tests(prahari_tests)

    # CLI smoke tests: exit codes are part of the contract.
    add_test(NAME cli_version COMMAND prahari-probe --version)
    add_test(NAME cli_decode_pfcp_heartbeat
             COMMAND prahari-probe decode-pfcp "2001000c0000010000600004e54d2a10")
    set_tests_properties(cli_decode_pfcp_heartbeat PROPERTIES
             PASS_REGULAR_EXPRESSION "\"message\":\"HeartbeatRequest\"")
    add_test(NAME cli_decode_pfcp_truncated COMMAND prahari-probe decode-pfcp "2001")
    set_tests_properties(cli_decode_pfcp_truncated PROPERTIES WILL_FAIL TRUE)
    add_test(NAME cli_run_fixture
             COMMAND prahari-probe run --pcap ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/n4-lifecycle.pcap --seed 7)
    set_tests_properties(cli_run_fixture PROPERTIES
             PASS_REGULAR_EXPRESSION "\"message\":\"SessionDeletionResponse\"")
    add_test(NAME cli_run_needs_input COMMAND prahari-probe run)
    set_tests_properties(cli_run_needs_input PROPERTIES WILL_FAIL TRUE)
    add_test(NAME cli_bench_fixture
             COMMAND prahari-probe bench --pcap ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/n4-lifecycle.pcap --repeat 10)
    set_tests_properties(cli_bench_fixture PROPERTIES PASS_REGULAR_EXPRESSION "\"pfcp_messages\":240,.*ns_per_signalling_msg")
    add_test(NAME cli_bench_n2_fixture
             COMMAND prahari-probe bench --pcap ${CMAKE_CURRENT_SOURCE_DIR}/tests/data/n2-registration.pcap --repeat 10)
    set_tests_properties(cli_bench_n2_fixture PROPERTIES PASS_REGULAR_EXPRESSION "\"ngap_messages\":230,")
endif()

if(PRAHARI_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "PRAHARI_FUZZ requires Clang")
    endif()
    foreach(f fuzz_pfcp fuzz_pfcp_ie fuzz_frame fuzz_ngap fuzz_nas)
        add_executable(${f} fuzz/${f}.cpp)
        target_link_libraries(${f} PRIVATE prahari_core)
        target_compile_options(${f} PRIVATE -fsanitize=fuzzer)
        target_link_options(${f} PRIVATE -fsanitize=fuzzer)
        prahari_set_warnings(${f})
    endforeach()
endif()
