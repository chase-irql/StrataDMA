cmake_minimum_required(VERSION 3.20)
project(TeekoDMA VERSION 2.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Teeko DMA Lib currently supports Windows only.")
endif()

option(TEEKO_DMA_BUILD_EXAMPLE "Build the existing example executable" ON)
option(TEEKO_DMA_BUILD_TESTS "Build hardware-independent mock tests" ON)

set(TEEKO_DMA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/Teeko-DMA-Lib/Teeko-DMA-Lib")
set(TEEKO_DMA_SOURCE_DIR "${TEEKO_DMA_ROOT}/Teeko-DMA")
set(TEEKO_DMA_SOURCES
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Advanced.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Backend.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Backend.Interface.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Context.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Input.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Module.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Pattern.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Scanner.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.System.cpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Types.cpp")

add_library(teeko_dma STATIC ${TEEKO_DMA_SOURCES})
add_library(TeekoDMA::TeekoDMA ALIAS teeko_dma)
target_compile_features(teeko_dma PUBLIC cxx_std_17)
target_include_directories(teeko_dma PUBLIC
    "$<BUILD_INTERFACE:${TEEKO_DMA_ROOT}>"
    "$<INSTALL_INTERFACE:include>")
target_compile_definitions(teeko_dma PUBLIC NOMINMAX)
target_link_libraries(teeko_dma PUBLIC
    "${TEEKO_DMA_SOURCE_DIR}/libs/vmm.lib"
    "${TEEKO_DMA_SOURCE_DIR}/libs/leechcore.lib")

if(MSVC)
    target_compile_options(teeko_dma PRIVATE /W4 /permissive-)
endif()

if(TEEKO_DMA_BUILD_EXAMPLE)
    add_executable(teeko_dma_example "${TEEKO_DMA_ROOT}/main.cpp")
    target_link_libraries(teeko_dma_example PRIVATE TeekoDMA::TeekoDMA)
    add_custom_command(TARGET teeko_dma_example POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${TEEKO_DMA_SOURCE_DIR}/deps/info.db"
            "$<TARGET_FILE_DIR:teeko_dma_example>/info.db")
endif()

if(TEEKO_DMA_BUILD_TESTS)
    enable_testing()
    set(TEEKO_DMA_TEST_CORE_SOURCES
        "${TEEKO_DMA_ROOT}/tests/MockFactory.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Advanced.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Backend.Interface.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Context.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Input.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Module.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Pattern.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Scanner.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.System.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Types.cpp")

    add_library(teeko_dma_test_core STATIC ${TEEKO_DMA_TEST_CORE_SOURCES})
    target_compile_features(teeko_dma_test_core PUBLIC cxx_std_17)
    target_include_directories(teeko_dma_test_core PUBLIC "${TEEKO_DMA_ROOT}")
    target_compile_definitions(teeko_dma_test_core PUBLIC NOMINMAX)
    if(MSVC)
        target_compile_options(teeko_dma_test_core PRIVATE /W4 /WX /permissive-)
    endif()

    function(teeko_add_mock_suite target suite_source suite_name suite_label)
        add_executable(${target}
            "${TEEKO_DMA_ROOT}/tests/TestMain.cpp"
            "${TEEKO_DMA_ROOT}/tests/MockVmmBackend.cpp"
            "${TEEKO_DMA_ROOT}/tests/${suite_source}")
        target_link_libraries(${target} PRIVATE teeko_dma_test_core)
        target_compile_definitions(${target} PRIVATE
            TEEKO_TEST_SUITE="${suite_name}")
        if(MSVC)
            target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
        endif()
        add_test(NAME ${target} COMMAND ${target})
        set_tests_properties(${target} PROPERTIES
            LABELS "mock;${suite_label}"
            TIMEOUT 30)
    endfunction()

    teeko_add_mock_suite(teeko_dma_lifecycle_tests
        LifecycleMemoryTests.cpp "lifecycle and memory" "core")
    teeko_add_mock_suite(teeko_dma_scatter_tests
        ScatterContextTests.cpp "scatter and frame gathering" "scatter")
    teeko_add_mock_suite(teeko_dma_scanner_tests
        ScannerAnalysisTests.cpp "scanning and analysis" "scanner")
    teeko_add_mock_suite(teeko_dma_system_tests
        SystemRecoveryTests.cpp "system information and CR3 recovery" "system")
    teeko_add_mock_suite(teeko_dma_registry_vfs_tests
        RegistryVfsTests.cpp "registry and VFS" "registry-vfs")
    teeko_add_mock_suite(teeko_dma_module_tests
        ModuleDumpTests.cpp "module dumping" "module")

    add_executable(teeko_dma_pattern_tests
        "${TEEKO_DMA_ROOT}/tests/PatternSelfTest.cpp"
        "${TEEKO_DMA_SOURCE_DIR}/DMA.Pattern.cpp")
    target_compile_features(teeko_dma_pattern_tests PRIVATE cxx_std_17)
    target_include_directories(teeko_dma_pattern_tests PRIVATE "${TEEKO_DMA_ROOT}")
    target_compile_definitions(teeko_dma_pattern_tests PRIVATE NOMINMAX)
    add_test(NAME teeko_dma_pattern_tests COMMAND teeko_dma_pattern_tests)
    set_tests_properties(teeko_dma_pattern_tests PROPERTIES
        LABELS "unit;pattern"
        TIMEOUT 10)
endif()

include(GNUInstallDirs)
install(TARGETS teeko_dma ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES
    "${TEEKO_DMA_SOURCE_DIR}/DMA.hpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Backend.hpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Context.hpp"
    "${TEEKO_DMA_SOURCE_DIR}/DMA.Types.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/Teeko-DMA")
install(FILES
    "${TEEKO_DMA_SOURCE_DIR}/deps/vmmdll.h"
    "${TEEKO_DMA_SOURCE_DIR}/deps/leechcore.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/Teeko-DMA/deps")
install(FILES
    "${TEEKO_DMA_SOURCE_DIR}/libs/vmm.lib"
    "${TEEKO_DMA_SOURCE_DIR}/libs/leechcore.lib"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${TEEKO_DMA_SOURCE_DIR}/deps/info.db"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/TeekoDMA")
