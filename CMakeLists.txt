cmake_minimum_required(VERSION 3.20)
project(StrataDMA VERSION 2.0.0 LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "StrataDMA currently supports Windows only.")
endif()

option(STRATA_DMA_BUILD_EXAMPLE "Build the existing example executable" ON)
option(STRATA_DMA_BUILD_TESTS "Build hardware-independent mock tests" ON)

set(STRATA_DMA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/StrataDMA/StrataDMA")
set(STRATA_DMA_SOURCE_DIR "${STRATA_DMA_ROOT}/StrataDMA")
set(STRATA_DMA_SOURCES
    "${STRATA_DMA_SOURCE_DIR}/DMA.Advanced.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Backend.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Backend.Interface.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Context.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Input.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Module.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Scanner.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.System.cpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Types.cpp")

add_library(strata_dma STATIC ${STRATA_DMA_SOURCES})
add_library(StrataDMA::StrataDMA ALIAS strata_dma)
target_compile_features(strata_dma PUBLIC cxx_std_17)
target_include_directories(strata_dma PUBLIC
    "$<BUILD_INTERFACE:${STRATA_DMA_ROOT}>"
    "$<INSTALL_INTERFACE:include>")
target_compile_definitions(strata_dma PUBLIC NOMINMAX)
target_link_libraries(strata_dma PUBLIC
    "${STRATA_DMA_SOURCE_DIR}/libs/vmm.lib"
    "${STRATA_DMA_SOURCE_DIR}/libs/leechcore.lib")

if(MSVC)
    target_compile_options(strata_dma PRIVATE /W4 /permissive-)
endif()

if(STRATA_DMA_BUILD_EXAMPLE)
    add_executable(strata_dma_example "${STRATA_DMA_ROOT}/main.cpp")
    target_link_libraries(strata_dma_example PRIVATE StrataDMA::StrataDMA)
    add_custom_command(TARGET strata_dma_example POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${STRATA_DMA_SOURCE_DIR}/deps/info.db"
            "$<TARGET_FILE_DIR:strata_dma_example>/info.db")
endif()

if(STRATA_DMA_BUILD_TESTS)
    enable_testing()
    set(STRATA_DMA_TEST_CORE_SOURCES
        "${STRATA_DMA_ROOT}/tests/MockFactory.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Advanced.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Backend.Interface.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Context.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Input.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Module.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Scanner.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.System.cpp"
        "${STRATA_DMA_SOURCE_DIR}/DMA.Types.cpp")

    add_library(strata_dma_test_core STATIC ${STRATA_DMA_TEST_CORE_SOURCES})
    target_compile_features(strata_dma_test_core PUBLIC cxx_std_17)
    target_include_directories(strata_dma_test_core PUBLIC "${STRATA_DMA_ROOT}")
    target_compile_definitions(strata_dma_test_core PUBLIC NOMINMAX)
    if(MSVC)
        target_compile_options(strata_dma_test_core PRIVATE /W4 /WX /permissive-)
    endif()

    function(strata_add_mock_suite target suite_source suite_name suite_label)
        add_executable(${target}
            "${STRATA_DMA_ROOT}/tests/TestMain.cpp"
            "${STRATA_DMA_ROOT}/tests/MockVmmBackend.cpp"
            "${STRATA_DMA_ROOT}/tests/${suite_source}")
        target_link_libraries(${target} PRIVATE strata_dma_test_core)
        target_compile_definitions(${target} PRIVATE
            STRATA_TEST_SUITE="${suite_name}")
        if(MSVC)
            target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
        endif()
        add_test(NAME ${target} COMMAND ${target})
        set_tests_properties(${target} PROPERTIES
            LABELS "mock;${suite_label}"
            TIMEOUT 30)
    endfunction()

    strata_add_mock_suite(strata_dma_lifecycle_tests
        LifecycleMemoryTests.cpp "lifecycle and memory" "core")
    strata_add_mock_suite(strata_dma_scatter_tests
        ScatterContextTests.cpp "scatter and frame gathering" "scatter")
    strata_add_mock_suite(strata_dma_scanner_tests
        ScannerAnalysisTests.cpp "scanning and analysis" "scanner")
    strata_add_mock_suite(strata_dma_system_tests
        SystemRecoveryTests.cpp "system information and CR3 recovery" "system")
    strata_add_mock_suite(strata_dma_registry_vfs_tests
        RegistryVfsTests.cpp "registry and VFS" "registry-vfs")
    strata_add_mock_suite(strata_dma_module_tests
        ModuleDumpTests.cpp "module dumping" "module")
endif()

include(GNUInstallDirs)
install(TARGETS strata_dma ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES
    "${STRATA_DMA_SOURCE_DIR}/DMA.hpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Backend.hpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Context.hpp"
    "${STRATA_DMA_SOURCE_DIR}/DMA.Types.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/StrataDMA")
install(FILES
    "${STRATA_DMA_SOURCE_DIR}/deps/vmmdll.h"
    "${STRATA_DMA_SOURCE_DIR}/deps/leechcore.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/StrataDMA/deps")
install(FILES
    "${STRATA_DMA_SOURCE_DIR}/libs/vmm.lib"
    "${STRATA_DMA_SOURCE_DIR}/libs/leechcore.lib"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(FILES "${STRATA_DMA_SOURCE_DIR}/deps/info.db"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/StrataDMA")
