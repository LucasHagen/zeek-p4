
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginRNA)

include(ZeekPlugin)

zeek_plugin_begin(BR_UFRGS_INF RNA)
zeek_plugin_cc(
    src/RnaHdr.cc
    src/RnaOffloaderHdr.cc
    src/RnaPacket.cc
    src/RnaAnalyzer.cc
    src/RnaOffloaderAnalyzer.cc
    src/Plugin.cc
@@CC_FILES@@
)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(
    scripts/__load__.zeek
    scripts/__preload__.zeek
    scripts/types.zeek
    scripts/BR_UFRGS_INF/RNA/main.zeek
    scripts/BR_UFRGS_INF/RNA/__load__.zeek
)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
