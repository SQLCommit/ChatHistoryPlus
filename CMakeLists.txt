# chathistoryplus - Ashita v4 plugin (32-bit).
# Expands native chat history to 140 records per page.
cmake_minimum_required(VERSION 3.22)

project(chathistoryplus LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(AshitaSDK REQUIRED)
ashita_sdk_initialize()

# Only the translation unit and the exports; the headers it includes are found next to it. That way this file also
# builds an older release's source, which has fewer headers.
add_library(chathistoryplus MODULE
    src/chathistoryplus.cpp
    src/exports.def
)

set_target_properties(chathistoryplus PROPERTIES
    PREFIX ""
    OUTPUT_NAME chathistoryplus
    SUFFIX ".dll"
)

# Attach SDK includes/libs and the recommended compiler/linker defaults.
ashita_sdk_attach(chathistoryplus)
ashita_sdk_set_compiler_defaults(chathistoryplus)
ashita_sdk_set_linker_defaults(chathistoryplus)
ashita_sdk_set_compiler_warn_level(chathistoryplus 3)

# Legacy Direct3D8 import libraries are not Safe-SEH compatible.

# Emit a linker map for crash diagnostics.
target_link_options(chathistoryplus PRIVATE "/MAP" "/MAPINFO:EXPORTS")
