####################################################################################################
# chathistoryplus - Ashita v4 plugin (32-bit).
#
# Raises how much chat history FFXI keeps, and (optionally) keeps it across sessions.
#
# Configure (from a Windows box, x86 toolset; ASHITA4_SDK_PATH must point at a folder with Ashita.h):
#   cmake -S . -B build -G "Visual Studio 17 2022" -A Win32 -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#
# Output: build/Release/chathistoryplus.dll  ->  copy to Ashita-v4beta-main/plugins/
####################################################################################################
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

# Do NOT enable Safe-SEH -- the legacy Direct3D8 import libs are not /SAFESEH-compatible.

# Emit a linker MAP so a crash address can be turned into a function name instead of a guess.
target_link_options(chathistoryplus PRIVATE "/MAP" "/MAPINFO:EXPORTS")
