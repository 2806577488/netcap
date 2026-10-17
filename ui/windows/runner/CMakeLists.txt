cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME} WIN32
  "flutter_window.cpp"
  "main.cpp"
  "utils.cpp"
  "win32_window.cpp"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  "Runner.rc"
  "runner.exe.manifest"
)

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})

# Add preprocessor definitions for the build version.
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

# Disable Windows macros that collide with C++ standard library functions.
target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX")

# Add dependency libraries and include directories. Add any application-specific
# dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter flutter_wrapper_app)
target_link_libraries(${BINARY_NAME} PRIVATE "dwmapi.lib")
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")

# Run the Flutter tool portions of the build. This must not be removed.
add_dependencies(${BINARY_NAME} flutter_assemble)

# Bundle the C++ capture tool next to the UI executable so the built
# application is self-contained and finds its back end without any
# configuration. The tool is produced by the repository-level CMake project
# (build/netcap.exe); if it is missing the UI still builds and reports the
# problem at run time.
set(NETCAP_EXE "${CMAKE_CURRENT_SOURCE_DIR}/../../../build/netcap.exe")
if(EXISTS "${NETCAP_EXE}")
  add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${NETCAP_EXE}" "$<TARGET_FILE_DIR:${BINARY_NAME}>/netcap.exe"
    COMMENT "Bundling netcap.exe next to the application")
else()
  message(WARNING
    "netcap.exe was not found at ${NETCAP_EXE}; "
    "build the C++ tool first: cmake --build build")
endif()

# Bundle the built-in filter list too: the UI starts the proxy with it when the
# user has not picked a list of their own (rules/adblock.txt = EasyList +
# EasyPrivacy plus a few local rules; its header carries the attribution).
set(NETCAP_RULES "${CMAKE_CURRENT_SOURCE_DIR}/../../../rules")
if(EXISTS "${NETCAP_RULES}/adblock.txt")
  add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${BINARY_NAME}>/rules"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${NETCAP_RULES}/adblock.txt"
            "$<TARGET_FILE_DIR:${BINARY_NAME}>/rules/adblock.txt"
    COMMENT "Bundling the built-in filter list next to the application")
else()
  message(WARNING
    "the built-in filter list was not found at ${NETCAP_RULES}/adblock.txt; "
    "the UI will ask for a rules file instead")
endif()

# Bundle Wintun as well: `--tun` / `--tun-takeover` needs wintun.dll next to the
# executable (it looks three levels up from its own directory, which does not
# reach third_party/ from a packaged Release folder).
set(NETCAP_WINTUN "${CMAKE_CURRENT_SOURCE_DIR}/../../../third_party/wintun")
if(EXISTS "${NETCAP_WINTUN}/wintun.dll")
  add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${NETCAP_WINTUN}/wintun.dll" "$<TARGET_FILE_DIR:${BINARY_NAME}>/wintun.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${NETCAP_WINTUN}/LICENSE.txt" "$<TARGET_FILE_DIR:${BINARY_NAME}>/wintun-LICENSE.txt"
    COMMENT "Bundling wintun.dll next to the application")
else()
  message(WARNING
    "wintun.dll was not found at ${NETCAP_WINTUN}/wintun.dll; "
    "the TUN takeover switches will report that it is missing")
endif()
