cmake_minimum_required(VERSION 3.16)
project(netcap LANGUAGES CXX)

# ---------------------------------------------------------------------------
# netcap: dependency-free low-level network traffic capture toolkit.
# Only a C++20 compiler and the platform sockets API are required - libpcap is
# deliberately not used, the savefile format and the dissectors are local.
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(NETCAP_SOURCES
  src/common.cpp
  src/packet.cpp
  src/dissect.cpp
  src/app.cpp
  src/filter.cpp
  src/pcap.cpp
  src/crypto.cpp
  src/p256.cpp
  src/p521.cpp
  src/cosmetic.cpp
  src/x509.cpp
  src/rsa.cpp
  src/x25519.cpp
  src/tls13.cpp
  src/tls12.cpp
  src/flow.cpp
  src/http.cpp
  src/tls.cpp
  src/http2.cpp
  src/httpframe.cpp
  src/origin.cpp
  src/picker.cpp
  src/analyze.cpp
  src/capture.cpp
  src/proc.cpp
  src/proxy.cpp
  src/rules.cpp
  src/blocker.cpp
  src/regex.cpp
  src/rewrite.cpp
  src/brotli.cpp
  src/brotli_dictionary.cpp
  src/brotli_encode.cpp
  src/quic.cpp
  src/h3.cpp
  src/h3_write.cpp
  src/quickeys.cpp
  src/quic_rewrite.cpp
  src/hosts.cpp
  src/dnssink.cpp
  src/wfp.cpp
  src/wfp_win.cpp
  src/sysproxy.cpp
  src/sysenv.cpp
  src/tun.cpp
  src/pktflow.cpp
  src/tunrelay.cpp
  src/tunpipe.cpp
  src/split.cpp
  src/block.cpp
  src/block_win.cpp
  src/selftest.cpp
  src/main.cpp
)

# One capture backend per platform.
if(WIN32)
  list(APPEND NETCAP_SOURCES src/capture_win.cpp)
else()
  list(APPEND NETCAP_SOURCES src/capture_posix.cpp)
endif()

# One process-attribution backend per platform (proc.cpp holds the portable half).
if(WIN32)
  list(APPEND NETCAP_SOURCES src/proc_win.cpp)
else()
  list(APPEND NETCAP_SOURCES src/proc_stub.cpp)
endif()

# One environment backend per platform (sysenv.cpp holds the portable half): the
# Windows half writes HKCU\Environment and broadcasts WM_SETTINGCHANGE, which is
# how the browser we are going to read QUIC from gets told where to write the
# traffic secrets -- invisibly, and undone when the session ends.
if(WIN32)
  list(APPEND NETCAP_SOURCES src/sysenv_win.cpp)
else()
  list(APPEND NETCAP_SOURCES src/sysenv_stub.cpp)
endif()

add_executable(netcap ${NETCAP_SOURCES})
target_include_directories(netcap PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
  target_compile_options(netcap PRIVATE /W4 /permissive- /utf-8)
else()
  target_compile_options(netcap PRIVATE -Wall -Wextra)
endif()

if(WIN32)
  # ws2_32    : Winsock (raw socket + WSAIoctl/SIO_RCVALL)
  # iphlpapi  : GetAdaptersAddresses / GetBestInterface for device discovery
  # fwpuclnt  : Windows Filtering Platform (FwpmEngineOpen0 / FwpmFilterAdd0)
  # bcrypt    : BCryptGenRandom, used by the P-256 key generator
  # wininet   : InternetSetOption, so a system-proxy takeover is picked up by
  #             running programs without a logoff
  target_compile_definitions(netcap PRIVATE _WIN32_WINNT=0x0601 WIN32_LEAN_AND_MEAN)
  target_link_libraries(netcap PRIVATE ws2_32 iphlpapi fwpuclnt bcrypt wininet)
  if(MINGW)
    # Without this the exe needs libstdc++-6.dll / libgcc_s_seh-1.dll /
    # libwinpthread-1.dll next to it: on a machine without the MinGW toolchain on
    # PATH it fails to start at all (Windows reports 0xC0000139, entry point not
    # found).  The Flutter UI runs netcap.exe as a child process, so link the
    # runtime in and keep the tool a single self-contained file.
    target_link_options(netcap PRIVATE -static -static-libgcc -static-libstdc++)
  endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(netcap PRIVATE)
endif()

enable_testing()
add_test(NAME selftest COMMAND netcap --selftest)

install(TARGETS netcap RUNTIME DESTINATION bin)
