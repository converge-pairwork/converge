cmake_minimum_required(VERSION 3.28)

# One authoritative version for the whole installed CONVERGE skill (the SKILL.md, the live
# renderer and this bridge, which is what actually executes). VERSION at the repository root is
# the only place it is written; scripts/skill-package.sh stamps the same string into the packaged
# SKILL.md and the update manifest, and scripts/version-check.sh refuses a mismatch.
# In the repository VERSION sits at the root, one level up. The published source tarball carries
# a copy beside this file, so a build from source states the same version as the binary release.
find_file(CONVERGE_VERSION_FILE NAMES VERSION
          PATHS "${CMAKE_CURRENT_SOURCE_DIR}/.." "${CMAKE_CURRENT_SOURCE_DIR}"
          NO_DEFAULT_PATH REQUIRED)
file(READ "${CONVERGE_VERSION_FILE}" CONVERGE_VERSION)
string(STRIP "${CONVERGE_VERSION}" CONVERGE_VERSION)
if(NOT CONVERGE_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
  message(FATAL_ERROR "VERSION must be MAJOR.MINOR.PATCH, got '${CONVERGE_VERSION}'")
endif()
project(converge-bridge LANGUAGES C CXX VERSION ${CONVERGE_VERSION})

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Warnings, in each compiler's own spelling. MSVC does not merely ignore GCC's flags, it
# refuses the whole command line when it is handed one, so a single unconditional -Wextra is
# the difference between a Windows build and no Windows build at all.
if(MSVC)
  set(CONVERGE_WARNINGS /W4 /permissive-)
  # Boost.Beast and Boost.Asio instantiate enough templates in relay_client.cpp to pass the COFF
  # limit on how many sections an object file may hold. /bigobj raises that limit and changes
  # nothing about the code that comes out. Directory wide, because which translation unit
  # crosses the line is a property of the headers, not of the file that included them.
  add_compile_options(/bigobj)
else()
  set(CONVERGE_WARNINGS -Wall -Wextra -Wpedantic)
endif()

# The published executables depend on nothing but the operating system: OpenSSL is linked as
# archives everywhere, and on Linux the whole binary is static (built against musl, so there is
# no glibc floor either). scripts/check-static.sh is the proof the release runs on the result.
option(CONVERGE_BRIDGE_FULLY_STATIC "One self contained executable: static OpenSSL, and on Linux -static" OFF)
if(CONVERGE_BRIDGE_FULLY_STATIC)
  set(OPENSSL_USE_STATIC_LIBS ON)
endif()

find_package(Boost 1.81 REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)
find_package(Threads REQUIRED)

add_executable(converge-bridge
  src/main.cpp src/tools.cpp src/fetch.cpp src/crypto.cpp src/identity.cpp src/relay_client.cpp src/mcp.cpp src/mcp_session.cpp src/session_ux.cpp src/json_src.cpp
  ../proto/portable/nacl.c)
target_include_directories(converge-bridge PRIVATE ../proto)
target_compile_options(converge-bridge PRIVATE ${CONVERGE_WARNINGS})
target_compile_definitions(converge-bridge PRIVATE BOOST_ASIO_NO_DEPRECATED CONVERGE_VERSION="${CONVERGE_VERSION}")
target_link_libraries(converge-bridge PRIVATE Boost::headers OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Windows keeps the security descriptor APIs that make CONVERGE's private state private
# (platform.hpp restrict_to_owner) in advapi32, and the sockets Boost.Asio uses in ws2_32.
if(WIN32)
  target_link_libraries(converge-bridge PRIVATE advapi32 ws2_32)
  target_compile_definitions(converge-bridge PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()


option(CONVERGE_BRIDGE_STATIC "Link libstdc++/libgcc statically for easy distribution" OFF)
if(CONVERGE_BRIDGE_STATIC)
  target_link_options(converge-bridge PRIVATE -static-libstdc++ -static-libgcc)
endif()
if(CONVERGE_BRIDGE_FULLY_STATIC)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_options(converge-bridge PRIVATE -static -s)   # -s: no symbol table, a third of the size
  elseif(MSVC)
    set_property(TARGET converge-bridge PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  endif()
endif()

install(TARGETS converge-bridge RUNTIME DESTINATION bin)

enable_testing()
add_executable(bridge_tests tests/test_crypto.cpp src/crypto.cpp src/identity.cpp)
target_include_directories(bridge_tests PRIVATE src)
target_link_libraries(bridge_tests PRIVATE OpenSSL::Crypto)
# The TweetNaCl reference is C as published; its style is not this project's, and its
# warnings are not findings.
set_source_files_properties(../proto/portable/nacl.c PROPERTIES COMPILE_OPTIONS "-w")

add_test(NAME crypto COMMAND bridge_tests)

# The link protocol (../proto): messages, handshake, sealed stream, certificates. Header only, so
# this is its whole build; the relay includes the same headers from the client release.
add_executable(proto_tests ../proto/tests/test_proto.cpp ../proto/portable/nacl.c)
target_include_directories(proto_tests PRIVATE ../proto)
target_compile_options(proto_tests PRIVATE ${CONVERGE_WARNINGS})
target_link_libraries(proto_tests PRIVATE OpenSSL::Crypto)
add_test(NAME proto COMMAND proto_tests)

# Where private state goes on this platform, and whether what is created there is private on
# it. Runs everywhere; on Windows it is the only proof that the owner-only ACL is really applied.
add_executable(platform_tests tests/test_platform.cpp)
target_include_directories(platform_tests PRIVATE src)
target_compile_options(platform_tests PRIVATE ${CONVERGE_WARNINGS})
if(WIN32)
  target_link_libraries(platform_tests PRIVATE advapi32)
  target_compile_definitions(platform_tests PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
add_test(NAME platform COMMAND platform_tests)

# The in-session interaction contract (banner, framed remote messages, modes, stop conditions).
add_executable(session_ux_tests tests/test_session_ux.cpp src/session_ux.cpp src/json_src.cpp)
target_include_directories(session_ux_tests PRIVATE src)
target_compile_options(session_ux_tests PRIVATE ${CONVERGE_WARNINGS})
target_compile_definitions(session_ux_tests PRIVATE CONVERGE_VERSION="${CONVERGE_VERSION}")
target_link_libraries(session_ux_tests PRIVATE Boost::headers)
add_test(NAME session_ux COMMAND session_ux_tests)
