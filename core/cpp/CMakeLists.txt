# archon core, C++.
#
# TWO crypto libraries, and the split is the point:
#
#   OpenSSL >= 3.2  signs.  archon's domain separation is Ed25519ph with the domain as the
#                   RFC 8032 context string, reached through the signature-operation
#                   parameters OSSL_SIGNATURE_PARAM_INSTANCE and CONTEXT_STRING. 3.2 is the
#                   floor because those parameters are how a context reaches Ed25519ph at
#                   all; BoringSSL's public API is raw Ed25519 only and does not qualify.
#
#   libsodium       decides what is acceptable.  OpenSSL validates NO points for Ed25519 --
#   >= 1.0.21       EVP_PKEY_public_check accepts all eight ADR 0008 classes -- and exposes
#                   no scalar multiplication for the curve, so the profile cannot be written
#                   against it. crypto_core_ed25519_is_valid_point is that predicate exactly.
#
# The libsodium floor is ASSERTED here rather than documented, because the failure it
# prevents is silent. In 1.0.20 and earlier that function accepted points in mixed-order
# subgroups: measured, it accepts profile-mixed-order-A-torsion-2-k-divisible (a point of
# order 2L) while refusing the 8L and 4L ones. A core built against 1.0.20 compiles, links,
# signs correctly and passes 104 of the oracle's 105 cases. It
# is also not a hypothetical: a machine whose package database predates 2026 offers 1.0.20,
# and `pacman -S mingw-w64-x86_64-libsodium` installs it without comment.

cmake_minimum_required(VERSION 3.20)
project(archon_core LANGUAGES CXX VERSION 0.8.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 3.2 REQUIRED)

# pkg-config carries libsodium's version, so the floor is a build failure rather than a
# runtime surprise. REQUIRED plus the version predicate means configure stops here.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.21)
message(STATUS "archon: libsodium ${SODIUM_VERSION} (>= 1.0.21 required for the ADR 0008 point predicate)")

add_library(archon_core src/core.cpp)
add_library(archon::core ALIAS archon_core)

# The alias above exists only in THIS build tree. Without EXPORT_NAME the installed package
# would offer archon::archon_core, so a consumer following the documented archon::core would
# fail to configure with "an ALIAS target is missing" — which is precisely how the consumer
# check below found this, on its first run against an installed package.
set_target_properties(archon_core PROPERTIES EXPORT_NAME core)

target_include_directories(archon_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)

target_link_libraries(archon_core PUBLIC OpenSSL::Crypto PkgConfig::SODIUM)

# The conformance CLI is a dev artifact and never part of the installed package, the same way
# the Java core's CLI is test-scoped: a consumer who resolves archon must not receive it.
option(ARCHON_BUILD_CONFORMANCE "Build the conformance CLI" ON)
if(ARCHON_BUILD_CONFORMANCE)
  add_executable(archon_conformance conformance/cli.cpp)
  target_link_libraries(archon_conformance PRIVATE archon_core)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS archon_core EXPORT archon-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/archon DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT archon-targets FILE archon-targets.cmake NAMESPACE archon::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/archon)

# A consumer of the installed package must inherit BOTH dependencies, including the version
# floor: finding archon without libsodium >= 1.0.21 would relocate the silent failure from
# our build to theirs.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/archon-config.cmake.in" [=[
@PACKAGE_INIT@
include(CMakeFindDependencyMacro)
find_dependency(OpenSSL 3.2)
find_dependency(PkgConfig)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.21)
include("${CMAKE_CURRENT_LIST_DIR}/archon-targets.cmake")
check_required_components(archon)
]=])
configure_package_config_file(
  "${CMAKE_CURRENT_BINARY_DIR}/archon-config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/archon-config.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/archon)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/archon-config-version.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMinorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/archon-config.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/archon-config-version.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/archon)
