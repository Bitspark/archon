# A consumer that knows nothing but the installed package.
#
# Deliberately NOT part of core/cpp's build: it calls find_package(archon), so it exercises
# the exported targets, the include paths and — critically — whether BOTH dependencies reach
# a consumer transitively. A core that builds in its own tree and leaves libsodium out of its
# package config passes every conformance case and fails here.
cmake_minimum_required(VERSION 3.20)
project(archon_consumer LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(archon REQUIRED)
add_executable(consumer consumer.cpp)
target_link_libraries(consumer PRIVATE archon::core)
