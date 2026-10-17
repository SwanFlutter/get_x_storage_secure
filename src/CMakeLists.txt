# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(get_x_storage_secure_library VERSION 0.0.1 LANGUAGES C)

add_library(get_x_storage_secure SHARED
  "get_x_storage_secure.c"
)

set_target_properties(get_x_storage_secure PROPERTIES
  PUBLIC_HEADER get_x_storage_secure.h
  OUTPUT_NAME "get_x_storage_secure"
)

target_compile_definitions(get_x_storage_secure PUBLIC DART_SHARED_LIB)

if (ANDROID)
  # Support Android 15 16k page size
  target_link_options(get_x_storage_secure PRIVATE "-Wl,-z,max-page-size=16384")
endif()
