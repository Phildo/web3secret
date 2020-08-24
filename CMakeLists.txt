cmake_minimum_required(VERSION 3.18)
set(CMAKE_FIND_DEBUG_MODE 1)

project(web3_secret
  VERSION 0.0.1
  DESCRIPTION "Testing crypto stuff"
  LANGUAGES C CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(cryptotest test.cpp)
set(botan_DIR "C:/Botan")
target_link_libraries(cryptotest PRIVATE "${botan_DIR}/lib/botan.lib")
target_include_directories(cryptotest PRIVATE "${botan_DIR}/include/botan-2")
