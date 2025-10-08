cmake_minimum_required(VERSION 3.15)
project(CryptoLib VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(cryptolib
    src/utils.cpp
    src/bigint_utils.cpp
    src/random_utils.cpp
    src/prime_utils.cpp
    src/hash_utils.cpp
    src/oaep.cpp
    src/rsa.cpp
)

target_include_directories(cryptolib PUBLIC include)

if (WIN32)
    target_link_libraries(cryptolib PRIVATE bcrypt)
endif()
add_executable(example_encrypt examples/encrypt_file.cpp)
target_link_libraries(example_encrypt PRIVATE cryptolib)

add_executable(rsa_demo examples/rsa_demo.cpp)
target_link_libraries(rsa_demo PRIVATE cryptolib)

add_executable(test_rsa tests/test_rsa.cpp)
target_link_libraries(test_rsa PRIVATE cryptolib)

add_executable(benchmark_rsa tests/benchmark_rsa.cpp)
target_link_libraries(benchmark_rsa PRIVATE cryptolib)

add_executable(test_signature tests/test_signature.cpp)
target_link_libraries(test_signature PRIVATE cryptolib)

add_executable(cli_tool tests/cli_tool.cpp)
target_link_libraries(cli_tool PRIVATE cryptolib)