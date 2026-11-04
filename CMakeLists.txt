cmake_minimum_required(VERSION 3.20)
project(SecureAuth LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "This starter project uses the Windows CNG API. Build it on Windows.")
endif()

add_library(auth_core src/auth.cpp)
target_include_directories(auth_core PUBLIC include)
target_link_libraries(auth_core PRIVATE bcrypt)

add_executable(SecureAuth src/main.cpp)
target_link_libraries(SecureAuth PRIVATE auth_core)

add_executable(auth_tests tests/auth_tests.cpp)
target_link_libraries(auth_tests PRIVATE auth_core)

enable_testing()
add_test(NAME AuthTests COMMAND auth_tests)
