cmake_minimum_required(VERSION 3.15)
project(bruteforce-core VERSION 1.0 LANGUAGES CXX)

# C++17 obrigatório
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Biblioteca estática
add_library(bruteforce_core STATIC
    src/bruteforce.cpp
)

# Pasta de headers públicos
target_include_directories(bruteforce_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Otimizações
target_compile_options(bruteforce_core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/O2>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-O3>
)

# Test executable
add_executable(test_bruteforce tests/test_main.cpp)
target_link_libraries(test_bruteforce PRIVATE bruteforce_core)
