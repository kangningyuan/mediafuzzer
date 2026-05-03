cmake_minimum_required(VERSION 3.14)
project(MediaFuzzerHarness C)

# Find Clang — prefer env CLANG_PATH, then auto-detect
if(DEFINED ENV{CLANG_PATH})
    set(CMAKE_C_COMPILER $ENV{CLANG_PATH})
else()
    # Try common Clang versions
    find_program(CLANG_FOUND NAMES clang-18 clang-16 clang-14 clang)
    if(CLANG_FOUND)
        set(CMAKE_C_COMPILER ${CLANG_FOUND})
    endif()
endif()

message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")

# Fuzzer sanitizer flags (compile LibFuzzer runtime without linking main loop)
set(FUZZER_FLAGS "-fsanitize=fuzzer-no-link")

# Coverage bitmap size — overridable via -DCOV_BITMAP_SIZE=...
if(NOT DEFINED COV_BITMAP_SIZE)
    set(COV_BITMAP_SIZE 65536)
endif()

# Target function name placeholder — overridable via -DTARGET_FUNC=...
if(NOT DEFINED TARGET_FUNC)
    set(TARGET_FUNC "target_func")
endif()

add_library(harness SHARED harness_template.c)
target_compile_options(harness PRIVATE
    ${FUZZER_FLAGS}
    -O2
    -fPIC
    -shared
)
target_compile_definitions(harness PRIVATE
    COV_BITMAP_SIZE=${COV_BITMAP_SIZE}
    TARGET_FUNC=${TARGET_FUNC}
)
