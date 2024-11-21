cmake_minimum_required(VERSION 3.4)
project(CXPROJECT C CXX)
find_package(LLVM REQUIRED CONFIG)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})

option(ENABLE_DEBUG "Enable debug mode" OFF)

add_executable(afl-clang ./afl-clang.c)
target_include_directories(afl-clang PRIVATE ./lib)

add_executable(afl-clang++ ./afl-clang.c)
target_include_directories(afl-clang++ PRIVATE ./lib)

add_library(afl-runtime OBJECT ./afl-runtime.cc)
target_compile_options(afl-runtime PRIVATE -O3)
target_include_directories(afl-runtime PRIVATE ./lib)
set_target_properties(afl-runtime PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(afl-fuzz ./afl-fuzz.c)
# target_compile_options(afl-fuzz PRIVATE -g)
target_compile_options(afl-fuzz PRIVATE -g -O3 -funroll-loops)
message(STATUS "ENABLE_DEBUG is set to: ${ENABLE_DEBUG}")
if(ENABLE_DEBUG)
    target_compile_options(afl-fuzz PRIVATE -g)
else()
    target_compile_options(afl-fuzz PRIVATE -O3 -funroll-loops)
endif()
target_include_directories(afl-fuzz PRIVATE ./lib)
target_link_libraries(afl-fuzz PRIVATE $<TARGET_OBJECTS:afl-runtime>)
target_link_libraries(afl-fuzz PRIVATE dl m stdc++ boost_program_options boost_graph jsoncpp)

add_library(afl-pass MODULE ./afl-pass.cc)
set_target_properties(afl-pass PROPERTIES COMPILE_FLAGS "-fno-rtti" PREFIX "")
target_link_libraries(afl-pass PRIVATE jsoncpp)

add_library(afl-llvm-rt OBJECT ./afl-llvm-rt.o.c)
set_target_properties(afl-llvm-rt PROPERTIES POSITION_INDEPENDENT_CODE ON)






