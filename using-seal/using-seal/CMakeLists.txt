cmake_minimum_required(VERSION 3.12)

project (using-seal)

set(CMAKE_CXX_STANDARD 17)

add_executable(using-seal "src/using-seal.cpp" "include/distancecomputer.h" "include/paramsrunner.h" "src/params.cpp" "include/params.h")

target_link_libraries(using-seal C:/Users/yiwai/Documents/SEAL/lib/x64/Release/seal.lib)
target_include_directories(using-seal PRIVATE C:/Users/yiwai/Documents/SEAL/native/src PRIVATE C:/Users/yiwai/Documents/SEAL/native/examples)