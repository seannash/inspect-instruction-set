cmake_minimum_required(VERSION 3.15)
project(inspect-instruction-set)

include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)

set(CMAKE_CXX_STANDARD 23)
set (CMAKE_CXX_STANDARD_REQUIRED ON)



find_package(capstone CONFIG REQUIRED)
find_package(Boost 1.82.0 COMPONENTS program_options REQUIRED)
find_package(elfio REQUIRED)

add_executable(${PROJECT_NAME} src/frontend.cc)
target_link_libraries(${PROJECT_NAME} 
    Boost::program_options
    capstone::capstone
    elfio::elfio
)

