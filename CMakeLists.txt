project(lms C CXX)
cmake_minimum_required(VERSION 3.22)
set(CMAKE_CXX_STANDARD 14)

find_package(Eigen3 3.3.9 REQUIRED)
add_executable(run-lms ${CMAKE_CURRENT_SOURCE_DIR}/sick.cpp)
target_link_libraries(run-lms Eigen3::Eigen)
