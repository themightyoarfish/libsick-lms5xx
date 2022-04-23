project(lms C CXX)
cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Eigen3 3.3.9 REQUIRED)
set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/example.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/parsing.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/util.cpp
    )
add_executable(run-lms)
target_link_libraries(run-lms Eigen3::Eigen)

if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    target_link_libraries(run-lms Threads::Threads)
endif()

target_include_directories(run-lms PRIVATE ${PCL_INCLUDE_DIRS})
target_include_directories(run-lms PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
option(WITH_PCL "Enable PCL support" OFF)
if (WITH_PCL)
    target_compile_definitions(run-lms PRIVATE WITH_PCL)
    find_package(PCL REQUIRED)
    target_link_libraries(run-lms ${PCL_LIBRARIES})
    add_definitions(${PCL_DEFINITIONS})
    list(APPEND SRCS ${CMAKE_CURRENT_SOURCE_DIR}/pcl.cpp)
endif()
target_sources(run-lms PRIVATE ${SRCS})
