project(lms C CXX)
cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Eigen3 3.3.9 REQUIRED)
set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/example.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parsing.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sopas.cpp
    )
set(LIBS Eigen3::Eigen)
add_executable(run-lms)
target_link_libraries(run-lms Eigen3::Eigen)

if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    list(APPEND LIBS Threads::Threads)
endif()

target_include_directories(run-lms PRIVATE ${PCL_INCLUDE_DIRS})
target_include_directories(run-lms PRIVATE SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/include)
option(WITH_PCL "Enable PCL support" OFF)
if (WITH_PCL)
    target_compile_definitions(run-lms PRIVATE WITH_PCL)
    find_package(PCL REQUIRED)
    add_definitions(${PCL_DEFINITIONS})
    list(APPEND SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/pcl.cpp)
    list(APPEND LIBS ${PCL_LIBRARIES})
endif()
target_sources(run-lms PRIVATE ${SRCS})
target_link_libraries(run-lms ${LIBS})

add_library(sick-lms5xx ${SRCS})
target_include_directories(sick-lms5xx
    PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        ${EIGEN3_INCLUDE_DIRS}
)
if (WITH_PCL)
target_include_directories(sick-lms5xx
    PUBLIC
    ${PCL_DEFINITIONS}
)
target_compile_definitions(sick-lms5xx PUBLIC ${PCL_DEFINITIONS} WITH_PCL)
target_link_libraries(sick-lms5xx PUBLIC ${LIBS})
endif()
