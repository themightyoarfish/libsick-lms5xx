cmake_minimum_required(VERSION 3.15)
project(sick-lms5xx VERSION 0.1.0 LANGUAGES C CXX)
set(PROJECT_NAME_UPPER SickLMS5xx)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Eigen3 3.3.4 REQUIRED)
set(SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parsing.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sopas.cpp
    )
set(HDRS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/parsing.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/network.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/util.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/sopas.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/config.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/types.hpp)

set(LIBS Eigen3::Eigen)

if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
    list(APPEND LIBS Threads::Threads)
endif()

option(WITH_PCL "Enable PCL support" ON)

if(WITH_PCL)
    find_package(PCL 1.10 REQUIRED COMPONENTS common io)
    list(APPEND SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/pcl.cpp)
    list(APPEND HDRS ${CMAKE_CURRENT_SOURCE_DIR}/include/sick-lms5xx/pcl.hpp)
    list(APPEND LIBS ${PCL_LIBRARIES})
endif()

option(BUILD_EXAMPLE "Build example code" ON)
if(BUILD_EXAMPLE)
    add_executable(example ${CMAKE_CURRENT_SOURCE_DIR}/src/example.cpp)
    target_include_directories(example PRIVATE SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_sources(example PRIVATE ${SRCS})
    target_link_libraries(example PRIVATE ${LIBS})
    target_link_directories(example PRIVATE ${PCL_LIBRARY_DIRS})
    if (WITH_PCL)
        target_include_directories(example PRIVATE ${PCL_INCLUDE_DIRS})
        target_compile_definitions(example PRIVATE ${PCL_DEFINITIONS})
        target_compile_definitions(example PRIVATE WITH_PCL)
    endif()
endif()

add_library(${PROJECT_NAME} SHARED ${SRCS})
add_library(${PROJECT_NAME_UPPER}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME}
    PUBLIC
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        ${EIGEN3_INCLUDE_DIRS}
)
if (WITH_PCL)
    target_include_directories(${PROJECT_NAME} PUBLIC ${PCL_INCLUDE_DIRS})
    target_compile_definitions(${PROJECT_NAME} PRIVATE ${PCL_DEFINITIONS} WITH_PCL)
    target_link_directories(${PROJECT_NAME} PUBLIC ${PCL_LIBRARY_DIRS})
endif()

# make eigen, pcl an threads transitive dependencies of dependent projects
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBS})

# Define rpath options to make library relocatable.
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_SKIP_BUILD_RPATH OFF)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
# Highest prio: Find libraries in same dir as where this is installed to.
if(OSX)
  set(MACOSX_RPATH ON)
  set(CMAKE_INSTALL_RPATH "@executable_path")
else()
  set(CMAKE_INSTALL_RPATH "$ORIGIN")
endif()
message(STATUS "CMAKE_INSTALL_RPATH=${CMAKE_INSTALL_RPATH}")
message(STATUS "CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}")

include(GNUInstallDirs)

# install cmake config script to lib/cmake/SickLMS5xx/...
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME_UPPER})

# configure install of the library and associate it with an export name
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# use uppercased name for the library's export name (whatever that is)
# This means you use this in dependent projects like this:
# `target_link_libraries(mytarget PUBLIC SickLMS5xx::SickLMS5xx)`
set_target_properties(${PROJECT_NAME} PROPERTIES EXPORT_NAME ${PROJECT_NAME_UPPER})

# install the header files
install(FILES ${HDRS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sick-lms5xx)

# install the export file for the exported targets. Prepend SickLMS5xx:: to the target
install(EXPORT ${PROJECT_NAME}-targets
  FILE
  ${PROJECT_NAME_UPPER}Targets.cmake
  NAMESPACE
    ${PROJECT_NAME_UPPER}::
  DESTINATION
    ${INSTALL_CONFIGDIR}
)

# make the version selection script
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME_UPPER}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

set(INCLUDE_INSTALL_DIR include/)
configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/cmake/${PROJECT_NAME_UPPER}Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME_UPPER}Config.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
    PATH_VARS INCLUDE_INSTALL_DIR
)

# install the cmake config and config version scripts
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME_UPPER}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME_UPPER}ConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

# export the export so this project can be used with add_subdirectory()
export(EXPORT ${PROJECT_NAME}-targets FILE
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME_UPPER}Targets.cmake NAMESPACE
    ${PROJECT_NAME_UPPER}::)

# add an uninstall target
# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake)
endif()

# `make package` creates a simple binary release with include/ and lib/
include(CPack)
