﻿# CMakeList.txt : CMake project for SynTcp, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(project_name "SynTcp")
project(${project_name})

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/vendor/include
)

if(MSVC)
set(MSVC_LIBS ws2_32)
else(MSVC)
set(MSVC_LIBS pthread)
endif(MSVC)

file(GLOB SRCS "*.c" "*.cpp")
# Add source to this project's executable.
add_executable (${project_name} ${SRCS})

target_link_libraries(${project_name}
PRIVATE ${MSVC_LIBS}
)
# TODO: Add tests and install targets if needed.
