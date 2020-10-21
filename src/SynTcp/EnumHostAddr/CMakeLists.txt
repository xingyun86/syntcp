# CMakeList.txt : CMake project for SynTcp, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

set(project_name "EnumHostAddr")
project(${project_name})

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/vendor/include
)

file(GLOB SRCS "*.cpp" "*.c")
# Add source to this project's executable.
add_executable (${project_name} ${SRCS})

# TODO: Add tests and install targets if needed.
