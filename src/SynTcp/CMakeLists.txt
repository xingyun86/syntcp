﻿# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("SynTcp")

# Include sub-projects.
add_subdirectory ("SynTcp")
add_subdirectory ("UdpClient")
add_subdirectory ("UdpServer")
add_subdirectory ("EnumHostAddr")
