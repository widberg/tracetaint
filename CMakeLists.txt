cmake_minimum_required(VERSION 3.14)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "Prevented in-tree built. Please create a build directory outside of the fmtk source code and call cmake from there")
endif()

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif()

if (POLICY CMP0074)
  cmake_policy(SET CMP0074 NEW)
endif()

if (POLICY CMP0091)
	cmake_policy(SET CMP0091 NEW)
endif()

project(tracetaint VERSION 0.0.1 LANGUAGES CXX)

option(X64DBG_DIR "Path to the x64dbg pluginsdk directory." "")

set(CMAKE_CXX_STANDARD 20 CACHE INTERNAL "")
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE INTERNAL "")

add_library(tracetaint SHARED tracetaint.cpp)
target_include_directories(tracetaint PRIVATE "${X64DBG_DIR}")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_link_libraries(tracetaint PRIVATE
        "${X64DBG_DIR}/pluginsdk/x64bridge.lib"
        "${X64DBG_DIR}/pluginsdk/x64dbg.lib"
    )
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dp64" CACHE INTERNAL "")
else()
    target_link_libraries(tracetaint PRIVATE
        "${X64DBG_DIR}/pluginsdk/x32bridge.lib"
        "${X64DBG_DIR}/pluginsdk/x32dbg.lib"
    )
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dp32" CACHE INTERNAL "")
endif()
install(TARGETS tracetaint DESTINATION ".")
