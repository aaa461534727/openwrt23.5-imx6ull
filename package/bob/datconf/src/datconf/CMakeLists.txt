cmake_minimum_required(VERSION 2.6)

project(datconf)

OPTION(BUILD_LUA "build Lua binding" ON)

#add_subdirectory(lua)

add_definitions(-Os -Wall -Werror -g3)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../kvcutil)

add_library(datconf libdatconf.c)
set_target_properties(datconf PROPERTIES COMPILE_FLAGS "-fPIC -ffunction-sections -fdata-sections")

add_executable(dconf datconf.c)
target_link_libraries(dconf datconf kvcutil)
set_target_properties(dconf PROPERTIES OUTPUT_NAME datconf)
set_target_properties(dconf PROPERTIES COMPILE_FLAGS "-fPIC -ffunction-sections -fdata-sections")
set_target_properties(dconf PROPERTIES LINK_FLAGS "-Wl,--gc-sections")

install(FILES libdatconf.h
	DESTINATION include
)

install(TARGETS datconf dconf
	ARCHIVE DESTINATION lib
	LIBRARY DESTINATION lib
	RUNTIME DESTINATION bin
)

