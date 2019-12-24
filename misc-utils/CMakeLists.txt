cmake_minimum_required(VERSION 3.1)


project(blkid)

#set(EXECUTABLE_OUTPUT_PATH bin${CMAKE_BUILD_TYPE})
#file(GLOB_RECURSE lib_src src/*.c src/*.h)
list(APPEND blkid_src ${CMAKE_SOURCE_DIR}/misc-utils/blkid.c)


add_executable(blkid ${blkid_src})

set_property(TARGET blkid PROPERTY VS_PLATFORM_TOOLSET_OVERRIDE "v140_clang_c2")

target_include_directories(blkid PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/libblkid/src
	${CMAKE_SOURCE_DIR}/../posix4msvc/include
	${CMAKE_SOURCE_DIR}/../posix4msvc/include/bsd
	${CMAKE_SOURCE_DIR}/../posix4msvc/include/sys/arch
)
target_link_libraries(blkid libblkid)



