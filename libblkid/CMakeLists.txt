cmake_minimum_required(VERSION 3.1)

#Configuration du projet
project(libblkid)

#set(EXECUTABLE_OUTPUT_PATH bin${CMAKE_BUILD_TYPE})

#Génération de la liste des fichiers sources
file(GLOB_RECURSE lib_src src/*.c src/*.h)

list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/blkdev.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/md5.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/crc32.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/sysfs.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/fileutils.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/ismounted.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/canonicalize.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/ttyutils.c)
list(APPEND lib_src ${CMAKE_SOURCE_DIR}/lib/strutils.c)

list(REMOVE_ITEM lib_src 
${CMAKE_CURRENT_SOURCE_DIR}/src/topology/dm.c
${CMAKE_CURRENT_SOURCE_DIR}/src/topology/evms.c
${CMAKE_CURRENT_SOURCE_DIR}/src/topology/ioctl.c
${CMAKE_CURRENT_SOURCE_DIR}/src/topology/lvm.c
${CMAKE_CURRENT_SOURCE_DIR}/src/topology/md.c
#${CMAKE_CURRENT_SOURCE_DIR}/src/topology/sysfs_test.c
)

file(GLOB samples_mkfs samples/mkfs.c )
file(GLOB samples_partitions samples/partitions.c )
file(GLOB samples_superblocks samples/superblocks.c )
file(GLOB samples_topology samples/topology.c )
#MESSAGE( STATUS "lib_src:         " ${lib_src} )


add_library(libblkid ${lib_src})
target_include_directories(libblkid PUBLIC
    src
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/../posix4msvc/include 
)
target_link_libraries(libblkid posix4msvc)

project(samples_mkfs)
add_executable(samples_mkfs ${samples_mkfs})
set_property(TARGET samples_mkfs PROPERTY VS_PLATFORM_TOOLSET_OVERRIDE "v140_clang_c2")
target_include_directories(samples_mkfs PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/libblkid/src
	${CMAKE_SOURCE_DIR}/../posix4msvc/include
)
target_link_libraries(samples_mkfs libblkid)

project(samples_partitions)
add_executable(samples_partitions ${samples_partitions})
set_property(TARGET samples_partitions PROPERTY VS_PLATFORM_TOOLSET_OVERRIDE "v140_clang_c2")
target_include_directories(samples_mkfs PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/libblkid/src
	${CMAKE_SOURCE_DIR}/../posix4msvc/include
)
target_link_libraries(samples_partitions libblkid)

project(samples_superblocks)
add_executable(samples_superblocks ${samples_superblocks})
set_property(TARGET samples_superblocks PROPERTY VS_PLATFORM_TOOLSET_OVERRIDE "v140_clang_c2")
target_include_directories(samples_mkfs PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/libblkid/src
	${CMAKE_SOURCE_DIR}/../posix4msvc/include
)
target_link_libraries(samples_superblocks libblkid)

project(samples_topology)
add_executable(samples_topology ${samples_topology})
set_property(TARGET samples_topology PROPERTY VS_PLATFORM_TOOLSET_OVERRIDE "v140_clang_c2")
target_include_directories(samples_mkfs PUBLIC
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/libblkid/src
	${CMAKE_SOURCE_DIR}/../posix4msvc/include
)
target_link_libraries(samples_topology libblkid)


