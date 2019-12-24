cmake_minimum_required(VERSION 3.1)


project(util-linux)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# force Unicode over Multi-byte
#if(COMPILER_MSVC)
#    add_definitions(-DUNICODE -D_UNICODE)
#endif()

#add_definitions(-D__STDC__=0 -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -DHAVE_SYS_STAT_H -DHAVE_ERRNO_H -DHAVE_UNISTD_H)
#
add_definitions(
-D__STDC__=1 
-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS 
-DPACKAGE_STRING="util-linux 2.28.rc2-21-6460a-dirty"
-DHAVE_STRNLEN
-DHAVE_SYS_STAT_H 
-DHAVE_ERRNO_H 
-DHAVE_UNISTD_H  
-DHAVE_LSEEK64 -DHAVE_LSEEK64_PROTOTYPE
-DHAVE_USLEEP
-DBLKGETSIZE64)

add_subdirectory(windevblk)
add_subdirectory(posix4msvc)
add_subdirectory(libblkid)
add_subdirectory(misc-utils)

 execute_process(COMMAND py -3 ${CMAKE_CURRENT_SOURCE_DIR}/fix-cmake-vs-clang.py RESULT_VARIABLE retcode)

					  