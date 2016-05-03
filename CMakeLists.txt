cmake_minimum_required(VERSION 3.1)


project(util-linux)

set(EXECUTABLE_OUTPUT_PATH bin/${CMAKE_BUILD_TYPE})

# force Unicode over Multi-byte
#if(COMPILER_MSVC)
#    add_definitions(-DUNICODE -D_UNICODE)
#endif()

#add_definitions(-D__STDC__=0 -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS -DHAVE_SYS_STAT_H -DHAVE_ERRNO_H -DHAVE_UNISTD_H)
add_definitions(
-D__STDC__=1 
-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS 
-DHAVE_SYS_STAT_H 
-DHAVE_ERRNO_H 
-DHAVE_UNISTD_H  
-DHAVE_LSEEK64 -DHAVE_LSEEK64_PROTOTYPE
-DHAVE_USLEEP
-DBLKGETSIZE64)

add_subdirectory(posix4msvc)
add_subdirectory(libblkid)
