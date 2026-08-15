cmake_minimum_required(VERSION 3.16)

project(KylinRCA
	VERSION 0.1.0
	LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(
	kylinrca_toolchain_smoke
	tests/toolchain_smoke.cpp
)

find_package(PkgConfig REQUIRED) #cMake ,请帮我找到Pkg-config
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf) 
#通过pkg_config 查找系统中的libbpf相关配置，并把它包装成一个cmake可以使用的target PkgConfig::LIBBPF
add_executable(
	kylinrca_loader 
	src/bpf_loader.cpp
	src/event_queue.cpp
	src/ring_buffer_consumer.cpp) #让cmake创造一个叫kylinrca_loader的程序，源码是src/bpf_loader.cpp,src/event_queue.cpp

target_include_directories(
	kylinrca_loader
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include) # 告诉includecmake去哪儿找头文件

target_link_libraries(
	kylinrca_loader 
	PRIVATE 
	PkgConfig::LIBBPF)#给叫kylinrca_loader的程序链接PkgConfig::LIBBPF库
