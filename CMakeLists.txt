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

find_program(CLANG_EXECUTABLE clang REQUIRED) #让 CMake 去系统里找 clang

# 架构判断，方便移植到ARM64
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(BPF_TARGET_ARCH x86)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BPF_TARGET_ARCH arm64)
else()
    message(FATAL_ERROR
        "Unsupported architecture for eBPF build: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(SYSCALL_BPF_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/syscall.bpf.c
)

set(SYSCALL_BPF_OBJECT
    ${CMAKE_CURRENT_BINARY_DIR}/syscall.bpf.o
)

set(CPU_BPF_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/bpf/cpu.bpf.c
)

set(CPU_BPF_OBJECT
    ${CMAKE_CURRENT_BINARY_DIR}/cpu.bpf.o
)

add_custom_command(
    OUTPUT
        ${SYSCALL_BPF_OBJECT}

    COMMAND
        ${CLANG_EXECUTABLE}
        -g
        -O2
        -target bpf
        -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}/bpf/include
        -I${CMAKE_CURRENT_SOURCE_DIR}/include
        -c ${SYSCALL_BPF_SOURCE}
        -o ${SYSCALL_BPF_OBJECT}

    DEPENDS
        ${SYSCALL_BPF_SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/event.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/bpf_common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/vmlinux.h

    VERBATIM
)

add_custom_target(
    syscall_bpf
    ALL
    DEPENDS ${SYSCALL_BPF_OBJECT}
)

add_custom_command(
    OUTPUT
        ${CPU_BPF_OBJECT}

    COMMAND
        ${CLANG_EXECUTABLE}
        -g
        -O2
        -target bpf
        -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}/bpf/include
        -I${CMAKE_CURRENT_SOURCE_DIR}/include
        -c ${CPU_BPF_SOURCE}
        -o ${CPU_BPF_OBJECT}

    DEPENDS
        ${CPU_BPF_SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/event.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/bpf_common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/vmlinux.h

    VERBATIM
)

add_custom_target(
    cpu_bpf
    ALL
    DEPENDS ${CPU_BPF_OBJECT}
)

add_executable(
    kylinrca_loader
    src/bpf_loader.cpp
    src/event_queue.cpp
    src/ring_buffer_consumer.cpp
    src/syscall_analyzer.cpp
    src/json_reporter.cpp
) #让cmake创造一个叫kylinrca_loader的程序，源码是src/bpf_loader.cpp,src/event_queue.cpp

add_dependencies(
    kylinrca_loader
    syscall_bpf
) # 想构建 kylinrca_loader，必须先把 syscall_bpf 构建出来。

target_include_directories(
	kylinrca_loader
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include) # 告诉includecmake去哪儿找头文件

target_link_libraries(
	kylinrca_loader 
	PRIVATE 
	PkgConfig::LIBBPF)#给叫kylinrca_loader的程序链接PkgConfig::LIBBPF库

add_executable(
    kylinrca_syscall_analyzer_smoke
    tests/syscall_analyzer_smoke.cpp
    src/syscall_analyzer.cpp
)

target_include_directories(
    kylinrca_syscall_analyzer_smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(
    kylinrca_json_reporter_smoke
    tests/json_reporter_smoke.cpp
    src/syscall_analyzer.cpp
    src/json_reporter.cpp
)

target_include_directories(
    kylinrca_json_reporter_smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(
    kylinrca_cpu_probe_smoke
    tests/cpu_probe_test.cpp
)

target_include_directories(
    kylinrca_cpu_probe_smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    kylinrca_cpu_probe_smoke
    PRIVATE
    PkgConfig::LIBBPF
)

add_dependencies(
    kylinrca_cpu_probe_smoke
    cpu_bpf
)
