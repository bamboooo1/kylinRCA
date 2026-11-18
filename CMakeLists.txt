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
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cpu_probe_stats.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/cpu_runtime.h
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
    kylinrca_cpu_analyzer_smoke
    tests/cpu_analyzer_smoke.cpp
    src/cpu_analyzer.cpp
)

target_include_directories(
    kylinrca_cpu_analyzer_smoke
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
    src/cpu_analyzer.cpp
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
add_executable(
    kylinrca_cpu_rca_smoke
    tests/cpu_rca_smoke.cpp
    src/cpu_analyzer.cpp
    src/proc_cpu_sampler.cpp
)

target_include_directories(
    kylinrca_cpu_rca_smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    kylinrca_cpu_rca_smoke
    PRIVATE
    PkgConfig::LIBBPF
)

add_dependencies(
    kylinrca_cpu_rca_smoke
    cpu_bpf
)

add_executable(
    kylinrca_proc_cpu_sampler_smoke
    tests/proc_cpu_sampler_smoke.cpp
    src/proc_cpu_sampler.cpp
)

target_include_directories(
    kylinrca_proc_cpu_sampler_smoke
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(
    kylinrca_proc_cpu_sampler_stability
    tests/proc_cpu_sampler_stab.cpp
    src/proc_cpu_sampler.cpp
)

target_include_directories(
    kylinrca_proc_cpu_sampler_stability
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 非特权回归纳入 CTest；真实 BPF/压力测试通过 scripts/check_cpu_pipeline.py 执行。
add_executable(kylinrca_cpu_runtime_smoke
    tests/cpu_runtime_smoke.cpp src/cpu_analyzer.cpp src/proc_cpu_sampler.cpp)
target_include_directories(kylinrca_cpu_runtime_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(kylinrca_cpu_runtime_smoke PRIVATE PkgConfig::LIBBPF)
enable_testing()
add_test(NAME syscall_analyzer COMMAND kylinrca_syscall_analyzer_smoke)
add_test(NAME cpu_analyzer COMMAND kylinrca_cpu_analyzer_smoke)
add_test(NAME cpu_runtime_window COMMAND kylinrca_cpu_runtime_smoke)
add_test(NAME json_reporter COMMAND kylinrca_json_reporter_smoke)

set(LOCK_BPF_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/bpf/lock.bpf.c)
set(LOCK_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/lock.bpf.o)

add_custom_command(
    OUTPUT ${LOCK_BPF_OBJECT}
    COMMAND
        ${CLANG_EXECUTABLE}
        -g -O2 -target bpf
        -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}/bpf/include
        -I${CMAKE_CURRENT_SOURCE_DIR}/include
        -c ${LOCK_BPF_SOURCE}
        -o ${LOCK_BPF_OBJECT}
    DEPENDS
        ${LOCK_BPF_SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/include/event.h
        ${CMAKE_CURRENT_SOURCE_DIR}/include/lock_probe.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/bpf_common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/bpf/include/vmlinux.h
    VERBATIM
)

add_custom_target(lock_bpf ALL DEPENDS ${LOCK_BPF_OBJECT})

add_executable(kylinrca_lock_probe_smoke tests/lock_probe_test.cpp)
target_include_directories(kylinrca_lock_probe_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(kylinrca_lock_probe_smoke PRIVATE PkgConfig::LIBBPF)
target_compile_definitions(kylinrca_lock_probe_smoke PRIVATE
    KYLINRCA_LOCK_BPF_OBJECT="${LOCK_BPF_OBJECT}")
add_dependencies(kylinrca_lock_probe_smoke lock_bpf)

find_package(Threads REQUIRED)
add_executable(kylinrca_syscall_pid_test tests/syscall_pid_test.cpp)
target_include_directories(kylinrca_syscall_pid_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(kylinrca_syscall_pid_test PRIVATE PkgConfig::LIBBPF Threads::Threads)
target_compile_definitions(kylinrca_syscall_pid_test PRIVATE
    KYLINRCA_SYSCALL_BPF_OBJECT="${SYSCALL_BPF_OBJECT}")
add_dependencies(kylinrca_syscall_pid_test syscall_bpf)

add_executable(kylinrca_lock_wait_workload tests/lock_wait_workload.cpp)
target_link_libraries(kylinrca_lock_wait_workload PRIVATE Threads::Threads)
add_test(NAME lock_wait_workload COMMAND kylinrca_lock_wait_workload --auto --iterations 1)

add_executable(kylinrca_lock_test scenarios/lock_test.cpp)
target_link_libraries(kylinrca_lock_test PRIVATE Threads::Threads)
add_test(NAME mutex_contention_workload
    COMMAND kylinrca_lock_test --scenario contention --threads 8 --auto)
add_test(NAME mutex_uncontended_workload
    COMMAND kylinrca_lock_test --scenario uncontended --threads 8 --auto)
set_tests_properties(mutex_contention_workload mutex_uncontended_workload PROPERTIES TIMEOUT 15)

find_package(Python3 QUIET COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(NAME mutex_probe_validation
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/mutex_probe_validation_test.py)
endif()


# W3 I/O 原始采集：不依赖后续 IoAnalyzer/RCA。
set(IO_BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/io.bpf.o)
add_custom_command(
    OUTPUT ${IO_BPF_OBJECT}
    COMMAND ${CLANG_EXECUTABLE} -g -O2 -Wall -Werror -target bpf
        -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}/bpf/include
        -I${CMAKE_CURRENT_SOURCE_DIR}/include
        -c ${CMAKE_CURRENT_SOURCE_DIR}/bpf/io.bpf.c -o ${IO_BPF_OBJECT}
    DEPENDS bpf/io.bpf.c include/event.h include/io_probe_stats.h
        bpf/include/bpf_common.h bpf/include/vmlinux.h
    VERBATIM)
add_custom_target(io_bpf ALL DEPENDS ${IO_BPF_OBJECT})
add_executable(kylinrca_io_probe_smoke tests/io_probe_smoke.cpp)
target_include_directories(kylinrca_io_probe_smoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(kylinrca_io_probe_smoke PRIVATE PkgConfig::LIBBPF)
target_compile_options(kylinrca_io_probe_smoke PRIVATE -Wall -Wextra -Werror)
target_compile_definitions(kylinrca_io_probe_smoke PRIVATE
    KYLINRCA_IO_BPF_OBJECT="${IO_BPF_OBJECT}")
add_dependencies(kylinrca_io_probe_smoke io_bpf)
add_test(NAME io_probe_help COMMAND kylinrca_io_probe_smoke --help)
