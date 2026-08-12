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
