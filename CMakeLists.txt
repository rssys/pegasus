cmake_minimum_required(VERSION 3.8)
project(pegasus C CXX ASM)

option(DISABLE_MPK "Disable MPK memory protection" OFF)
option(DISABLE_MM "Disable memory menagement module" OFF)
option(ENABLE_FSTACK "Enable F-stack DPDK" ON)
option(ENABLE_TIME_TRACE "Tracing event" OFF)

find_package(Boost 1.70 REQUIRED)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_COMPILER clang++)

add_library(hook SHARED src/hook.c)
target_compile_options(hook PRIVATE -g -O3 -Wtrampolines -Wall)
set(CMAKE_ASM_CREATE_SHARED_LIBRARY ${CMAKE_C_CREATE_SHARED_LIBRARY})
add_library(
    linux-vdso.so.1
    SHARED
    src/vdso/vdso.S
)
set_target_properties(linux-vdso.so.1 PROPERTIES PREFIX "")
target_compile_options(linux-vdso.so.1 PRIVATE -fPIC -nostdlib -fno-stack-protector)
target_link_options(linux-vdso.so.1 PRIVATE -nostdlib -Wl,--hash-style=sysv
    -T ${CMAKE_SOURCE_DIR}/src/vdso/vdso.ld)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/vdso_elf.c
    COMMAND xxd -i linux-vdso.so.1.so vdso_elf.c
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS linux-vdso.so.1
    COMMENT "Generating vdso elf"
)

add_custom_target(
    vdsoelf ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/vdso_elf.c
)

file(GLOB HEADER_FILES include/pegasus/*.h)
add_executable(
    pegasus
    src/allocator.cc
    src/breakpoint.cc
    src/code_inspect.cc
    src/context.S
    src/clone.cc
    src/cluster.cc
    src/daemon.cc
    src/decode.cc
    src/epoll.cc
    src/event.cc
    src/exception.cc
    src/fair.cc
    src/fastcall.S
    src/file.cc
    src/futex.cc
    src/gate.S
    src/loader.cc
    #src/main.cc
    src/mm.cc
    src/monitor.cc
    src/mount.cc
    src/process.cc
    src/rewrite.cc
    src/runtime.cc
    src/sched.cc
    src/sigframe.cc
    src/signal.cc
    src/stat.cc
    src/syscall.cc
    src/timer.cc
    src/trace.cc
    src/vdso.cc
    src/wait_queue.cc
    src/network/local.cc
    src/network/network.cc
    src/network/socket.cc
    vendor/maple_tree/maple_tree.c
    ${HEADER_FILES}
)

add_dependencies(pegasus vdsoelf)

target_sources(pegasus PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/vdso_elf.c)

add_executable(
    runpc
    src/cli.cc
    src/exception.cc
    ${HEADER_FILES}
)

target_compile_options(pegasus PRIVATE -pie
    -fPIE -Wall -Wtrampolines -O3 -g -fnon-call-exceptions)
target_link_options(pegasus PRIVATE
    "SHELL:-z relro"
    "SHELL:-z now"
    "SHELL:-z noexecstack"
)
include_directories(SYSTEM vendor/linux vendor/maple_tree/ vendor/libsclog)
include_directories(vendor/json vendor/xed/include include)
target_link_directories(pegasus PRIVATE vendor/xed/lib)
target_link_libraries(pegasus xed liburing.a seccomp rt)
target_compile_definitions(runpc PRIVATE cli11)
if (ENABLE_FSTACK)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBDPDK REQUIRED libdpdk)
    target_sources(pegasus PRIVATE src/ioworker_fstack.cc src/network/dpdk.cc)
    target_compile_definitions(pegasus PRIVATE CONFIG_ENABLE_FSTACK)
    if (ENABLE_TIME_TRACE)
        target_link_libraries(pegasus fstack-trace ${LIBDPDK_STATIC_LDFLAGS})
    else()
        target_link_libraries(pegasus fstack ${LIBDPDK_STATIC_LDFLAGS})
    endif()
    target_compile_options(pegasus PRIVATE ${LIBDPDK_STATIC_CFLAGS})
endif()
if (DISABLE_MPK)
    target_compile_definitions(pegasus PRIVATE CONFIG_NOMPK)
endif()
if (DISABLE_MM)
    target_compile_definitions(pegasus PRIVATE CONFIG_NOMPK CONFIG_MM_PASSTHROUGH)
endif()
if (ENABLE_TIME_TRACE)
    target_compile_definitions(pegasus PRIVATE CONFIG_ENABLE_TIME_TRACE)
endif()
