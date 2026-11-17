# Versal VC1902 Cortex-A72, PetaLinux 2023.2 (glibc 2.36), cross-compiled with zig cc
SET(CMAKE_SYSTEM_NAME      Linux)
SET(CMAKE_SYSTEM_VERSION   1)
SET(CMAKE_SYSTEM_PROCESSOR aarch64)
SET(CMAKE_C_COMPILER   ${CMAKE_CURRENT_LIST_DIR}/../toolchain/cc)
SET(CMAKE_CXX_COMPILER ${CMAKE_CURRENT_LIST_DIR}/../toolchain/cxx)
SET(CMAKE_AR           ${CMAKE_CURRENT_LIST_DIR}/../toolchain/ar CACHE FILEPATH "")
SET(CMAKE_RANLIB       ${CMAKE_CURRENT_LIST_DIR}/../toolchain/ranlib CACHE FILEPATH "")
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
SET(CFE_SYSTEM_PSPNAME "pc-linux")
SET(OSAL_SYSTEM_OSTYPE "posix")

# post quantum primitive library for the target, built by protocol/build_pqsat.sh
set(PQSAT_LIB_DIR ${CMAKE_CURRENT_LIST_DIR}/../../protocol/lib-aarch64 CACHE PATH "libpqsat.so for aarch64")
set(SATSDLS_DIR ${CMAKE_CURRENT_LIST_DIR}/../../sdls CACHE PATH "SDLS layer with the libpqsat backend")
