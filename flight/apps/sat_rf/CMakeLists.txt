project(CFS_SAT_RF C)

set(APP_SRC_FILES
  fsw/src/sat_rf_app.c
  fsw/src/sat_ccsds.c
  fsw/src/sat_auth.c
)

add_cfe_app(sat_rf ${APP_SRC_FILES})
target_include_directories(sat_rf PUBLIC fsw/src)
# post quantum primitive library, built by protocol/build_pqsat.sh for the target
if(DEFINED PQSAT_LIB_DIR)
  # link by name so the module records "libpqsat.so" and finds it on the target
  # through LD_LIBRARY_PATH (/root/cpu1), not the build machine's path
  target_link_libraries(sat_rf -L${PQSAT_LIB_DIR} -lpqsat)
endif()
if(DEFINED SATSDLS_DIR)
  # SDLS library with the libpqsat backend, built as one archive by sdls/build_sdls.sh
  target_include_directories(sat_rf PRIVATE ${SATSDLS_DIR}/sat_sdls)
  target_link_libraries(sat_rf ${SATSDLS_DIR}/out-aarch64/libsatsdls.a)
endif()
