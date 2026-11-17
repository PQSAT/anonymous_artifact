# Constellation testbed, Satellite 1 on the Versal A72 (PetaLinux 2023.2)
SET(MISSION_NAME "Constellation")
SET(SPACECRAFT_ID 0x101)
list(APPEND MISSION_GLOBAL_APPLIST sample_app sample_lib sat_rf)
# NASA standard cFS application suite
list(APPEND MISSION_GLOBAL_APPLIST cf hs md mm cs fm lc sc ds hk)
SET(FT_INSTALL_SUBDIR "host/functional-test")
# Two satellites run as two cFS instances on the same A72 (cpu1 = SAT-1, SCID 0x101;
# cpu2 = SAT-2, SCID 0x102), joined by the inter satellite link of sat_rf.
SET(MISSION_CPUNAMES cpu1 cpu2)
SET(cpu1_PROCESSORID 1)
SET(cpu1_APPLIST sat_rf ci_lab to_lab sch_lab)
SET(cpu1_SYSTEM aarch64-versal-linux)
SET(cpu2_PROCESSORID 2)
SET(cpu2_APPLIST sat_rf ci_lab to_lab sch_lab)
SET(cpu2_SYSTEM aarch64-versal-linux)
