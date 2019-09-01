project(external C CXX)

#set(BUILD_TESTING_BCKP ${BUILD_TESTING})
#set(BUILD_TESTING OFF CACHE BOOL "Force disable of tests for external dependencies" FORCE)

#set(CUSTOM_COVERAGE_EXCLUDE ${CUSTOM_COVERAGE_EXCLUDE} "external" PARENT_SCOPE) # Replaced in CTestCustom.cmake.in

# Use a prebuilt version of detours
add_library(Detours::Detours IMPORTED STATIC GLOBAL)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DetoursLibFolder lib.X64)
else()
    set(DetoursLibFolder lib.X86)
endif()

set_target_properties(Detours::Detours PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/Detours/${DetoursLibFolder}/detours.lib")
#target_include_directories(Detours::Detours INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/Detours/include")
# -> the previous line fails with the error: Cannot specify include directories for imported target
set_property(TARGET Detours::Detours APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/Detours/include")

#set(BUILD_TESTING ${BUILD_TESTING_BCKP} CACHE BOOL "Build tests (default variable for CTest)" FORCE) #Set it back to its past value
